#!/usr/bin/env bash
# 폐쇄망(내부망) 반입용 배포물을 만든다.
#
#   bash scripts/build_offline.sh              # 전부
#   bash scripts/build_offline.sh binary       # 단일 실행파일만
#   bash scripts/build_offline.sh pyz wheelhouse
#
# 결과물 (dist/offline/):
#   dockguard                      단일 실행파일 — 서버에 Python이 없어도 동작 (약 14MB)
#   dockguard.pyz                  단일 zipapp  — 서버에 Python 3.10+ 만 있으면 동작
#   dockguard-wheelhouse.tar.gz    휠 꾸러미    — pip install --no-index 로 설치
#
# ⚠️ 반드시 **배포 대상과 같은 계열의 리눅스**에서 실행하라. 실행파일은 빌드한 glibc 버전보다
#    낮은 서버에서는 동작하지 않는다. 호환성이 가장 넓은 방법은 manylinux 컨테이너에서 빌드하는 것이고,
#    CI(.github/workflows/release.yml)가 태그를 붙일 때마다 그렇게 만들어 릴리스에 올린다.
#
#      docker run --rm -v "$PWD:/src" -w /src quay.io/pypa/manylinux_2_28_x86_64 \
#        bash -c 'export PYTHON=/opt/python/cp312-cp312/bin/python && bash scripts/build_offline.sh'
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="dist/offline"
PYTHON="${PYTHON:-python3}"
SNAPSHOT="examples/rabbitmq-incident/snapshot.json"
TARGETS=("$@")
[ ${#TARGETS[@]} -eq 0 ] && TARGETS=(wheelhouse pyz binary)

mkdir -p "$OUT"

"$PYTHON" -c "import dockguard" 2>/dev/null || "$PYTHON" -m pip install --quiet -e .

# 룰 자동 등록(pkgutil 스캔)이 패키징 과정에서 깨지지 않았는지 대조할 기준값.
# PyInstaller는 "아무도 import하지 않는" 룰 모듈을 통째로 빼 버리기 쉽고, 그러면 도구가
# 조용히 0개를 점검한다 — 가장 나쁜 실패다. 그래서 빌드마다 개수를 확인한다.
EXPECTED=$("$PYTHON" -c "from dockguard.core.engine import ScanEngine; print(len(ScanEngine().rules))")
echo "▶ 기준: 룰 ${EXPECTED}개"

# 검증은 사람이 읽는 한글 출력이 아니라 JSON(ASCII 키)으로 확인한다 — 로케일·인코딩에 좌우되지 않게.
verify() { # verify <설명> <실행 명령...>
  local label="$1"; shift
  local report diagnosis rules
  echo "  · ${label}"

  # 1) 룰이 전부 등록됐는가 (scan JSON의 rules_run)
  report=$("$@" scan --format json --docker-snapshot "$SNAPSHOT")
  rules=$(printf '%s' "$report" | tr -d ' ' | grep -o '"rules_run":[0-9]*' | grep -o '[0-9]*')
  if [ "${rules:-0}" != "$EXPECTED" ]; then
    echo "    ✗ 룰 ${rules:-0}개만 실행됨 (기대: ${EXPECTED}개) — 패키징에서 룰 모듈이 누락되었다" >&2
    return 1
  fi

  # 2) HTML 리포트 템플릿(패키지 데이터)이 들어 있는가
  "$@" scan -c daemon -o "$OUT/.verify.html" >/dev/null
  grep -q "dockguard" "$OUT/.verify.html" || { echo "    ✗ HTML 리포트 생성 실패" >&2; return 1; }
  rm -f "$OUT/.verify.html"

  # 3) 진단 엔진이 근본 원인을 찾는가 (원인을 찾으면 종료 코드 1이므로 || true)
  diagnosis=$("$@" diagnose connectivity backend-container rabbitmq --port 5672 \
    --docker-snapshot "$SNAPSHOT" --format json || true)
  printf '%s' "$diagnosis" | tr -d ' ' | grep -q '"resolved":true' \
    || { echo "    ✗ 진단이 근본 원인을 찾지 못함" >&2; return 1; }
  printf '%s' "$diagnosis" | grep -q "messaging_mq-net" \
    || { echo "    ✗ 진단 근거에 네트워크 이름이 없음" >&2; return 1; }

  # 4) 학습 콘텐츠가 들어 있는가
  # (파이프로 grep -q에 넘기면 grep이 먼저 끝나면서 파이프가 닫히고, dockguard는 그때 조용히
  #  종료 코드 1을 돌려준다. set -o pipefail과 만나면 멀쩡한 빌드가 실패로 보인다 → 변수로 받는다)
  local topic
  topic=$("$@" learn icc)
  printf '%s' "$topic" | grep -q "ICC" || { echo "    ✗ 학습 콘텐츠 누락" >&2; return 1; }

  echo "    ✓ 룰 ${rules}개 · HTML 리포트 · 진단 · 학습 정상"
}

for target in "${TARGETS[@]}"; do
  case "$target" in

    wheelhouse)
      echo "▶ 휠 꾸러미"
      rm -rf "$OUT/wheelhouse"
      "$PYTHON" -m pip wheel . -w "$OUT/wheelhouse" --quiet
      tar czf "$OUT/dockguard-wheelhouse.tar.gz" -C "$OUT" wheelhouse
      rm -rf "$OUT/wheelhouse"
      echo "    ✓ $OUT/dockguard-wheelhouse.tar.gz"
      ;;

    pyz)
      echo "▶ 단일 zipapp (.pyz)"
      "$PYTHON" -m pip install --quiet shiv
      "$PYTHON" -m shiv -c dockguard -o "$OUT/dockguard.pyz" . --quiet
      verify "dockguard.pyz" "$PYTHON" "$OUT/dockguard.pyz"
      ;;

    binary)
      echo "▶ 단일 실행파일 (PyInstaller)"
      "$PYTHON" -m pip install --quiet pyinstaller
      # --collect-submodules: @register로만 등록되는 룰·진단 모듈을 전부 포함 (없으면 룰 0개가 된다)
      # --collect-data:       HTML 리포트 템플릿(templates/report.html.j2) 포함
      # 빌드 로그는 파일로 보내고 실패했을 때만 보여준다 (성공 시 수백 줄이 화면을 덮는다)
      if ! "$PYTHON" -m PyInstaller --onefile --name dockguard --clean --noconfirm \
        --collect-submodules dockguard --collect-data dockguard \
        --distpath "$OUT" --workpath "dist/.pyinstaller" --specpath "dist/.pyinstaller" \
        dockguard/__main__.py > dist/pyinstaller.log 2>&1; then
        tail -30 dist/pyinstaller.log >&2
        echo "    ✗ PyInstaller 빌드 실패 (전체 로그: dist/pyinstaller.log)" >&2
        exit 1
      fi
      BIN="$OUT/dockguard"
      [ -f "$BIN.exe" ] && BIN="$BIN.exe"   # Windows에서 시험 삼아 돌릴 때
      chmod +x "$BIN"
      verify "$(basename "$BIN")" "$BIN"
      ;;

    *)
      echo "알 수 없는 대상: $target (wheelhouse | pyz | binary)" >&2
      exit 2
      ;;
  esac
done

echo
echo "완료 — $OUT"
ls -lh "$OUT" | tail -n +2 | awk '{printf "  %-32s %s\n", $9, $5}'
