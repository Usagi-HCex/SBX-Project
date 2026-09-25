#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if command -v python3 >/dev/null 2>&1 \
  && python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
  PYTHON_BIN=python3
elif command -v python >/dev/null 2>&1 \
  && python -c 'import sys; raise SystemExit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
  PYTHON_BIN=python
else
  printf 'Audit failed: Python 3 is required.\n' >&2
  exit 1
fi

printf '== Syntax ==\n'
bash -n install.sh src/sbx-manager.sh scripts/security-audit.sh tests/test_manager.sh
"$PYTHON_BIN" -m py_compile src/sbx_generator.py tests/test_generator.py

printf '== Network endpoints ==\n'
grep -RInE 'https?://' --exclude-dir=.git --exclude-dir=__pycache__ \
  install.sh src README.md SECURITY.md || true

printf '== Dangerous remote execution patterns ==\n'
if grep -RInE '(curl|wget)[^|;]*[|][[:space:]]*(ba)?sh|eval[[:space:]]' \
  --include='*.sh' --include='*.py' install.sh src; then
  printf 'Audit failed: remote execution or eval pattern found.\n' >&2
  exit 1
fi

printf '== Obvious telemetry/exfiltration markers ==\n'
if grep -RInEi 'telegram|discord|webhook|pastebin|ipinfo|icanhazip|api\.ipify|analytics|telemetry' \
  --include='*.sh' --include='*.py' install.sh src; then
  printf 'Audit failed: review endpoint/telemetry marker above.\n' >&2
  exit 1
fi

printf 'Security audit checks passed.\n'
