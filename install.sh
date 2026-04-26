#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "Python was not found. Install Python 3.10+, then rerun this script." >&2
    exit 1
  fi
fi

if [[ "${1:-}" == "--force" && -d ".venv" ]]; then
  echo "Removing existing virtual environment: $ROOT/.venv"
  rm -rf ".venv"
fi

if [[ ! -x ".venv/bin/python" ]]; then
  echo "Creating virtual environment..."
  "$PYTHON_BIN" -m venv .venv
fi

echo "Installing Proc Blart..."
".venv/bin/python" -m pip install -r requirements.txt
".venv/bin/python" -m pip install -e .

echo
echo "Install complete."
echo "Activate with: source .venv/bin/activate"
echo "Run safely with: procblart run -dry"
echo 'Set VirusTotal for this shell with: export VIRUSTOTAL_API_KEY="paste_key_here"'
