#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/proc-blart}"
BRANCH="${BRANCH:-main}"
REPO_OWNER="AlexCasF"
REPO_NAME="proc-blart"
ZIP_URL="https://github.com/$REPO_OWNER/$REPO_NAME/archive/refs/heads/$BRANCH.zip"
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ -e "$INSTALL_DIR" && "${FORCE:-}" != "1" ]]; then
  if [[ ! -f "$INSTALL_DIR/install.sh" ]]; then
    echo "Install directory already exists but does not contain install.sh: $INSTALL_DIR" >&2
    echo "Choose another INSTALL_DIR or rerun with FORCE=1." >&2
    exit 1
  fi
  echo "Using existing install directory: $INSTALL_DIR"
else
  if [[ -e "$INSTALL_DIR" && "${FORCE:-}" == "1" ]]; then
    echo "Removing existing install directory: $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
  fi

  mkdir -p "$(dirname "$INSTALL_DIR")"
  echo "Downloading Proc Blart from $ZIP_URL"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$ZIP_URL" -o "$TMP_DIR/source.zip"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP_DIR/source.zip" "$ZIP_URL"
  else
    echo "Neither curl nor wget was found." >&2
    exit 1
  fi

  if command -v unzip >/dev/null 2>&1; then
    unzip -q "$TMP_DIR/source.zip" -d "$TMP_DIR/source"
  elif command -v python3 >/dev/null 2>&1; then
    python3 -m zipfile -e "$TMP_DIR/source.zip" "$TMP_DIR/source"
  elif command -v python >/dev/null 2>&1; then
    python -m zipfile -e "$TMP_DIR/source.zip" "$TMP_DIR/source"
  else
    echo "Neither unzip nor Python was found to extract the archive." >&2
    exit 1
  fi

  SOURCE_DIR="$(find "$TMP_DIR/source" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  if [[ -z "$SOURCE_DIR" ]]; then
    echo "Downloaded archive did not contain a source directory." >&2
    exit 1
  fi

  mv "$SOURCE_DIR" "$INSTALL_DIR"
fi

echo "Running installer..."
bash "$INSTALL_DIR/install.sh"

echo
echo "Proc Blart is installed in: $INSTALL_DIR"
echo "Start a new shell or run:"
echo "  cd '$INSTALL_DIR'"
echo "  source .venv/bin/activate"
echo "  procblart run -dry"
