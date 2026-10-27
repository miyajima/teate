#!/usr/bin/env bash
# Bootstrap Python/Git, then install Teate's tools without changing app sources.
set -euo pipefail
umask 077

teate_root="$(cd "$(dirname "$0")/.." && pwd)"
teate_all=false
teate_dry=false
for arg in "$@"; do
  case "$arg" in
    --all) teate_all=true ;;
    --dry-run) teate_dry=true ;;
    --help|-h)
      echo 'Usage: bash scripts/install.sh [--all] [--dry-run]'
      echo 'Default: Python 3.11+, Git, OSV-Scanner.'
      echo '--all: also Node/npm, Trivy, gh, gcloud, Codex, Linux bubblewrap.'
      exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

step() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  if ! "$teate_dry"; then "$@"; fi
}

teate_system="$(uname -s)"
case "$(uname -m)" in
  x86_64|amd64|aarch64|arm64) ;;
  *) echo 'Supported architectures: amd64 / arm64.' >&2; exit 2 ;;
esac
if [[ "$teate_system" == Darwin ]]; then
  teate_brew="$(command -v brew || true)"
  if [[ -z "$teate_brew" ]]; then
    for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
      if [[ -x "$candidate" ]]; then teate_brew="$candidate"; break; fi
    done
  fi
  if [[ -z "$teate_brew" ]]; then
    if "$teate_dry"; then
      echo '+ Download and run official Homebrew installer (administrator access may be needed)'
    else
      teate_tmp="$(mktemp -d)"
      trap 'rm -rf "$teate_tmp"' EXIT
      curl --fail --show-error --silent --location --proto '=https' \
        https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh \
        --output "$teate_tmp/homebrew.sh"
      /bin/bash "$teate_tmp/homebrew.sh"
    fi
    if [[ "$(uname -m)" == arm64 ]]; then teate_brew=/opt/homebrew/bin/brew
    else teate_brew=/usr/local/bin/brew; fi
  fi
  if ! "$teate_dry"; then eval "$("$teate_brew" shellenv)"; fi
  step "$teate_brew" install python@3.13 git
  teate_python="$(dirname "$teate_brew")/python3.13"
elif [[ "$teate_system" == Linux ]]; then
  teate_sudo=()
  if [[ "$(id -u)" != 0 ]]; then
    if ! "$teate_dry" && ! command -v sudo >/dev/null; then
      echo 'sudo is required to install system packages; ask the VPS administrator.' >&2
      exit 2
    fi
    teate_sudo=(sudo)
  fi
  if command -v apt-get >/dev/null; then
    step "${teate_sudo[@]}" apt-get update
    teate_packages=(python3 git ca-certificates)
    if "$teate_all"; then teate_packages+=(bubblewrap); fi
    step "${teate_sudo[@]}" apt-get install -y "${teate_packages[@]}"
  elif command -v dnf >/dev/null; then
    teate_packages=(python3 git ca-certificates)
    if "$teate_all"; then teate_packages+=(bubblewrap); fi
    step "${teate_sudo[@]}" dnf install -y "${teate_packages[@]}"
  else
    echo 'Automatic bootstrap supports apt-get / dnf. With Python 3.11+ and Git installed, use scripts/install_dependencies.py.' >&2
    exit 2
  fi
  teate_python=python3
else
  echo 'Use macOS/Linux, or scripts/install.ps1 on Windows (WSL2).' >&2
  exit 2
fi

teate_args=("$teate_root/scripts/install_dependencies.py")
if "$teate_all"; then teate_args+=(--all); fi
if "$teate_dry"; then
  step "$teate_python" "${teate_args[@]}" --dry-run
  echo 'Dry run only: no packages, files, or login settings changed.'
else
  "$teate_python" -c 'import sys; sys.exit(0 if (3, 11) <= sys.version_info[:2] < (3, 16) else "Python 3.11–3.15 is required. Use Ubuntu 24.04+, Debian 12+, or a current Fedora.")'
  "$teate_python" "${teate_args[@]}"
fi
