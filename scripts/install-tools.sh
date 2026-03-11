#!/usr/bin/env bash
# Install all security tools required by the bug bounty agent.
# Idempotent — skips tools that are already installed.
# No sudo required — installs everything under $HOME.
set -euo pipefail

GOVERSION="1.23.6"
GO_HOME="$HOME/.local/go"
GOBIN="$HOME/go/bin"

GO_TOOLS=(
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/ffuf/ffuf/v2@latest"
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/hahwul/dalfox/v2@latest"
)

BIN_NAMES=(nuclei ffuf subfinder httpx katana gau dalfox)

status() { printf "\033[1;34m[+]\033[0m %s\n" "$*"; }
ok()     { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
warn()   { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
fail()   { printf "\033[1;31m[✗]\033[0m %s\n" "$*"; }

# ---------- Go (user-local install, no sudo) ----------
install_go() {
  export PATH="$GO_HOME/bin:$GOBIN:$HOME/.local/bin:$PATH"
  if command -v go &>/dev/null; then
    ok "Go already installed: $(go version)"
    return 0
  fi
  status "Installing Go ${GOVERSION} to ${GO_HOME}..."
  local arch
  arch=$(dpkg --print-architecture 2>/dev/null || uname -m)
  case "$arch" in
    amd64|x86_64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) fail "Unsupported architecture: $arch"; return 1 ;;
  esac
  local tarball="go${GOVERSION}.linux-${arch}.tar.gz"
  curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
  rm -rf "$GO_HOME"
  mkdir -p "$GO_HOME"
  tar -C "$GO_HOME" --strip-components=1 -xzf "/tmp/${tarball}"
  rm -f "/tmp/${tarball}"
  export PATH="$GO_HOME/bin:$GOBIN:$PATH"
  ok "Go installed: $(go version)"
}

# ---------- Go tools ----------
install_go_tools() {
  export PATH="$GO_HOME/bin:$GOBIN:$HOME/.local/bin:$PATH"
  export GOPATH="$HOME/go"
  for i in "${!GO_TOOLS[@]}"; do
    local tool="${GO_TOOLS[$i]}"
    local name="${BIN_NAMES[$i]}"
    if command -v "$name" &>/dev/null; then
      ok "$name already installed"
    else
      status "Installing $name..."
      if go install "$tool" 2>&1; then
        ok "$name installed"
      else
        fail "$name installation failed"
      fi
    fi
  done
}

# ---------- sqlmap (Python) ----------
install_sqlmap() {
  export PATH="$HOME/.local/bin:$PATH"
  if command -v sqlmap &>/dev/null; then
    ok "sqlmap already installed"
    return 0
  fi
  status "Installing sqlmap via pipx..."
  if command -v pipx &>/dev/null; then
    pipx install sqlmap 2>&1
    ok "sqlmap installed"
  else
    pip3 install --user sqlmap 2>&1
    ok "sqlmap installed via pip"
  fi
}

# ---------- bba CLI ----------
install_bba() {
  if uv run bba --help &>/dev/null 2>&1; then
    ok "bba CLI available"
    return 0
  fi
  status "Installing bba CLI..."
  uv pip install -e ".[dev]" 2>&1
  ok "bba CLI installed"
}

# ---------- Main ----------
main() {
  status "Bug Bounty Agent — Tool Installation"
  echo ""

  install_go
  install_go_tools
  install_sqlmap
  install_bba

  # Final PATH for verification
  export PATH="$GO_HOME/bin:$GOBIN:$HOME/.local/bin:$PATH"

  echo ""
  status "Installation summary:"
  local all_ok=true
  for name in "${BIN_NAMES[@]}" sqlmap; do
    if command -v "$name" &>/dev/null; then
      ok "$name: $(which "$name")"
    else
      fail "$name: NOT FOUND"
      all_ok=false
    fi
  done

  if uv run bba --help &>/dev/null 2>&1; then
    ok "bba CLI: available via 'uv run bba'"
  else
    fail "bba CLI: NOT AVAILABLE"
    all_ok=false
  fi

  echo ""
  if [ "$all_ok" = true ]; then
    ok "All tools installed successfully!"
  else
    warn "Some tools failed to install. Check errors above."
  fi
}

main "$@"
