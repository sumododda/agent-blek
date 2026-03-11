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
  "github.com/owasp-amass/amass/v4/...@master"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/projectdiscovery/alterx/cmd/alterx@latest"
  "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  "github.com/d3mondev/puredns/v2@latest"
  "github.com/sensepost/gowitness@latest"
  "github.com/hakluke/hakrevdns@latest"
  "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
  "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
  "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
  "github.com/projectdiscovery/uncover/cmd/uncover@latest"
  # Phase 4 — Vulnerability Testing Tools
  "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
  "github.com/Charlie-belmer/nosqli@latest"
  # Phase 5A — Infrastructure Hardening
  "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  "github.com/devploit/nomore403@latest"
  # Phase 5B — Tool Cleanup + High-Value Additions
  "github.com/BishopFox/jsluice/cmd/jsluice@latest"
  "github.com/PentestPad/subzy@latest"
  # Phase 5C — Monitoring & Platform Integration
  "github.com/projectdiscovery/notify/cmd/notify@latest"
)

BIN_NAMES=(nuclei ffuf subfinder httpx katana gau dalfox amass dnsx naabu alterx shuffledns puredns gowitness hakrevdns cdncheck asnmap tlsx uncover crlfuzz nosqli interactsh-client nomore403 jsluice subzy notify)

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

# ---------- Python security tools ----------
install_python_tools() {
  export PATH="$HOME/.local/bin:$PATH"
  local PYTHON_TOOLS=(wafw00f paramspider arjun git-dumper waymore graphw00f s3scanner uro ghauri clairvoyance cewler)
  local PIP_NAMES=(wafw00f paramspider arjun git-dumper waymore graphw00f s3scanner uro ghauri clairvoyance cewler)

  for i in "${!PYTHON_TOOLS[@]}"; do
    local tool="${PYTHON_TOOLS[$i]}"
    local name="${PIP_NAMES[$i]}"
    if command -v "$name" &>/dev/null || pip3 show "$tool" &>/dev/null 2>&1; then
      ok "$tool already installed"
    else
      status "Installing $tool..."
      if command -v pipx &>/dev/null; then
        pipx install "$tool" 2>&1 && ok "$tool installed" || warn "$tool installation failed (non-critical)"
      else
        pip3 install --user "$tool" 2>&1 && ok "$tool installed" || warn "$tool installation failed (non-critical)"
      fi
    fi
  done
}

# ---------- Binary tools (GitHub releases) ----------
install_binary_tools() {
  export PATH="$HOME/.local/bin:$PATH"
  local BIN_DIR="$HOME/.local/bin"
  mkdir -p "$BIN_DIR"

  # feroxbuster
  if command -v feroxbuster &>/dev/null; then
    ok "feroxbuster already installed"
  else
    status "Installing feroxbuster..."
    local arch
    arch=$(dpkg --print-architecture 2>/dev/null || uname -m)
    case "$arch" in
      amd64|x86_64) arch="x86_64" ;;
      arm64|aarch64) arch="aarch64" ;;
    esac
    local url="https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_linux_${arch}.tar.gz"
    if curl -fsSL "$url" | tar xz -C "$BIN_DIR" feroxbuster 2>/dev/null; then
      chmod +x "$BIN_DIR/feroxbuster"
      ok "feroxbuster installed"
    else
      warn "feroxbuster installation failed (non-critical)"
    fi
  fi

  # trufflehog
  if command -v trufflehog &>/dev/null; then
    ok "trufflehog already installed"
  else
    status "Installing trufflehog..."
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$BIN_DIR" 2>&1 && ok "trufflehog installed" || warn "trufflehog installation failed"
  fi

  # gitleaks
  if command -v gitleaks &>/dev/null; then
    ok "gitleaks already installed"
  else
    status "Installing gitleaks..."
    go install github.com/gitleaks/gitleaks/v8@latest 2>&1 && ok "gitleaks installed" || warn "gitleaks installation failed"
  fi

  # kiterunner
  if command -v kr &>/dev/null; then
    ok "kiterunner already installed"
  else
    status "Installing kiterunner..."
    go install github.com/assetnote/kiterunner/cmd/kr@latest 2>&1 && ok "kiterunner installed" || warn "kiterunner installation failed"
  fi

  # brutespray
  if command -v brutespray &>/dev/null; then
    ok "brutespray already installed"
  else
    status "Installing brutespray..."
    if command -v pipx &>/dev/null; then
      pipx install brutespray 2>&1 && ok "brutespray installed" || warn "brutespray installation failed (non-critical)"
    else
      pip3 install --user brutespray 2>&1 && ok "brutespray installed" || warn "brutespray installation failed (non-critical)"
    fi
  fi

  # retire.js
  if command -v retire &>/dev/null; then
    ok "retire.js already installed"
  else
    status "Installing retire.js..."
    if command -v npm &>/dev/null; then
      npm install -g retire 2>&1 && ok "retire.js installed" || warn "retire.js installation failed (non-critical)"
    else
      warn "retire.js requires npm — install Node.js first"
    fi
  fi

  # Phase 4 — git-based Python tools
  local GIT_TOOLS=(
    "https://github.com/vladko312/SSTImap.git:/opt/sstimap:sstimap"
    "https://github.com/commixproject/commix.git:/opt/commix:commix"
    "https://github.com/s0md3v/XSStrike.git:/opt/xsstrike:xsstrike"
    "https://github.com/ticarpi/jwt_tool.git:/opt/jwt_tool:jwt_tool"
  )
  for entry in "${GIT_TOOLS[@]}"; do
    local repo="${entry%%:*}"
    local rest="${entry#*:}"
    local dest="${rest%%:*}"
    local name="${rest##*:}"
    if [ -d "$dest" ]; then
      ok "$name already cloned at $dest"
    else
      status "Cloning $name..."
      git clone "$repo" "$dest" 2>/dev/null && ok "$name cloned" || warn "$name clone failed (non-critical)"
    fi
  done

  # Phase 4 — ppfuzz (Rust/cargo)
  if command -v ppfuzz &>/dev/null; then
    ok "ppfuzz already installed"
  else
    status "Installing ppfuzz via cargo..."
    if command -v cargo &>/dev/null; then
      cargo install ppfuzz 2>/dev/null && ok "ppfuzz installed" || warn "ppfuzz installation failed (non-critical)"
    else
      warn "ppfuzz requires cargo (Rust) — install Rust first: https://rustup.rs"
    fi
  fi
}

# ---------- System tools (require manual install) ----------
check_system_tools() {
  local SYSTEM_TOOLS=(nmap masscan)
  echo ""
  status "System tools (may require sudo to install):"
  for tool in "${SYSTEM_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
      ok "$tool: $(which "$tool")"
    else
      warn "$tool: NOT FOUND — install with: sudo apt install $tool"
    fi
  done
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
  install_python_tools
  install_binary_tools
  check_system_tools
  install_bba

  # Final PATH for verification
  export PATH="$GO_HOME/bin:$GOBIN:$HOME/.local/bin:$PATH"

  echo ""
  status "Installation summary:"
  local all_ok=true
  for name in "${BIN_NAMES[@]}" sqlmap feroxbuster trufflehog gitleaks kr brutespray retire; do
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
