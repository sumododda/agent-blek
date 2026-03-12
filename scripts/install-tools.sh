#!/usr/bin/env bash
# Install all security tools required by the bug bounty agent.
# Idempotent — skips tools that are already installed.
# No sudo required — installs everything under $HOME.
# Optional: sudo apt install build-essential libpcap-dev nmap
#   (needed for naabu, jsluice, nmap — script skips these gracefully if missing)
set -euo pipefail

GOVERSION="1.23.6"
GO_HOME="$HOME/.local/go"
GOBIN="$HOME/go/bin"
OPT_DIR="$HOME/.local/opt"
BIN_DIR="$HOME/.local/bin"

# Go tools that compile without CGo (pure Go)
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
  "github.com/projectdiscovery/alterx/cmd/alterx@latest"
  "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  "github.com/d3mondev/puredns/v2@latest"
  "github.com/sensepost/gowitness@latest"
  "github.com/hakluke/hakrevdns@latest"
  "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
  "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
  "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
  "github.com/projectdiscovery/uncover/cmd/uncover@latest"
  "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
  "github.com/Charlie-belmer/nosqli@latest"
  "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  "github.com/devploit/nomore403@latest"
  "github.com/PentestPad/subzy@latest"
  "github.com/projectdiscovery/notify/cmd/notify@latest"
  "github.com/tomnomnom/qsreplace@latest"
  # gitleaks go.mod declares zricethezav path despite github.com/gitleaks/gitleaks repo
  "github.com/zricethezav/gitleaks/v8@latest"
)

GO_BIN_NAMES=(nuclei ffuf subfinder httpx katana gau dalfox amass dnsx alterx shuffledns puredns gowitness hakrevdns cdncheck asnmap tlsx uncover crlfuzz nosqli interactsh-client nomore403 subzy notify qsreplace gitleaks)

# Go tools that need CGo (gcc + system libs)
CGO_TOOLS=(
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/BishopFox/jsluice/cmd/jsluice@latest"
)
CGO_BIN_NAMES=(naabu jsluice)
CGO_DEPS=("libpcap-dev" "gcc")

status() { printf "\033[1;34m[+]\033[0m %s\n" "$*"; }
ok()     { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
warn()   { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
fail()   { printf "\033[1;31m[✗]\033[0m %s\n" "$*"; }

# ---------- Go (user-local install, no sudo) ----------
install_go() {
  export PATH="$GO_HOME/bin:$GOBIN:$BIN_DIR:$PATH"
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

# ---------- Pure Go tools ----------
install_go_tools() {
  export PATH="$GO_HOME/bin:$GOBIN:$BIN_DIR:$PATH"
  export GOPATH="$HOME/go"
  for i in "${!GO_TOOLS[@]}"; do
    local tool="${GO_TOOLS[$i]}"
    local name="${GO_BIN_NAMES[$i]}"
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

# ---------- CGo tools (need gcc + system libs) ----------
install_cgo_tools() {
  export PATH="$GO_HOME/bin:$GOBIN:$BIN_DIR:$PATH"
  export GOPATH="$HOME/go"

  if ! command -v gcc &>/dev/null; then
    warn "gcc not found — skipping CGo tools (naabu, jsluice)"
    warn "Fix: sudo apt install build-essential libpcap-dev"
    return 0
  fi

  for i in "${!CGO_TOOLS[@]}"; do
    local tool="${CGO_TOOLS[$i]}"
    local name="${CGO_BIN_NAMES[$i]}"
    if command -v "$name" &>/dev/null; then
      ok "$name already installed"
    else
      status "Installing $name (CGo)..."
      if CGO_ENABLED=1 go install "$tool" 2>&1; then
        ok "$name installed"
      else
        warn "$name installation failed — may need: sudo apt install build-essential libpcap-dev"
      fi
    fi
  done
}

# ---------- sqlmap (Python) ----------
install_sqlmap() {
  export PATH="$BIN_DIR:$PATH"
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
  export PATH="$BIN_DIR:$PATH"

  # Tools installable from PyPI
  local PYPI_TOOLS=(wafw00f arjun git-dumper waymore s3scanner uro clairvoyance cewler)
  for tool in "${PYPI_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
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

  # Tools that need git install (not on PyPI or broken PyPI packages)
  local GIT_PIP_TOOLS=(
    "paramspider:https://github.com/devanshbatham/paramspider.git"
    "ghauri:https://github.com/r0oth3x49/ghauri.git"
  )
  for entry in "${GIT_PIP_TOOLS[@]}"; do
    local name="${entry%%:*}"
    local repo="${entry#*:}"
    if command -v "$name" &>/dev/null; then
      ok "$name already installed"
    else
      status "Installing $name from git..."
      if command -v pipx &>/dev/null; then
        pipx install "git+${repo}" 2>&1 && ok "$name installed" || warn "$name installation failed (non-critical)"
      else
        pip3 install --user "git+${repo}" 2>&1 && ok "$name installed" || warn "$name installation failed (non-critical)"
      fi
    fi
  done
}

# ---------- Binary tools (GitHub releases) ----------
install_binary_tools() {
  export PATH="$BIN_DIR:$PATH"
  mkdir -p "$BIN_DIR"

  local arch
  arch=$(uname -m)
  local goarch="$arch"
  case "$arch" in
    x86_64)  goarch="amd64" ;;
    aarch64) goarch="arm64" ;;
  esac

  # feroxbuster — pre-built binary
  if command -v feroxbuster &>/dev/null; then
    ok "feroxbuster already installed"
  else
    status "Installing feroxbuster..."
    local ferox_arch="$arch"
    case "$arch" in
      x86_64)  ferox_arch="x86_64" ;;
      aarch64) ferox_arch="aarch64" ;;
    esac
    # Get latest version tag, then download with explicit version (no /latest/download redirect)
    local ferox_ver
    ferox_ver=$(curl -fsSL "https://api.github.com/repos/epi052/feroxbuster/releases/latest" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])" 2>/dev/null || echo "")
    if [ -n "$ferox_ver" ]; then
      local url="https://github.com/epi052/feroxbuster/releases/download/${ferox_ver}/${ferox_arch}-linux-feroxbuster.tar.gz"
      if curl -fsSL "$url" -o /tmp/ferox.tar.gz 2>/dev/null && tar xzf /tmp/ferox.tar.gz -C "$BIN_DIR" 2>/dev/null; then
        chmod +x "$BIN_DIR/feroxbuster"
        rm -f /tmp/ferox.tar.gz
        ok "feroxbuster installed ($ferox_ver)"
      else
        warn "feroxbuster installation failed (non-critical)"
      fi
    else
      warn "feroxbuster: could not determine latest version"
    fi
  fi

  # naabu — pre-built binary (fallback if CGo build failed)
  if ! command -v naabu &>/dev/null; then
    status "Installing naabu from pre-built binary..."
    local naabu_ver
    naabu_ver=$(curl -fsSL "https://api.github.com/repos/projectdiscovery/naabu/releases/latest" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))" 2>/dev/null || echo "")
    if [ -n "$naabu_ver" ]; then
      local url="https://github.com/projectdiscovery/naabu/releases/download/v${naabu_ver}/naabu_${naabu_ver}_linux_${goarch}.zip"
      if curl -fsSL "$url" -o /tmp/naabu.zip 2>/dev/null && python3 -c "
import zipfile, sys
with zipfile.ZipFile('/tmp/naabu.zip') as z:
    for name in z.namelist():
        if 'naabu' in name and not name.endswith('/'):
            with open('$BIN_DIR/naabu', 'wb') as f:
                f.write(z.read(name))
            break
" 2>/dev/null; then
        chmod +x "$BIN_DIR/naabu"
        rm -f /tmp/naabu.zip
        ok "naabu installed (pre-built $naabu_ver)"
      else
        warn "naabu pre-built installation failed"
      fi
    fi
  fi

  # brutespray — pre-built binary (Go rewrite, not a Python package)
  if command -v brutespray &>/dev/null; then
    ok "brutespray already installed"
  else
    status "Installing brutespray from pre-built binary..."
    local bs_ver
    bs_ver=$(curl -fsSL "https://api.github.com/repos/x90skysn3k/brutespray/releases/latest" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))" 2>/dev/null || echo "")
    if [ -n "$bs_ver" ]; then
      local url="https://github.com/x90skysn3k/brutespray/releases/download/v${bs_ver}/brutespray_v${bs_ver}_linux_${goarch}.tar.gz"
      if curl -fsSL "$url" -o /tmp/brutespray.tar.gz 2>/dev/null && tar xzf /tmp/brutespray.tar.gz -C "$BIN_DIR" brutespray 2>/dev/null; then
        chmod +x "$BIN_DIR/brutespray"
        rm -f /tmp/brutespray.tar.gz
        ok "brutespray installed ($bs_ver)"
      else
        warn "brutespray installation failed (non-critical)"
      fi
    else
      warn "brutespray: could not determine latest version"
    fi
  fi

  # trufflehog
  if command -v trufflehog &>/dev/null; then
    ok "trufflehog already installed"
  else
    status "Installing trufflehog..."
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$BIN_DIR" 2>&1 && ok "trufflehog installed" || warn "trufflehog installation failed"
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
}

# ---------- Git-cloned tools (to ~/.local/opt with venv wrappers) ----------
install_git_tools() {
  mkdir -p "$OPT_DIR" "$BIN_DIR"

  # Each entry: repo_url:dir_name:wrapper_entrypoint
  local GIT_TOOLS=(
    "https://github.com/vladko312/SSTImap.git:sstimap:sstimap.py"
    "https://github.com/commixproject/commix.git:commix:commix.py"
    "https://github.com/s0md3v/XSStrike.git:xsstrike:xsstrike.py"
    "https://github.com/ticarpi/jwt_tool.git:jwt_tool:jwt_tool.py"
    "https://github.com/dolevf/graphw00f.git:graphw00f:main.py"
  )

  for entry in "${GIT_TOOLS[@]}"; do
    local repo="${entry%%:*}"
    local rest="${entry#*:}"
    local dirname="${rest%%:*}"
    local entrypoint="${rest##*:}"
    local dest="$OPT_DIR/$dirname"
    local name="$dirname"

    if command -v "$name" &>/dev/null; then
      ok "$name already installed"
      continue
    fi

    if [ ! -d "$dest" ]; then
      status "Cloning $name..."
      git clone "$repo" "$dest" 2>/dev/null || { warn "$name clone failed (non-critical)"; continue; }
    fi

    # Create venv and install requirements if they exist
    if [ ! -d "$dest/.venv" ]; then
      python3 -m venv "$dest/.venv" 2>/dev/null || { warn "$name venv creation failed"; continue; }
      if [ -f "$dest/requirements.txt" ]; then
        "$dest/.venv/bin/pip" install -r "$dest/requirements.txt" 2>/dev/null || true
      else
        # Install common deps
        "$dest/.venv/bin/pip" install requests 2>/dev/null || true
      fi
    fi

    # Create wrapper script
    cat > "$BIN_DIR/$name" << WRAPPER
#!/usr/bin/env bash
exec "$dest/.venv/bin/python" "$dest/$entrypoint" "\$@"
WRAPPER
    chmod +x "$BIN_DIR/$name"
    ok "$name installed (venv wrapper)"
  done

  # ppfuzz (Rust/cargo)
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

  if ! command -v gcc &>/dev/null; then
    warn "gcc: NOT FOUND — some tools need: sudo apt install build-essential libpcap-dev"
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
  install_cgo_tools
  install_sqlmap
  install_python_tools
  install_binary_tools
  install_git_tools
  check_system_tools
  install_bba

  # Final PATH for verification
  export PATH="$GO_HOME/bin:$GOBIN:$BIN_DIR:$PATH"

  echo ""
  status "Installation summary:"
  local all_ok=true
  local total=0 installed=0
  for name in "${GO_BIN_NAMES[@]}" "${CGO_BIN_NAMES[@]}" sqlmap wafw00f arjun git-dumper waymore s3scanner uro clairvoyance cewler paramspider ghauri feroxbuster trufflehog brutespray retire qsreplace gitleaks sstimap commix xsstrike jwt_tool graphw00f; do
    total=$((total + 1))
    if command -v "$name" &>/dev/null; then
      installed=$((installed + 1))
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
  status "Installed: $installed / $total"
  if [ "$all_ok" = true ]; then
    ok "All tools installed successfully!"
  else
    warn "Some tools failed to install. Check errors above."
  fi
}

main "$@"
