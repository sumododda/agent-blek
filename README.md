# agent-blek

Autonomous bug bounty agent powered by Claude Code. Orchestrates reconnaissance, vulnerability scanning, OSINT, validation, and reporting through specialized AI agents.

## Architecture

```
/scan-target <program>
  Coordinator (Opus) -- reasons between phases, makes strategic decisions
    |-- Recon Agent (Haiku) -- multi-phase subdomain enum, DNS, ports, WAF, URL harvesting
    |-- Infrastructure Agent (Haiku) -- port scanning, service fingerprinting, ASN mapping
    |-- OSINT Agent (Sonnet) -- secret hunting, git dumping, cloud enumeration
    |-- Scanner Agent (Sonnet) -- nuclei, ffuf, feroxbuster, JS analysis, parameter discovery
    |-- Vuln-Tester Agent (Sonnet) -- category-specific testing (XSS, SQLi, SSRF, SSTI, etc.)
    |-- Deep Dive Agent (Opus) -- manual investigation of promising findings with curl
    |-- Validator Agent (Opus) -- independent re-testing, false positive filtering
    |-- Reporter Agent (Sonnet) -- professional security reports
```

The coordinator reasons between phases -- explicit thinking about what was found, what to prioritize, and when to dispatch conditional agents (infrastructure, OSINT) based on recon results.

## Prerequisites

### Required

| Dependency | Version | Purpose |
|-----------|---------|---------|
| **[Claude Code](https://docs.anthropic.com/en/docs/claude-code)** | Latest | Agent orchestration runtime -- this is the core engine |
| **Python** | >= 3.13 | BBA CLI and tool wrappers |
| **[uv](https://docs.astral.sh/uv/)** | Latest | Python package manager |
| **Go** | >= 1.23 | Most security tools are written in Go (auto-installed by setup script) |
| **git** | Any | Cloning tool repos and git-dumper OSINT |

### Optional (for full tool coverage)

| Dependency | Purpose | Install |
|-----------|---------|---------|
| **gcc + libpcap-dev** | CGo tools (naabu, jsluice) | `sudo apt install build-essential libpcap-dev` |
| **nmap** | Advanced port scanning & service detection | `sudo apt install nmap` |
| **Node.js + npm** | retire.js (vulnerable JS library detection) | `sudo apt install nodejs npm` |
| **Rust/cargo** | ppfuzz (prototype pollution fuzzer) | [rustup.rs](https://rustup.rs) |
| **pipx** | Cleaner Python tool isolation (falls back to pip) | `pip install pipx` |
| **Docker** | Integration tests against OWASP Juice Shop | [docs.docker.com](https://docs.docker.com/get-docker/) |

### API Keys (for enhanced recon)

Set these in your environment for tools that use external APIs:

```bash
export SHODAN_API_KEY="..."        # Shodan host search
export CENSYS_API_ID="..."         # Censys search
export CENSYS_API_SECRET="..."
export GITHUB_TOKEN="..."          # Trufflehog GitHub scanning
```

## Setup

### 1. Install Claude Code

Claude Code is the runtime that orchestrates all agents. Install it globally:

```bash
npm install -g @anthropic-ai/claude-code
```

Or see the [official installation guide](https://docs.anthropic.com/en/docs/claude-code) for alternative methods (Homebrew, direct download, etc.).

Verify it's working:

```bash
claude --version
```

You'll need an Anthropic API key or a Claude Pro/Max subscription.

### 2. Clone and install the project

```bash
git clone <repo-url> agent-blek
cd agent-blek

# Install the BBA CLI and dev dependencies
uv pip install -e ".[dev]"
```

### 3. Install security tools

The install script handles Go, Python, binary, and git-cloned tools -- all user-local, no sudo required:

```bash
bash scripts/install-tools.sh
```

This installs 56+ tools (subfinder, nuclei, httpx, ffuf, sqlmap, dalfox, etc.). Idempotent -- safe to re-run.

### 4. Download wordlists

```bash
uv run bba wordlist download --name all
```

Downloads SecLists, Assetnote DNS, OneListForAll, and resolver lists into `data/wordlists/`.

### 5. Define a target scope

Create a YAML scope file in `data/programs/`:

```yaml
# data/programs/example.yaml
program: example
platform: hackerone
handle: example
in_scope:
  domains:
    - "example.com"
    - "*.example.com"
  cidrs: []
out_of_scope:
  domains:
    - "admin.example.com"
    - "*.staging.example.com"
  paths:
    - "/logout"
    - "/account/delete"
rate_limit:
  requests_per_second: 10
  burst: 20
notes: |
  Example program configuration.
```

Or import directly from a bug bounty platform:

```bash
uv run bba scope import-h1 <hackerone-handle>
uv run bba scope import-bc <bugcrowd-handle>
```

## Running a Scan

### Full autonomous scan

Open Claude Code in the project directory and run the scan-target command:

```bash
cd agent-blek
claude

# Inside Claude Code, run:
/scan-target example
```

This launches the full pipeline: Recon -> Infrastructure -> OSINT -> Scanning -> Vuln Testing -> Deep Dive -> Validation -> Reporting. The Opus coordinator reasons between each phase and decides what to prioritize.

### Individual tools via BBA CLI

You can also run tools directly outside of Claude Code:

```bash
uv run bba recon subfinder example.com --program example    # subdomain enumeration
uv run bba recon httpx <targets> --program example          # HTTP probing
uv run bba recon katana <targets> --program example         # URL crawling
uv run bba recon naabu <targets> --program example          # port scanning
uv run bba scan nuclei <targets> --program example          # vulnerability scanning
uv run bba scan feroxbuster <url> --program example         # directory brute-force
uv run bba scan sqlmap <url> --program example              # SQL injection
uv run bba scan arjun <url> --program example               # parameter discovery
uv run bba db findings --program example                    # query findings
uv run bba db summary --program example                     # scan summary
uv run bba report --program example                         # generate report
```

### Dry-run mode

Preview what commands would run without executing them:

```bash
uv run bba --dry-run scan nuclei <targets> --program example
```

## Tool Categories

| Category | Tools |
|----------|-------|
| Subdomain Enum | subfinder, crtsh, amass, alterx, puredns, shuffledns |
| DNS & Resolution | dnsx, hakrevdns, asnmap |
| HTTP Probing | httpx, wafw00f, cdncheck, graphw00f, tlsx |
| Port Scanning | naabu, nmap, shodan, uncover |
| URL Harvesting | katana, gau, waymore, gowitness, cewler |
| Vuln Scanning | nuclei, ffuf, feroxbuster, sqlmap, dalfox |
| Parameter Discovery | arjun, paramspider |
| JS Analysis | jsluice (URLs + secrets), retirejs |
| Injection Testing | crlfuzz, sstimap, commix, ghauri, nosqli, xsstrike |
| Cloud & Auth | s3scanner, jwt-tool, subzy, clairvoyance |
| OOB & Bypass | interactsh, nomore403, cache-scanner, ppfuzz |
| OSINT | trufflehog, gitleaks, git-dumper |
| Utilities | uro, qsreplace, brutespray, notify |

## Database

SQLite at `data/db/findings.db` with tables: subdomains, services, ports, urls, js_files, secrets, screenshots, findings, audit_log, scan_runs, scan_phases, scan_snapshots.

```bash
uv run bba db subdomains --program example     # list discovered subdomains
uv run bba db services --program example       # list discovered services
uv run bba db urls --program example           # list discovered URLs
uv run bba db findings --program example       # list all findings
uv run bba db summary --program example        # full scan summary
uv run bba db scan-history --program example   # past scan runs
```

Or query directly:

```bash
sqlite3 data/db/findings.db "SELECT severity, COUNT(*) FROM findings WHERE program='example' GROUP BY severity"
```

## Project Layout

```
src/bba/cli/           CLI entry points (recon, scan, db, report submodules)
src/bba/               Core library (scope, db, rate limiter, sanitizer, tool runner)
src/bba/tools/         56 tool wrappers
data/programs/         Scope YAML files per target program
data/wordlists/        Downloaded wordlists (SecLists, Assetnote, resolvers)
data/output/           Raw tool output + reports
data/db/               SQLite database
.claude/agents/        Agent definitions (recon, infra, osint, scanner, vuln-tester, etc.)
.claude/commands/      User-facing commands (scan-target)
tests/                 Unit tests (558+ tests)
scripts/               Tool installation and setup scripts
```

## Safety

- All targets validated against scope before any tool invocation
- Rate limiting enforced per-target with configurable RPS and burst
- Tool output sanitized against prompt injection (9 detection patterns)
- Subprocess calls use list-based args (no shell injection possible)
- Findings require human approval before submission
- Full audit log of every action in the database
- Dry-run mode available for testing without execution

## Testing

```bash
# Unit tests (no external tools required)
uv run pytest tests/ --ignore=tests/integration -v

# Integration tests (requires Docker + Juice Shop)
docker run -d -p 3000:3000 bkimminich/juice-shop
uv run pytest tests/integration -v -m integration
```

## Scan Monitoring

Track scan progress and compare runs:

```bash
uv run bba db scan-history --program example                          # list past runs
uv run bba db scan-status <run_id> --program example                  # check run progress
uv run bba db scan-diff <old_id> <new_id> --category subdomains --program example  # delta between runs
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `bba: command not found` | Run `uv pip install -e ".[dev]"` and use `uv run bba` |
| Tool not found during scan | Run `bash scripts/install-tools.sh` and check output |
| Scope file not found | Create `data/programs/<name>.yaml` or use `uv run bba scope import-h1 <handle>` |
| Permission denied on tool | Tools install to `~/.local/bin` -- ensure it's in your `$PATH` |
| CGo tools fail to build | Install `build-essential` and `libpcap-dev`: `sudo apt install build-essential libpcap-dev` |
| Database locked errors | Only run one scan per program at a time |
