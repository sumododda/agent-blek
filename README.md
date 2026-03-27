# agent-blek

Autonomous offensive security agent powered by Claude Code. Orchestrates reconnaissance, vulnerability scanning, OSINT, validation, and reporting through specialized AI agents.

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

You can also embed API keys directly in scope YAML files using environment variable substitution:

```yaml
api_keys:
  shodan: "${SHODAN_API_KEY}"
  censys_id: "${CENSYS_API_ID}"
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
# data/programs/acme-corp.yaml
program: acme-corp
platform: hackerone          # hackerone | bugcrowd | intigriti | self-hosted
handle: acme-corp            # platform handle (used by scope import)

in_scope:
  domains:
    # Wildcards — cover all subdomains
    - "*.acme-corp.com"
    - "*.api.acme-corp.com"

    # Explicit high-value targets
    - "acme-corp.com"
    - "app.acme-corp.com"
    - "api.acme-corp.com"
    - "dashboard.acme-corp.com"
    - "auth.acme-corp.com"

  cidrs:
    - "203.0.113.0/24"       # Primary hosting range

out_of_scope:
  domains:
    - "status.acme-corp.com"           # Third-party status page
    - "docs.acme-corp.com"             # Static docs (no vuln impact)
    - "*.staging.acme-corp.com"        # Staging (separate program)
    - "corporate-blog.acme-corp.com"   # WordPress managed by vendor

  paths:
    - "/logout"
    - "/account/delete"
    - "/account/deactivate"
    - "/unsubscribe"

rate_limit:
  requests_per_second: 10   # Requests per second per target
  burst: 20                  # Token bucket burst size

api_keys:
  shodan: "${SHODAN_API_KEY}"
  censys_id: "${CENSYS_API_ID}"
  censys_secret: "${CENSYS_API_SECRET}"
  github: "${GITHUB_TOKEN}"

notes: |
  HackerOne program for Acme Corp.
  Main app is a React SPA backed by Express.js API.
  auth.acme-corp.com runs Keycloak — test for OIDC misconfigs.
  API uses JWT (RS256) — check for algorithm confusion.
  WAF: Cloudflare on *.acme-corp.com — use conservative rate limits.
  Mobile apps in scope on the platform but not testable via CLI.
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

### Subdomain Enumeration (6)

| Tool | Description | Command |
|------|-------------|---------|
| subfinder | Passive subdomain discovery via APIs | `uv run bba recon subfinder <domain> --program <prog>` |
| crtsh | Certificate Transparency log search | `uv run bba recon crtsh <domain> --program <prog>` |
| amass | 73+ data source subdomain enum | `uv run bba recon amass <domain> --program <prog>` |
| alterx | Subdomain permutation generation | `uv run bba recon alterx <targets> --program <prog>` |
| puredns | DNS resolution with wildcard filtering | `uv run bba recon puredns <targets> --program <prog>` |
| shuffledns | Active DNS brute-force | `uv run bba recon shuffledns <domain> --program <prog>` |

### DNS & Resolution (3)

| Tool | Description | Command |
|------|-------------|---------|
| dnsx | DNS resolution + record extraction | `uv run bba recon dnsx <targets> --program <prog>` |
| hakrevdns | Reverse DNS on IP ranges | `uv run bba recon hakrevdns <ips> --program <prog>` |
| asnmap | ASN to IP block mapping | `uv run bba recon asnmap <domain> --program <prog>` |

### HTTP Probing & Fingerprinting (5)

| Tool | Description | Command |
|------|-------------|---------|
| httpx | HTTP probing + tech detection | `uv run bba recon httpx <targets> --program <prog>` |
| wafw00f | WAF fingerprinting | `uv run bba recon wafw00f <url> --program <prog>` |
| cdncheck | CDN/WAF detection | `uv run bba recon cdncheck <targets> --program <prog>` |
| graphw00f | GraphQL endpoint detection | `uv run bba recon graphw00f <url> --program <prog>` |
| tlsx | TLS/cert intelligence + SAN extraction | `uv run bba recon tlsx <targets> --program <prog>` |

### Port Scanning & Infrastructure (4)

| Tool | Description | Command |
|------|-------------|---------|
| naabu | Fast port scanning | `uv run bba recon naabu <targets> --program <prog> [--ports top-1000]` |
| nmap | Service fingerprinting | `uv run bba recon nmap <target> --program <prog> [--ports 80,443]` |
| shodan | Shodan API search | `uv run bba recon shodan <query> --program <prog> [--domain]` |
| uncover | Multi-engine search (Shodan/Censys/FOFA) | `uv run bba scan uncover <query> --program <prog> [--engines]` |

### URL Harvesting & Crawling (5)

| Tool | Description | Command |
|------|-------------|---------|
| katana | Web crawler + endpoint extraction | `uv run bba recon katana <targets> --program <prog>` |
| gau | Wayback Machine URL fetching | `uv run bba recon gau <domain> --program <prog>` |
| waymore | Enhanced wayback (73+ sources) | `uv run bba recon waymore <domain> --program <prog>` |
| gowitness | Screenshot capture | `uv run bba recon gowitness <targets> --program <prog>` |
| cewler | Target-specific wordlist generation | `uv run bba recon cewler <url> --program <prog> [--depth 2]` |

### Vulnerability Scanning (6)

| Tool | Description | Command |
|------|-------------|---------|
| nuclei | Template-based vulnerability scanner | `uv run bba scan nuclei <targets> --program <prog> [--severity] [--tags]` |
| ffuf | Web fuzzer (dirs, vhosts, params) | `uv run bba scan ffuf <url-with-FUZZ> --program <prog> [--wordlist]` |
| feroxbuster | Recursive directory brute-force | `uv run bba scan feroxbuster <url> --program <prog> [--wordlist] [--depth]` |
| sqlmap | SQL injection detection + exploitation | `uv run bba scan sqlmap <url> --program <prog> [--tamper] [--data]` |
| dalfox | XSS scanner with DOM analysis | `uv run bba scan dalfox <url> --program <prog>` |
| nikto | Web server vulnerability scanner | `uv run bba scan nikto <url> --program <prog>` |

### Parameter & Endpoint Discovery (2)

| Tool | Description | Command |
|------|-------------|---------|
| arjun | Hidden HTTP parameter discovery | `uv run bba scan arjun <url> --program <prog>` |
| paramspider | URL parameter mining from archives | `uv run bba scan paramspider <domain> --program <prog>` |

### JS Analysis (3)

| Tool | Description | Command |
|------|-------------|---------|
| jsluice (URLs) | AST-based URL/path extraction from JS | `uv run bba scan jsluice-urls <js-url> --program <prog> --domain <d>` |
| jsluice (secrets) | AST-based secret extraction from JS | `uv run bba scan jsluice-secrets <js-url> --program <prog> --domain <d>` |
| retirejs | Vulnerable JS library detection | `uv run bba scan retirejs <path> --program <prog>` |

### Injection Testing (8)

| Tool | Description | Command |
|------|-------------|---------|
| crlfuzz | CRLF injection testing | `uv run bba scan crlfuzz <url> --program <prog>` |
| sstimap | Server-side template injection | `uv run bba scan sstimap <url> --program <prog>` |
| commix | Command injection testing | `uv run bba scan commix <url> --program <prog>` |
| ghauri | Advanced SQL injection | `uv run bba scan ghauri <url> --program <prog> [--level] [--technique]` |
| nosqli | NoSQL injection detection | `uv run bba scan nosqli <url> --program <prog>` |
| xsstrike | XSS with WAF bypass | `uv run bba scan xsstrike <url> --program <prog> [--blind] [--crawl]` |
| jwt-tool | JWT attack testing | `uv run bba scan jwt-tool <token> --program <prog> --domain <d> [--mode]` |
| ppfuzz | Prototype pollution fuzzing | `uv run bba scan ppfuzz <targets> --program <prog>` |

### Cloud & Auth (3)

| Tool | Description | Command |
|------|-------------|---------|
| s3scanner | S3 bucket misconfiguration | `uv run bba scan s3scanner <bucket> --program <prog>` |
| subzy | Subdomain takeover detection | `uv run bba scan subzy <targets> --program <prog>` |
| clairvoyance | GraphQL schema reconstruction | `uv run bba scan clairvoyance <url> --program <prog>` |

### OOB & Bypass (4)

| Tool | Description | Command |
|------|-------------|---------|
| interactsh | Out-of-band callback generation/polling | `uv run bba scan interactsh-generate --program <prog>` |
| nomore403 | Automated 403 bypass techniques | `uv run bba scan nomore403 <url> --program <prog>` |
| cache-scanner | Web cache poisoning/deception | `uv run bba scan cache-scanner <url> --program <prog>` |
| brutespray | Service credential brute-force | `uv run bba scan brutespray <nmap-xml> --program <prog>` |

### OSINT & Secrets (3)

| Tool | Description | Command |
|------|-------------|---------|
| git-dumper | Exposed .git directory dumping | `uv run bba recon git-dumper <url> --program <prog>` |
| trufflehog | Secret scanning in repos/URLs | `uv run bba recon trufflehog <target> --program <prog>` |
| gitleaks | Git secret scanning | `uv run bba recon gitleaks <source-path> --program <prog>` |

### TLS/SSL Auditing (3)

| Tool | Description | Command |
|------|-------------|---------|
| testssl | TLS/SSL configuration testing | `uv run bba scan testssl <url> --program <prog>` |
| sslyze | SSL/TLS server analysis | `uv run bba scan sslyze <target> --program <prog>` |
| security-headers | HTTP security header analysis | `uv run bba scan security-headers <url> --program <prog>` |

### Pipeline Utilities (3)

| Tool | Description | Command |
|------|-------------|---------|
| uro | URL deduplication and normalization | `uv run bba recon uro <targets> --program <prog>` |
| qsreplace | Query string payload injection | `uv run bba recon qsreplace <targets> --program <prog> --payload <p>` |
| notify | Send alerts to Slack/Discord/Telegram | `uv run bba scan notify <message> --program <prog>` |

## Database

SQLite at `data/db/findings.db` with tables: subdomains, services, ports, urls, js_files, secrets, screenshots, findings, audit_log, scan_runs, scan_phases, scan_snapshots.

```bash
uv run bba db subdomains --program example     # list discovered subdomains
uv run bba db services --program example       # list discovered services
uv run bba db urls --program example           # list discovered URLs
uv run bba db findings --program example       # list all findings
uv run bba db summary --program example        # full scan summary
uv run bba db scan-history --program example   # past scan runs

# Phase outputs (agent coordination)
uv run bba db set-phase-output --program example --phase recon --key technology_profile --value '{"frameworks":["Express.js"]}'
uv run bba db get-phase-output --program example --phase recon --key technology_profile

# Coverage tracking
uv run bba db coverage --program example

# Update finding with reason
uv run bba db update-finding 1 --status validated --reason "XSS confirmed"
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
