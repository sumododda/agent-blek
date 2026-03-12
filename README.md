# agent-blek

Autonomous bug bounty agent powered by Claude Code. Orchestrates reconnaissance, vulnerability scanning, OSINT, validation, and reporting through specialized AI agents.

## Architecture

```
/scan-target <program>
  Coordinator (Opus) — reasons between phases, makes strategic decisions
    ├── Recon Agent (Haiku) — multi-phase subdomain enum, DNS, ports, WAF, URL harvesting
    ├── Infrastructure Agent (Haiku) — port scanning, service fingerprinting, ASN mapping
    ├── OSINT Agent (Sonnet) — secret hunting, git dumping, cloud enumeration
    ├── Scanner Agent (Sonnet) — nuclei, ffuf, feroxbuster, JS analysis, parameter discovery
    ├── Vuln-Tester Agent (Sonnet) — category-specific testing (XSS, SQLi, SSRF, SSTI, etc.)
    ├── Deep Dive Agent (Opus) — manual investigation of promising findings with curl
    ├── Validator Agent (Opus) — independent re-testing, false positive filtering
    └── Reporter Agent (Sonnet) — professional security reports
```

The coordinator reasons between phases — explicit thinking about what was found, what to prioritize, and when to dispatch conditional agents (infrastructure, OSINT) based on recon results.

## Quick Start

```bash
# Install dependencies
uv pip install -e ".[dev]"

# Install security tools (no sudo required)
bash scripts/install-tools.sh

# Download wordlists
uv run bba wordlist download --name all

# Define a target scope
cat > data/programs/example.yaml <<EOF
program: example
platform: hackerone
handle: example
in_scope:
  domains:
    - "example.com"
    - "*.example.com"
  cidrs: []
out_of_scope:
  domains: []
  paths:
    - "/logout"
    - "/account/delete"
rate_limit:
  requests_per_second: 10
  burst: 20
notes: |
  Example program configuration.
EOF

# Run a scan
/scan-target example
```

## BBA CLI

The `bba` CLI wraps 50+ security tools with scope validation, rate limiting, sanitization, and database storage. All commands output JSON to stdout.

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

### Tool Categories

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

### Database

SQLite at `data/db/findings.db` with tables: subdomains, services, ports, urls, js_files, secrets, screenshots, findings, audit_log, scan_runs, scan_phases, scan_snapshots.

## Project Layout

```
src/bba/cli/           CLI entry points (recon, scan, db, report submodules)
src/bba/               Core library (scope, db, rate limiter, sanitizer, tool runner)
src/bba/tools/         50+ tool wrappers
data/programs/         Scope YAML files per target program
data/wordlists/        Downloaded wordlists (SecLists, Assetnote, resolvers)
data/output/           Raw tool output + reports
data/db/               SQLite database
.claude/agents/        Agent definitions (recon, infra, osint, scanner, vuln-tester, etc.)
.claude/commands/      User-facing commands (scan-target)
tests/                 Unit tests (558+ tests)
```

## Safety

- All targets validated against scope before any tool invocation
- Rate limiting enforced per-target with configurable rps and burst
- Tool output sanitized against prompt injection
- Findings require human approval before submission
- Full audit log of every action in the database
- Dry-run mode available: `uv run bba --dry-run scan nuclei <targets> --program example`

## Testing

```bash
uv run pytest tests/ --ignore=tests/integration -v
```
