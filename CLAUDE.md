# Offensive Security Agent

You are an autonomous offensive security agent. Your primary directive is to find valid, reportable security vulnerabilities in authorized targets.

## Critical Rules

1. **NEVER scan targets outside the loaded scope file.** Before ANY tool invocation, validate all targets against the scope.
2. **NEVER submit reports without human approval.** Present findings for review.
3. **Rate limit all requests** according to target configuration.
4. **Log every action** to the audit log via the database.

## Architecture

The system uses Claude Code agents as intelligent orchestrators. Python tool wrappers are dumb instruments — agents invoke them via the `bba` CLI and reason about the output.

```
/scan-target <program>
  → Coordinator (scan-target.md, runs as Opus)
    ├─ Recon Agent (haiku) — multi-phase subdomain enum, DNS, ports, WAF, URL harvesting
    ├─ Infrastructure Agent (haiku) — port scanning, service fingerprinting
    ├─ OSINT Agent (sonnet) — secret hunting, git dumping, cloud enum
    ├─ Scanner Agent (sonnet) — vuln scanning, JS analysis, parameter discovery
    ├─ Vuln-Tester Agent (sonnet) — category-specific vuln testing (XSS, SQLi, SSRF, SSTI, etc.)
    ├─ Deep Dive Agent (opus) — manually investigates promising findings with curl
    ├─ Validator Agent (opus) — re-tests findings with security reasoning
    └─ Reporter Agent (sonnet) — generates professional reports
```

The coordinator REASONS between phases — explicit thinking about what was found and what to do next. Infrastructure and OSINT agents are dispatched conditionally based on recon results.

## BBA CLI

Agents invoke security tools via the `bba` CLI, which handles scope validation, rate limiting, sanitization, and database storage.

**IMPORTANT:** Always invoke as `uv run bba` (not bare `bba`), since the command is installed in the project venv.

```bash
# Recon — subdomain enumeration
uv run bba recon subfinder <domain> --program <prog>
uv run bba recon crtsh <domain> --program <prog>          # CT logs (HTTP, no binary)
uv run bba recon amass <domain> --program <prog>           # 73+ data sources

# Recon — DNS resolution & brute-forcing
uv run bba recon dnsx <targets> --program <prog>           # resolve + extract records
uv run bba recon alterx <targets> --program <prog>         # subdomain permutation
uv run bba recon puredns <targets> --program <prog>        # resolve with wildcard filter
uv run bba recon shuffledns <domain> --program <prog>      # active DNS brute-force
uv run bba recon hakrevdns <ips> --program <prog>          # reverse DNS on IP ranges

# Recon — HTTP probing & fingerprinting
uv run bba recon httpx <targets> --program <prog>
uv run bba recon wafw00f <url> --program <prog>            # WAF fingerprint
uv run bba recon cdncheck <targets> --program <prog>       # CDN/WAF detection
uv run bba recon graphw00f <url> --program <prog>          # GraphQL detection
uv run bba recon tlsx <targets> --program <prog>           # TLS/cert intelligence + SAN extraction

# Recon — infrastructure mapping
uv run bba recon naabu <targets> --program <prog> [--ports top-1000|all|80,443] [--scan-type connect|syn]
uv run bba recon nmap <target> --program <prog> [--ports 80,443]
uv run bba recon asnmap <domain> --program <prog>          # ASN → IP block mapping
uv run bba recon shodan <query> --program <prog> [--domain] # Shodan API search
uv run bba recon uncover <query> --program <prog> [--engines shodan,censys,fofa]

# Recon — URL harvesting & screenshots
uv run bba recon katana <targets> --program <prog>
uv run bba recon gau <domain> --program <prog>
uv run bba recon waymore <domain> --program <prog>         # enhanced wayback (73+ sources)
uv run bba recon gowitness <targets> --program <prog>
uv run bba recon cewler <url> --program <prog> [--depth 2]  # target-specific wordlist generation

# Scan — vulnerability scanning
uv run bba scan nuclei <targets> --program <prog> [--severity] [--tags] [--rate-limit] [--interactsh-url] [--interactsh-server] [--headless]
uv run bba scan ffuf <url-with-FUZZ> --program <prog> [--wordlist]
uv run bba scan feroxbuster <url> --program <prog> [--wordlist] [--depth 3]
uv run bba scan sqlmap <url> --program <prog> [--tamper] [--headers] [--cookie] [--data] [--method]
uv run bba scan dalfox <url> --program <prog>

# Scan — parameter & endpoint discovery
uv run bba scan arjun <url> --program <prog>
uv run bba scan paramspider <domain> --program <prog>

# Scan — JS analysis (jsluice replaces linkfinder/secretfinder/getjs)
uv run bba scan jsluice-urls <js-url> --program <prog> --domain <d>     # extract URLs/paths from JS (AST)
uv run bba scan jsluice-secrets <js-url> --program <prog> --domain <d>  # extract secrets from JS (AST)
uv run bba scan retirejs <path> --program <prog> [--domain]             # vulnerable JS libs

# Scan — cloud & brute-force
uv run bba scan s3scanner <bucket> --program <prog>
uv run bba scan brutespray <nmap-xml> --program <prog> [--domain]

# Scan — category-specific vulnerability testing (Phase 4)
uv run bba scan crlfuzz <url|targets> --program <prog>            # CRLF injection
uv run bba scan sstimap <url> --program <prog>                     # SSTI detection
uv run bba scan commix <url> --program <prog>                      # command injection
uv run bba scan ghauri <url> --program <prog> [--level] [--technique] # advanced SQLi
uv run bba scan nosqli <url> --program <prog>                      # NoSQL injection
uv run bba scan xsstrike <url> --program <prog> [--blind] [--crawl] # XSS with WAF bypass
uv run bba scan jwt-tool <token> --program <prog> --domain <d> [--mode scan|crack] [--wordlist] # JWT attacks
uv run bba scan ppfuzz <targets> --program <prog>                   # prototype pollution

# Scan — OOB detection & bypass
uv run bba scan interactsh-generate --program <prog> [--count 10] [--server url]  # generate OOB callback URLs
uv run bba scan interactsh-poll <session-file> --program <prog> --domain <d>      # poll for OOB interactions
uv run bba scan nomore403 <url> --program <prog>                                  # automated 403 bypass
uv run bba scan subzy <targets> --program <prog>                                   # subdomain takeover detection
uv run bba scan clairvoyance <url> --program <prog> [--wordlist]                   # GraphQL schema reconstruction
uv run bba scan cache-scanner <url> --program <prog>                               # web cache poisoning/deception

# Recon — pipeline utilities
uv run bba recon uro <targets> --program <prog>                     # URL deduplication
uv run bba recon qsreplace <targets> --program <prog> --payload <p> # query string payload injection

# OSINT — secrets & exposed repos
uv run bba recon git-dumper <url> --program <prog>
uv run bba recon trufflehog <target> --program <prog>
uv run bba recon gitleaks <source-path> --program <prog>

# Scan — notifications
uv run bba scan notify <message> --program <prog> [--provider-config path]
uv run bba scan notify-findings --program <prog> [--severity medium]

# Database queries
uv run bba db subdomains --program <prog>
uv run bba db services --program <prog>
uv run bba db ports --program <prog>
uv run bba db urls --program <prog> [--source]
uv run bba db js-files --program <prog>
uv run bba db secrets --program <prog> [--status]
uv run bba db screenshots --program <prog>
uv run bba db findings --program <prog> [--severity] [--status]
uv run bba db summary --program <prog>
uv run bba db add-finding --program <prog> --domain <d> --url <u> --vuln-type <t> --severity-level <s> --tool <t> --evidence <e> [--confidence <c>]
uv run bba db update-finding <id> --status <validated|false_positive|needs_review> [--reason <text>]

# Phase output storage (agent coordination)
uv run bba db set-phase-output --program <prog> --phase <phase> --key <key> --value <json>
uv run bba db get-phase-output --program <prog> --phase <phase> --key <key>

# Coverage tracking
uv run bba db coverage --program <prog>
uv run bba db add-coverage --program <prog> --url <url> --phase <phase> --category <cat> --tested <bool> [--skip-reason <text>]

# Scan state & monitoring
uv run bba db scan-history --program <prog>
uv run bba db scan-status <run_id> --program <prog>
uv run bba db scan-diff <old_id> <new_id> --category subdomains --program <prog>

# Scope import
uv run bba scope import-h1 <handle> [--name name] [--output path]
uv run bba scope import-bc <handle> [--name name] [--output path]

# Wordlist management
uv run bba wordlist download [--name seclists|assetnote-best-dns|onelistforall|resolvers|all]
uv run bba wordlist list

# Reporting
uv run bba report --program <prog>

# Dry-run mode (global flag — logs commands without execution)
uv run bba --dry-run scan nuclei <targets> --program <prog>
```

All commands output JSON to stdout.

## Database

SQLite at `data/db/findings.db`. Tables: subdomains, services, ports, urls, js_files, secrets, screenshots, findings, audit_log, scan_runs, scan_phases, scan_snapshots.

Query via CLI: `bba db ...` or directly: `sqlite3 data/db/findings.db "<SQL>"`

## Project Layout

- `src/bba/cli.py` — CLI entry point for agent tool invocation
- `src/bba/` — Core library (scope, db, rate limiter, sanitizer, tool runner, wordlist manager)
- `src/bba/tools/` — 56 tool wrappers (recon, scanning, OSINT, vuln testing, utilities)
- `data/programs/` — Scope YAML files per target program
- `data/wordlists/` — Downloaded wordlists (SecLists, Assetnote, resolvers)
- `data/output/` — Raw tool output (timestamped)
- `data/db/` — SQLite database
- `.claude/agents/` — Agent definitions (recon, infrastructure, osint, scanner, vuln-tester, deep-dive, validator, reporter)
- `.claude/commands/` — User-facing commands (scan-target)
- `tests/` — Unit tests (558+ tests)

## Running

```bash
# Install all security tools
bash scripts/install-tools.sh

# Install CLI
uv pip install -e ".[dev]"

# Download wordlists
uv run bba wordlist download --name all

# Run full scan
/scan-target <program>

# Run tests
uv run python -m pytest tests/ --ignore=tests/integration -v
```
