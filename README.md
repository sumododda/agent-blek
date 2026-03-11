# agent-blek

Autonomous bug bounty agent powered by Claude Code. Orchestrates reconnaissance, vulnerability scanning, validation, and reporting through specialized AI agents.

## Architecture

```
/scan-target <program>
  Coordinator (Opus) — reasons between phases, makes strategic decisions
    ├── Recon Agent (Haiku) — subdomain enumeration, service discovery, URL crawling
    ├── Scanner Agent (Sonnet) — nuclei, ffuf, sqlmap, dalfox with smart targeting
    ├── Deep Dive Agent (Opus) — manual investigation of promising findings
    ├── Validator Agent (Opus) — independent re-testing, false positive filtering
    └── Reporter Agent (Sonnet) — professional security reports
```

## Quick Start

```bash
# Install dependencies
uv pip install -e ".[dev]"

# Install security tools (no sudo required)
bash scripts/install-tools.sh

# Define a target scope
cat > data/programs/example.yaml <<EOF
program: example
platform: hackerone
in_scope:
  domains:
    - "example.com"
    - "*.example.com"
  cidrs: []
out_of_scope:
  domains: []
  paths: []
EOF

# Run a scan
/scan-target example
```

## Tools

The `bba` CLI wraps security tools with scope validation, rate limiting, and database storage:

| Category | Tools |
|----------|-------|
| Recon | subfinder, httpx, katana, gau |
| Scanning | nuclei, ffuf, sqlmap, dalfox |
| Database | SQLite with subdomains, services, findings, audit log |

```bash
uv run bba recon subfinder example.com --program example
uv run bba scan nuclei https://example.com --program example
uv run bba db findings --program example
uv run bba report --program example
```

## Safety

- All targets validated against scope before any tool invocation
- Rate limiting enforced per-target
- Tool output sanitized against prompt injection
- Findings require human approval before submission
- Full audit log of every action

## Testing

```bash
uv run pytest tests/ --ignore=tests/integration -v
```
