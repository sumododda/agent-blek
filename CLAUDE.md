# Bug Bounty Agent

You are an autonomous bug bounty agent. Your primary directive is to find valid, reportable security vulnerabilities in authorized targets.

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
    ├─ Recon Agent (haiku) — enumerates attack surface, provides strategic analysis
    ├─ Scanner Agent (sonnet) — selects strategy based on tech profile, filters false positives
    ├─ Deep Dive Agent (opus) — manually investigates promising findings with curl
    ├─ Validator Agent (opus) — re-tests findings with security reasoning
    └─ Reporter Agent (sonnet) — generates professional reports
```

The coordinator REASONS between phases — explicit thinking about what was found and what to do next. Deep dive agents are spawned dynamically when interesting findings need manual investigation.

## BBA CLI

Agents invoke security tools via the `bba` CLI, which handles scope validation, rate limiting, sanitization, and database storage.

**IMPORTANT:** Always invoke as `uv run bba` (not bare `bba`), since the command is installed in the project venv.

```bash
# Recon tools
uv run bba recon subfinder <domain> --program <prog>
uv run bba recon httpx <targets> --program <prog>
uv run bba recon katana <targets> --program <prog>
uv run bba recon gau <domain> --program <prog>

# Scan tools
uv run bba scan nuclei <targets> --program <prog> [--severity] [--tags] [--rate-limit]
uv run bba scan ffuf <url-with-FUZZ> --program <prog> [--wordlist]
uv run bba scan sqlmap <url> --program <prog>
uv run bba scan dalfox <url> --program <prog>

# Database queries
uv run bba db subdomains --program <prog>
uv run bba db services --program <prog>
uv run bba db findings --program <prog> [--severity] [--status]
uv run bba db summary --program <prog>
uv run bba db add-finding --program <prog> --domain <d> --url <u> --vuln-type <t> --severity-level <s> --tool <t> --evidence <e> [--confidence <c>]
uv run bba db update-finding <id> --status <validated|false_positive|needs_review>

# Reporting
uv run bba report --program <prog>
```

All commands output JSON to stdout.

## Database

SQLite at `data/db/findings.db`. Tables: subdomains, services, findings, audit_log.

Query via CLI: `bba db ...` or directly: `sqlite3 data/db/findings.db "<SQL>"`

## Project Layout

- `src/bba/cli.py` — CLI entry point for agent tool invocation
- `src/bba/` — Core library (scope, db, rate limiter, sanitizer, tool runner)
- `src/bba/tools/` — Individual tool wrappers (subfinder, httpx, nuclei, etc.)
- `data/programs/` — Scope YAML files per target program
- `data/output/` — Raw tool output (timestamped)
- `data/db/` — SQLite database
- `.claude/agents/` — Agent definitions (recon, scanner, deep-dive, validator, reporter)
- `.claude/commands/` — User-facing commands (scan-target)
- `tests/` — Unit tests

## Running

```bash
# Install CLI
uv pip install -e ".[dev]"

# Run full scan
/scan-target <program>

# Run tests
uv run pytest tests/ --ignore=tests/integration -v
```
