# Agent-Blek Hardening: Full Sweep Design

**Date:** 2026-03-27
**Scope:** All 14 issues from codebase audit — quick fixes, DRY refactor, DB improvements, scope hardening, agent orchestration overhaul, README expansion.

---

## 1. Quick Fixes

### 1a. Hardcoded Paths

**Files:** `src/bba/cli/__init__.py:97`, `src/bba/tools/feroxbuster.py`

Replace hardcoded `/home/sumo/agent-blek/...` with relative path resolution.

`cli/__init__.py` already computes `PROJECT_ROOT` at line 92. Change line 97:

```python
# Before
DEFAULT_WORDLIST = "/home/sumo/agent-blek/data/wordlists/seclists/Discovery/Web-Content/common.txt"

# After
DEFAULT_WORDLIST = str(DATA_DIR / "wordlists" / "seclists" / "Discovery" / "Web-Content" / "common.txt")
```

`feroxbuster.py` — compute relative to its own file:

```python
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_WORDLIST = str(_PROJECT_ROOT / "data" / "wordlists" / "seclists" / "Discovery" / "Web-Content" / "common.txt")
```

### 1b. Secrets Table Dedup

**File:** `src/bba/db.py`

Add UNIQUE constraint to schema:

```sql
CREATE TABLE IF NOT EXISTS secrets (
    ...
    UNIQUE(program, secret_type, value)
);
```

Change `add_secret()` from `INSERT INTO` to `INSERT OR IGNORE INTO`.

### 1c. Audit Log Indexes

**File:** `src/bba/db.py`

Add to SCHEMA string after existing indexes:

```sql
CREATE INDEX IF NOT EXISTS idx_audit_log_tool ON audit_log(tool);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target);
```

### 1d. Tool Name Substring Collision

**File:** `src/bba/db.py`, `add_finding()` method

Replace the `NOT LIKE` pattern:

```sql
-- Before
tool = CASE WHEN findings.tool NOT LIKE '%' || excluded.tool || '%'
       THEN findings.tool || ',' || excluded.tool
       ELSE findings.tool END

-- After
tool = CASE WHEN ',' || findings.tool || ',' NOT LIKE '%,' || excluded.tool || ',%'
       THEN findings.tool || ',' || excluded.tool
       ELSE findings.tool END
```

This wraps both sides with commas so `"sql"` won't match `"sqlmap"`.

### 1e. Evidence Field Cap

**File:** `src/bba/db.py`, `add_finding()` method

Add length check in the ON CONFLICT clause:

```sql
evidence = CASE WHEN LENGTH(findings.evidence) < 50000
           THEN findings.evidence || '; ' || excluded.evidence
           ELSE findings.evidence END
```

Caps at ~50KB per finding. Existing evidence is preserved; new evidence is silently dropped once the cap is hit.

---

## 2. DRY Refactor: ToolRunner Utilities

**File:** `src/bba/tool_runner.py`

Add 4 static utility methods. No new files, no class hierarchy changes.

### 2a. `parse_jsonl()`

Replaces identical 8-line JSONL parsing block in 8+ tool wrappers.

```python
@staticmethod
def parse_jsonl(output: str) -> list[dict]:
    results = []
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results
```

### 2b. `create_input_file()`

Replaces 3-line input file creation in 5+ tools.

```python
@staticmethod
def create_input_file(targets: list[str], work_dir: Path, filename: str = "targets.txt") -> Path:
    input_file = work_dir / filename
    input_file.write_text("\n".join(targets) + "\n")
    return input_file
```

### 2c. `extract_domain()`

Replaces `urlparse` + hostname extraction in 7+ tools.

```python
@staticmethod
def extract_domain(target: str) -> str:
    if "://" in target:
        from urllib.parse import urlparse
        return urlparse(target).hostname or target
    return target
```

### 2d. `error_result()`

Standardizes error return dict used across all tools.

```python
@staticmethod
def error_result(error: str | None = None) -> dict:
    return {"total": 0, "results": [], "error": error}
```

### Update Pattern

Each tool wrapper changes from:

```python
# Before (inline)
results = []
for line in output.strip().splitlines():
    ...

# After (one-liner)
results = self.runner.parse_jsonl(output)
```

Estimated ~250 lines removed across 61 tool files. Zero behavior change.

---

## 3. Database Schema Improvements

### 3a. `validation_reason` Field

**File:** `src/bba/db.py`

Add column to findings table:

```sql
ALTER TABLE findings ADD COLUMN validation_reason TEXT;
```

For fresh DBs, add to schema. For existing DBs, run migration via `initialize()`:

```python
# In initialize(), after executescript(SCHEMA):
try:
    await self._conn.execute("ALTER TABLE findings ADD COLUMN validation_reason TEXT")
    await self._conn.commit()
except Exception:
    pass  # Column already exists
```

Update `update_finding_status()`:

```python
async def update_finding_status(self, finding_id: int, status: str, reason: str | None = None) -> None:
    await self._conn.execute(
        "UPDATE findings SET status = ?, validated_at = CURRENT_TIMESTAMP, validation_reason = ? WHERE id = ?",
        (status, reason, finding_id),
    )
    if not self._batch_mode:
        await self._conn.commit()
```

CLI `bba db update-finding` gains `--reason` flag.

### 3b. `phase_outputs` Table

**File:** `src/bba/db.py` (add to SCHEMA) and `src/bba/scan_state.py`

```sql
CREATE TABLE IF NOT EXISTS phase_outputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    phase TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(run_id, phase, key)
);

CREATE INDEX IF NOT EXISTS idx_phase_outputs_lookup ON phase_outputs(run_id, phase);
```

Methods on `ScanState`:

```python
async def set_phase_output(self, run_id: int, phase: str, key: str, value: str) -> None:
    await self.db._conn.execute(
        """INSERT INTO phase_outputs (run_id, phase, key, value)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(run_id, phase, key) DO UPDATE SET value = excluded.value""",
        (run_id, phase, key, value),
    )
    await self.db._conn.commit()

async def get_phase_output(self, run_id: int, phase: str, key: str) -> str | None:
    cursor = await self.db._conn.execute(
        "SELECT value FROM phase_outputs WHERE run_id = ? AND phase = ? AND key = ?",
        (run_id, phase, key),
    )
    row = await cursor.fetchone()
    return row[0] if row else None

async def get_all_phase_outputs(self, run_id: int, phase: str) -> dict[str, str]:
    cursor = await self.db._conn.execute(
        "SELECT key, value FROM phase_outputs WHERE run_id = ? AND phase = ?",
        (run_id, phase),
    )
    rows = await cursor.fetchall()
    return {row[0]: row[1] for row in rows}
```

New CLI commands:

```bash
uv run bba db set-phase-output --program <prog> --phase <phase> --key <key> --value <json>
uv run bba db get-phase-output --program <prog> --phase <phase> --key <key>
```

These resolve `--program` to the latest `run_id` automatically.

### 3c. `coverage` Table

**File:** `src/bba/db.py`

```sql
CREATE TABLE IF NOT EXISTS coverage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    program TEXT NOT NULL,
    url TEXT NOT NULL,
    phase TEXT NOT NULL,
    category TEXT,
    tested BOOLEAN DEFAULT 0,
    skip_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(run_id, url, phase, category)
);

CREATE INDEX IF NOT EXISTS idx_coverage_program ON coverage(program);
CREATE INDEX IF NOT EXISTS idx_coverage_run ON coverage(run_id, phase);
```

Methods on `Database`:

```python
async def add_coverage(self, run_id: int, program: str, url: str, phase: str,
                       category: str | None, tested: bool, skip_reason: str | None = None) -> None:
    await self._conn.execute(
        """INSERT OR IGNORE INTO coverage (run_id, program, url, phase, category, tested, skip_reason)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (run_id, program, url, phase, category, tested, skip_reason),
    )
    if not self._batch_mode:
        await self._conn.commit()

async def get_coverage_summary(self, program: str) -> dict:
    cursor = await self._conn.execute(
        """SELECT phase, category,
                  SUM(CASE WHEN tested = 1 THEN 1 ELSE 0 END) as tested,
                  SUM(CASE WHEN tested = 0 THEN 1 ELSE 0 END) as skipped,
                  COUNT(*) as total
           FROM coverage WHERE program = ? GROUP BY phase, category""",
        (program,),
    )
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]
```

New CLI commands:

```bash
uv run bba db coverage --program <prog>
uv run bba db add-coverage --program <prog> --url <url> --phase <phase> --category <cat> --tested <bool> [--skip-reason <text>]
```

### 3d. Transaction Batching

**File:** `src/bba/db.py`

Add batch context manager:

```python
class Database:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._conn: aiosqlite.Connection | None = None
        self._batch_mode: bool = False

    @asynccontextmanager
    async def batch(self):
        self._batch_mode = True
        try:
            yield
        finally:
            self._batch_mode = False
            await self._conn.commit()
```

Update every `await self._conn.commit()` line to:

```python
if not self._batch_mode:
    await self._conn.commit()
```

Tools use it as:

```python
async with self.db.batch():
    for finding in results:
        await self.db.add_finding(...)
# Single commit at end
```

Fully backward-compatible: outside of `batch()`, every call commits immediately as before.

---

## 4. Scope Validation Hardening

### 4a. IDN/Punycode Normalization

**File:** `src/bba/scope.py`

Add normalization function:

```python
def _normalize_domain(domain: str) -> str:
    domain = domain.lower().rstrip(".")
    try:
        domain = domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        pass
    return domain
```

Update `_domain_matches()` to use it:

```python
def _domain_matches(pattern: str, domain: str) -> bool:
    domain = _normalize_domain(domain)
    pattern = _normalize_domain(pattern)
    ...
```

Update `is_domain_in_scope()` to normalize before matching:

```python
def is_domain_in_scope(self, domain: str) -> bool:
    domain = _normalize_domain(domain)
    ...
```

### 4b. CIDR Octet Validation

**File:** `src/bba/scope_importer.py`

Replace regex-only check:

```python
# Before
def _is_cidr(self, asset: str) -> bool:
    return bool(re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", asset))

# After
def _is_cidr(self, asset: str) -> bool:
    try:
        ipaddress.ip_network(asset, strict=False)
        return True
    except ValueError:
        return False
```

Uses stdlib `ipaddress` — rejects `999.999.999.999/32`, handles IPv6.

### 4c. API Key Configuration

**New file:** `src/bba/config.py` (~30 lines)

```python
from __future__ import annotations
import os

def resolve_api_key(value: str) -> str | None:
    if not value:
        return None
    if value.startswith("${") and value.endswith("}"):
        return os.environ.get(value[2:-1])
    return value
```

**File:** `src/bba/scope.py` — `ScopeConfig` gains optional `api_keys`:

```python
@dataclass
class ScopeConfig:
    ...
    api_keys: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> ScopeConfig:
        ...
        raw_keys = data.get("api_keys", {})
        resolved_keys = {k: resolve_api_key(v) for k, v in raw_keys.items()}
        return cls(..., api_keys=resolved_keys)
```

Scope YAML supports:

```yaml
api_keys:
  shodan: "${SHODAN_API_KEY}"
  censys_id: "${CENSYS_API_ID}"
  censys_secret: "${CENSYS_API_SECRET}"
  github: "${GITHUB_TOKEN}"
```

Tools that need keys access `scope_config.api_keys.get("shodan")`. No dotenv dependency — users set env vars however they prefer.

---

## 5. Agent Orchestration Improvements

### 5a. Expanded Phase Tracking

**File:** `src/bba/scan_state.py`

Replace `ALL_PHASES`:

```python
ALL_PHASES = [
    "precheck",
    "initialize",
    "recon",
    "recon-analysis",
    "infrastructure",
    "osint",
    "scan-planning",
    "scanning",
    "scan-analysis",
    "vuln-testing",
    "vuln-analysis",
    "deep-dive",
    "validation",
    "validation-analysis",
    "reporting",
    "diff-notify",
]
```

New CLI command for coordinator to record decisions:

```bash
uv run bba db update-phase <run_id> --phase infrastructure --status skipped --reason "no non-standard ports found"
```

### 5b. Structured Agent Handoffs

**Files:** `.claude/agents/recon.md`, `.claude/agents/scanner.md`, `.claude/agents/vuln-tester.md`, `.claude/agents/deep-dive.md`, `.claude/agents/validator.md`, `.claude/agents/reporter.md`, `.claude/commands/scan-target.md`

**Recon agent** — append to output instructions:

```
Before finishing, store structured outputs:
  uv run bba db set-phase-output --program <prog> --phase recon --key technology_profile --value '<json>'
  uv run bba db set-phase-output --program <prog> --phase recon --key waf_detected --value '<json>'
  uv run bba db set-phase-output --program <prog> --phase recon --key high_value_targets --value '<json>'
  uv run bba db set-phase-output --program <prog> --phase recon --key live_count --value '<number>'
```

**Scanner agent handoff** — change from prose placeholders to DB queries:

```
Before scanning, query the intelligence gathered so far:
  uv run bba db get-phase-output --program <prog> --phase recon --key technology_profile
  uv run bba db get-phase-output --program <prog> --phase recon --key waf_detected
  uv run bba db get-phase-output --program <prog> --phase recon --key high_value_targets
Use these to inform your scan strategy.

Before finishing, store your own structured outputs:
  uv run bba db set-phase-output --program <prog> --phase scanning --key url_classifications --value '<json>'
  uv run bba db set-phase-output --program <prog> --phase scanning --key discovered_endpoints --value '<json>'
```

**Vuln-tester handoff** — add DB reads:

```
Before testing, load the latest attack surface:
  uv run bba db urls --program <prog>
  uv run bba db findings --program <prog> --status new
  uv run bba db get-phase-output --program <prog> --phase scanning --key url_classifications
```

All agents follow the pattern: **read** prior phase outputs, **do** work, **write** own phase outputs.

### 5c. Scanner-to-Vuln-Tester Feedback Loop

Scanner already writes to the `urls` table. Vuln-tester prompt is updated (5b above) to query `uv run bba db urls --program <prog>` which includes scanner-discovered endpoints. Scanner stores gf_patterns classification as a phase output.

No new code needed — purely prompt changes.

### 5d. Deep-Dive Spawn/Collect Pattern

**File:** `.claude/commands/scan-target.md`

Replace vague deep-dive instructions with explicit:

```
PHASE 9: DEEP DIVES

For each deep-dive candidate identified in Phase 8c:
1. Spawn a deep-dive agent (can be parallel for independent targets)
2. Each deep-dive agent stores findings via `uv run bba db add-finding`
   with tool="manual-deep-dive"
3. WAIT for ALL deep-dive agents to complete before proceeding
4. Verify results: `uv run bba db findings --program <prog> --status new`
5. Only then proceed to Phase 10 (Validation)

IMPORTANT: Do NOT proceed to validation until all deep-dive agents have
finished. Check that the finding count in the DB reflects expected results.
```

### 5e. Validator Origin Tracking

**File:** `.claude/agents/validator.md`

Add to the validation process:

```
When validating, note the finding source via the `tool` field:
- Automated tools (nuclei, dalfox, sqlmap) -> higher false-positive rate, test thoroughly
- Deep-dive (manual-deep-dive) -> already manually investigated, verify PoC reproduces
- Include validation_reason with EVERY status update:
  uv run bba db update-finding <id> --status validated --reason "XSS fires in Chrome, reflected in unquoted attribute"
  uv run bba db update-finding <id> --status false_positive --reason "Response is static 403 page, not actual injection"
  uv run bba db update-finding <id> --status needs_review --reason "Intermittent — reproduced once but not consistently"
```

### 5f. Reporter Coverage & FP Stats

**File:** `.claude/agents/reporter.md`

Add sections to report template:

```
Generate a Coverage section:
  uv run bba db coverage --program <prog>
  Show: total endpoints discovered, tested count, skipped count, skip reasons breakdown

Generate a Validation Statistics section:
  - Total findings before validation: [count]
  - Validated: [count]
  - False positives: [count] with reason breakdown
  - Needs review: [count]
  - False positive rate: [percentage]
```

---

## 6. README Expansion

### 6a. Full Tools Reference

Replace the summary table in README.md with a comprehensive listing of all 56 tools organized by category. Each entry includes: tool name, one-line description, exact `uv run bba` command with flags.

Categories:
- Subdomain Enumeration (6): subfinder, crtsh, amass, alterx, puredns, shuffledns
- DNS & Resolution (3): dnsx, hakrevdns, asnmap
- HTTP Probing & Fingerprinting (5): httpx, wafw00f, cdncheck, graphw00f, tlsx
- Port Scanning & Infrastructure (4): naabu, nmap, shodan, uncover
- URL Harvesting & Crawling (5): katana, gau, waymore, gowitness, cewler
- Vulnerability Scanning (6): nuclei, ffuf, feroxbuster, sqlmap, dalfox, nikto
- Parameter & Endpoint Discovery (2): arjun, paramspider
- JS Analysis (3): jsluice-urls, jsluice-secrets, retirejs
- Injection Testing (8): crlfuzz, sstimap, commix, ghauri, nosqli, xsstrike, jwt-tool, ppfuzz
- Cloud & Auth (3): s3scanner, subzy, clairvoyance
- OOB & Bypass (4): interactsh, nomore403, cache-scanner, brutespray
- OSINT & Secrets (3): git-dumper, trufflehog, gitleaks
- TLS/SSL Auditing (3): testssl, sslyze, security-headers
- Pipeline Utilities (3): uro, qsreplace, notify

### 6b. New CLI Commands

Document the new commands introduced by this design:

```bash
# Phase output storage
uv run bba db set-phase-output --program <prog> --phase <phase> --key <key> --value <json>
uv run bba db get-phase-output --program <prog> --phase <phase> --key <key>

# Phase status updates
uv run bba db update-phase <run_id> --phase <phase> --status <status> [--reason <text>]

# Coverage tracking
uv run bba db coverage --program <prog>
uv run bba db add-coverage --program <prog> --url <url> --phase <phase> --category <cat> --tested <bool> [--skip-reason <text>]

# Updated existing command
uv run bba db update-finding <id> --status <status> [--reason <text>]
```

---

## Files Changed Summary

| Section | Files Modified | Files Created |
|---------|---------------|---------------|
| 1. Quick Fixes | `db.py`, `cli/__init__.py`, `feroxbuster.py` | — |
| 2. DRY Refactor | `tool_runner.py`, 61 tool wrappers | — |
| 3. DB Improvements | `db.py`, `scan_state.py`, `cli/db_cmds.py` | — |
| 4. Scope Hardening | `scope.py`, `scope_importer.py` | `config.py` |
| 5. Agent Orchestration | `scan_state.py`, all agent `.md` files, `scan-target.md` | — |
| 6. README | `README.md` | — |

**New file:** `src/bba/config.py` (~30 lines — API key resolver only)

**Total estimated changes:** ~700 lines modified, ~250 lines removed (DRY), ~200 lines added (new features). Net delta: ~-50 to +150 lines depending on how aggressively tools are deduplicated.

---

## Implementation Order

Recommended phasing to minimize risk:

1. **Quick fixes** (Section 1) — standalone, no dependencies, immediate value
2. **DRY refactor** (Section 2) — large but mechanical, tests catch regressions
3. **DB schema** (Section 3) — new tables/columns, backward-compatible migrations
4. **Scope hardening** (Section 4) — isolated module changes
5. **Agent prompts** (Section 5) — depends on Sections 3a, 3b, 3c being in place
6. **README** (Section 6) — last, reflects final state of all changes

Each section is independently deployable and testable.
