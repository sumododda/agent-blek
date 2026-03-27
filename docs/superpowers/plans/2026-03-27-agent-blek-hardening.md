# Agent-Blek Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all 14 issues from the codebase audit — quick fixes, DRY refactor, DB improvements, scope hardening, agent orchestration, README expansion.

**Architecture:** Six independent sections executed in dependency order. Sections 1-4 are pure code changes with tests. Section 5 is agent prompt updates (depends on DB changes from 3). Section 6 is documentation (reflects final state).

**Tech Stack:** Python 3.13, aiosqlite, pytest + pytest-asyncio, YAML scope files, Claude Code agent markdown prompts.

---

### Task 1: Fix hardcoded paths

**Files:**
- Modify: `src/bba/cli/__init__.py:97`
- Modify: `src/bba/tools/feroxbuster.py:15`
- Test: `tests/test_hardcoded_paths.py`

- [ ] **Step 1: Write test for relative path resolution**

Create `tests/test_hardcoded_paths.py`:

```python
import pytest
from pathlib import Path


class TestDefaultWordlistPaths:
    def test_cli_default_wordlist_is_relative(self):
        from bba.cli import DEFAULT_WORDLIST
        assert "/home/sumo" not in DEFAULT_WORDLIST
        assert "agent-blek" not in DEFAULT_WORDLIST or DEFAULT_WORDLIST.startswith(str(Path(__file__).resolve().parent.parent))

    def test_feroxbuster_default_wordlist_is_relative(self):
        from bba.tools.feroxbuster import DEFAULT_WORDLIST
        assert "/home/sumo" not in DEFAULT_WORDLIST

    def test_cli_wordlist_under_data_dir(self):
        from bba.cli import DEFAULT_WORDLIST, DATA_DIR
        assert DEFAULT_WORDLIST.startswith(str(DATA_DIR))

    def test_feroxbuster_wordlist_path_structure(self):
        from bba.tools.feroxbuster import DEFAULT_WORDLIST
        assert "seclists" in DEFAULT_WORDLIST
        assert "common.txt" in DEFAULT_WORDLIST
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_hardcoded_paths.py -v`
Expected: FAIL — both DEFAULT_WORDLIST values contain `/home/sumo`

- [ ] **Step 3: Fix cli/__init__.py**

In `src/bba/cli/__init__.py`, change line 97 from:

```python
DEFAULT_WORDLIST = "/home/sumo/agent-blek/data/wordlists/seclists/Discovery/Web-Content/common.txt"
```

to:

```python
DEFAULT_WORDLIST = str(DATA_DIR / "wordlists" / "seclists" / "Discovery" / "Web-Content" / "common.txt")
```

- [ ] **Step 4: Fix feroxbuster.py**

In `src/bba/tools/feroxbuster.py`, replace line 15:

```python
DEFAULT_WORDLIST = "/home/sumo/agent-blek/data/wordlists/seclists/Discovery/Web-Content/common.txt"
```

with:

```python
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_WORDLIST = str(_PROJECT_ROOT / "data" / "wordlists" / "seclists" / "Discovery" / "Web-Content" / "common.txt")
```

Note: `Path` is already imported at the top if not, add `from pathlib import Path`. Check the existing imports first.

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_hardcoded_paths.py -v`
Expected: All 4 PASS

- [ ] **Step 6: Run full test suite to check for regressions**

Run: `uv run pytest tests/ --ignore=tests/integration -v`
Expected: All existing tests still pass

- [ ] **Step 7: Commit**

```bash
git add tests/test_hardcoded_paths.py src/bba/cli/__init__.py src/bba/tools/feroxbuster.py
git commit -m "fix: replace hardcoded absolute paths with relative resolution"
```

---

### Task 2: Fix DB bugs — secrets dedup, audit indexes, tool substring, evidence cap

**Files:**
- Modify: `src/bba/db.py:91-102` (secrets UNIQUE), `src/bba/db.py:115-127` (indexes), `src/bba/db.py:200-216` (add_finding SQL)
- Test: `tests/test_db_fixes.py`

- [ ] **Step 1: Write tests for all 4 DB fixes**

Create `tests/test_db_fixes.py`:

```python
import pytest
from bba.db import Database


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestSecretsDedup:
    async def test_duplicate_secret_ignored(self, db):
        await db.add_secret("prog", "api_key", "AKIA1234", "https://x.com", "", "trufflehog", 0.9)
        await db.add_secret("prog", "api_key", "AKIA1234", "https://x.com", "", "gitleaks", 0.8)
        secrets = await db.get_secrets("prog")
        assert len(secrets) == 1

    async def test_different_secrets_not_deduped(self, db):
        await db.add_secret("prog", "api_key", "AKIA1234", "", "", "trufflehog", 0.9)
        await db.add_secret("prog", "api_key", "AKIA5678", "", "", "trufflehog", 0.9)
        secrets = await db.get_secrets("prog")
        assert len(secrets) == 2


class TestAuditLogIndexes:
    async def test_audit_log_indexes_exist(self, db):
        cursor = await db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='audit_log'"
        )
        rows = await cursor.fetchall()
        index_names = [r[0] for r in rows]
        assert "idx_audit_log_tool" in index_names
        assert "idx_audit_log_timestamp" in index_names
        assert "idx_audit_log_target" in index_names


class TestToolSubstringCollision:
    async def test_sql_not_confused_with_sqlmap(self, db):
        """Tool 'sql' should not prevent 'sqlmap' from being appended."""
        await db.add_finding("prog", "a.com", "https://a.com/x", "sqli", "high", "sql", "ev1", 0.7)
        await db.add_finding("prog", "a.com", "https://a.com/x", "sqli", "high", "sqlmap", "ev2", 0.8)
        findings = await db.get_findings("prog")
        assert "sql" in findings[0]["tool"]
        assert "sqlmap" in findings[0]["tool"]

    async def test_exact_tool_not_duplicated(self, db):
        await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "dalfox", "ev1", 0.8)
        await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "dalfox", "ev2", 0.9)
        findings = await db.get_findings("prog")
        assert findings[0]["tool"] == "dalfox"


class TestEvidenceCap:
    async def test_evidence_capped_at_50k(self, db):
        large_evidence = "x" * 49000
        await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "t", large_evidence, 0.8)
        await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "t2", "new_evidence", 0.9)
        findings = await db.get_findings("prog")
        # First evidence + separator + second should be present (under cap)
        assert "new_evidence" in findings[0]["evidence"]

    async def test_evidence_stops_growing_past_cap(self, db):
        large_evidence = "x" * 51000
        await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "t", large_evidence, 0.8)
        await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "t2", "should_not_appear", 0.9)
        findings = await db.get_findings("prog")
        assert "should_not_appear" not in findings[0]["evidence"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_db_fixes.py -v`
Expected: FAIL — secrets dedup fails (no UNIQUE), audit log indexes fail (no indexes), tool substring collision fails ("sql" matches "sqlmap"), evidence cap test may fail

- [ ] **Step 3: Fix secrets table — add UNIQUE constraint**

In `src/bba/db.py`, in the SCHEMA string, change the secrets table (lines 91-102). Add `UNIQUE(program, secret_type, value)` before the closing `);`:

```sql
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    secret_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source_url TEXT,
    source_file TEXT,
    tool TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    status TEXT DEFAULT 'new',
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program, secret_type, value)
);
```

Also change `add_secret()` method (line 364) from `INSERT INTO` to `INSERT OR IGNORE INTO`:

```python
    async def add_secret(
        self, program: str, secret_type: str, value: str,
        source_url: str, source_file: str, tool: str, confidence: float,
    ) -> None:
        await self._conn.execute(
            """INSERT OR IGNORE INTO secrets
               (program, secret_type, value, source_url, source_file, tool, confidence)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (program, secret_type, value, source_url, source_file, tool, confidence),
        )
        await self._conn.commit()
```

- [ ] **Step 4: Fix audit log — add indexes**

In `src/bba/db.py`, after line 124 (`idx_screenshots_program`), add:

```sql
CREATE INDEX IF NOT EXISTS idx_audit_log_tool ON audit_log(tool);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target);
```

- [ ] **Step 5: Fix tool name substring collision**

In `src/bba/db.py`, in the `add_finding()` method (lines 210-212), change:

```python
                 tool = CASE WHEN findings.tool NOT LIKE '%' || excluded.tool || '%'
                        THEN findings.tool || ',' || excluded.tool
                        ELSE findings.tool END""",
```

to:

```python
                 tool = CASE WHEN ',' || findings.tool || ',' NOT LIKE '%,' || excluded.tool || ',%'
                        THEN findings.tool || ',' || excluded.tool
                        ELSE findings.tool END""",
```

- [ ] **Step 6: Fix evidence field cap**

In the same `add_finding()` method, change line 208:

```python
                 evidence = findings.evidence || '; ' || excluded.evidence,
```

to:

```python
                 evidence = CASE WHEN LENGTH(findings.evidence) < 50000
                            THEN findings.evidence || '; ' || excluded.evidence
                            ELSE findings.evidence END,
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/test_db_fixes.py -v`
Expected: All 6 PASS

- [ ] **Step 8: Run full test suite**

Run: `uv run pytest tests/ --ignore=tests/integration -v`
Expected: All existing tests still pass

- [ ] **Step 9: Commit**

```bash
git add src/bba/db.py tests/test_db_fixes.py
git commit -m "fix: secrets dedup, audit indexes, tool substring collision, evidence cap"
```

---

### Task 3: Add ToolRunner utility methods (DRY refactor)

**Files:**
- Modify: `src/bba/tool_runner.py`
- Test: `tests/test_tool_runner_utils.py`

- [ ] **Step 1: Write tests for the 4 utility methods**

Create `tests/test_tool_runner_utils.py`:

```python
import json
import pytest
from pathlib import Path
from bba.tool_runner import ToolRunner


class TestParseJsonl:
    def test_parses_valid_jsonl(self):
        output = '{"host":"a.com"}\n{"host":"b.com"}\n'
        results = ToolRunner.parse_jsonl(output)
        assert len(results) == 2
        assert results[0]["host"] == "a.com"

    def test_skips_invalid_lines(self):
        output = '{"host":"a.com"}\nnot-json\n{"host":"b.com"}\n'
        results = ToolRunner.parse_jsonl(output)
        assert len(results) == 2

    def test_handles_empty_output(self):
        assert ToolRunner.parse_jsonl("") == []
        assert ToolRunner.parse_jsonl("  \n  \n") == []

    def test_handles_blank_lines(self):
        output = '{"a":1}\n\n\n{"b":2}\n'
        results = ToolRunner.parse_jsonl(output)
        assert len(results) == 2


class TestCreateInputFile:
    def test_creates_file_with_targets(self, tmp_path):
        targets = ["a.example.com", "b.example.com"]
        result = ToolRunner.create_input_file(targets, tmp_path)
        assert result.exists()
        content = result.read_text()
        assert "a.example.com\n" in content
        assert "b.example.com\n" in content

    def test_custom_filename(self, tmp_path):
        result = ToolRunner.create_input_file(["a.com"], tmp_path, filename="custom.txt")
        assert result.name == "custom.txt"

    def test_default_filename(self, tmp_path):
        result = ToolRunner.create_input_file(["a.com"], tmp_path)
        assert result.name == "targets.txt"


class TestExtractDomain:
    def test_extracts_from_url(self):
        assert ToolRunner.extract_domain("https://api.example.com/v1") == "api.example.com"

    def test_extracts_from_http_url(self):
        assert ToolRunner.extract_domain("http://shop.example.com") == "shop.example.com"

    def test_returns_plain_domain(self):
        assert ToolRunner.extract_domain("example.com") == "example.com"

    def test_handles_url_with_port(self):
        assert ToolRunner.extract_domain("https://api.example.com:8443/v2") == "api.example.com"


class TestErrorResult:
    def test_default_error_result(self):
        result = ToolRunner.error_result()
        assert result == {"total": 0, "results": [], "error": None}

    def test_error_result_with_message(self):
        result = ToolRunner.error_result("timeout")
        assert result == {"total": 0, "results": [], "error": "timeout"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_tool_runner_utils.py -v`
Expected: FAIL — methods don't exist yet

- [ ] **Step 3: Add utility methods to ToolRunner**

In `src/bba/tool_runner.py`, add `import json` to the imports at the top (line 2 area), then add these 4 static methods to the `ToolRunner` class, after the `__init__` method (after line 35):

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

    @staticmethod
    def create_input_file(targets: list[str], work_dir: Path, filename: str = "targets.txt") -> Path:
        input_file = work_dir / filename
        input_file.write_text("\n".join(targets) + "\n")
        return input_file

    @staticmethod
    def extract_domain(target: str) -> str:
        if "://" in target:
            from urllib.parse import urlparse
            return urlparse(target).hostname or target
        return target

    @staticmethod
    def error_result(error: str | None = None) -> dict:
        return {"total": 0, "results": [], "error": error}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_tool_runner_utils.py -v`
Expected: All 12 PASS

- [ ] **Step 5: Commit**

```bash
git add src/bba/tool_runner.py tests/test_tool_runner_utils.py
git commit -m "feat: add parse_jsonl, create_input_file, extract_domain, error_result to ToolRunner"
```

---

### Task 4: Apply ToolRunner utilities across tool wrappers

**Files:**
- Modify: All files in `src/bba/tools/` that have the duplicated patterns
- Test: Existing tool tests (regression check)

- [ ] **Step 1: Update subfinder.py**

In `src/bba/tools/subfinder.py`, replace the `parse_output` method (lines 16-26) with:

```python
    def parse_output(self, output: str) -> list[dict]:
        return self.runner.parse_jsonl(output)
```

Also update `run()` error return (line 33) from:

```python
            return {"total": 0, "domains": [], "sources": {}, "error": result.error}
```

Leave this as-is — subfinder returns domain-specific keys, not the generic `error_result` shape. Only update `parse_output`.

- [ ] **Step 2: Update httpx_runner.py**

In `src/bba/tools/httpx_runner.py`:

Replace `parse_output` (lines 19-29):
```python
    def parse_output(self, output: str) -> list[dict]:
        return self.runner.parse_jsonl(output)
```

Replace `build_command` input file creation (lines 15-16):
```python
    def build_command(self, domains: list[str], work_dir: Path) -> list[str]:
        input_file = self.runner.create_input_file(domains, work_dir, filename="httpx_input.txt")
        return ["httpx", "-l", str(input_file), "-silent", "-json", "-nc"]
```

- [ ] **Step 3: Update nuclei.py**

In `src/bba/tools/nuclei.py`:

Replace `parse_output` (lines 46-56):
```python
    def parse_output(self, output: str) -> list[dict]:
        return self.runner.parse_jsonl(output)
```

Replace input file creation in `build_command` (lines 22-23):
```python
        input_file = self.runner.create_input_file(targets, work_dir, filename="nuclei_targets.txt")
```

Replace domain extraction in `run()` (lines 68-70):
```python
        domains = [self.runner.extract_domain(t) for t in targets]
```

- [ ] **Step 4: Update feroxbuster.py**

In `src/bba/tools/feroxbuster.py`:

Replace `parse_output` (lines 30-42):
```python
    def parse_output(self, output: str) -> list[dict]:
        results = []
        for entry in self.runner.parse_jsonl(output):
            if entry.get("type") == "response" or "url" in entry:
                results.append(entry)
        return results
```

Replace domain extraction in `run()` (line 49):
```python
        domain = self.runner.extract_domain(url)
```

- [ ] **Step 5: Update remaining tools that use parse_jsonl pattern**

Apply the same `parse_output` replacement to each of these files. In each case, replace the inline JSONL parsing loop with `return self.runner.parse_jsonl(output)`:

- `src/bba/tools/katana.py`
- `src/bba/tools/dalfox.py`
- `src/bba/tools/gau.py` (if it has JSONL parsing — gau may output plain text)
- `src/bba/tools/jsluice.py`
- `src/bba/tools/dnsx.py`
- `src/bba/tools/naabu.py`
- `src/bba/tools/arjun.py`
- `src/bba/tools/crlfuzz.py`
- `src/bba/tools/cdncheck.py`
- `src/bba/tools/tlsx.py`
- `src/bba/tools/wafw00f.py`
- `src/bba/tools/asnmap.py`
- `src/bba/tools/shodan_cli.py`

For each file: read it first, check if it has the JSONL parsing pattern, and replace with `self.runner.parse_jsonl(output)`. Some tools (sqlmap, nmap, gau) may parse differently — leave those alone.

Also apply `self.runner.create_input_file()` to tools that write target files, and `self.runner.extract_domain()` to tools that do `urlparse(x).hostname or x`.

- [ ] **Step 6: Run full test suite for regression**

Run: `uv run pytest tests/ --ignore=tests/integration -v`
Expected: All 558+ tests PASS — behavior is identical, only code organization changed

- [ ] **Step 7: Commit**

```bash
git add src/bba/tools/
git commit -m "refactor: replace duplicated JSONL/input/domain patterns with ToolRunner utilities"
```

---

### Task 5: Add transaction batching to Database

**Files:**
- Modify: `src/bba/db.py`
- Test: `tests/test_db_batch.py`

- [ ] **Step 1: Write tests for batch mode**

Create `tests/test_db_batch.py`:

```python
import pytest
from bba.db import Database


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestBatchMode:
    async def test_batch_commits_at_end(self, db):
        async with db.batch():
            await db.add_subdomain("prog", "a.example.com", "subfinder")
            await db.add_subdomain("prog", "b.example.com", "subfinder")
        subs = await db.get_subdomains("prog")
        assert len(subs) == 2

    async def test_non_batch_commits_immediately(self, db):
        await db.add_subdomain("prog", "a.example.com", "subfinder")
        subs = await db.get_subdomains("prog")
        assert len(subs) == 1

    async def test_batch_mode_flag(self, db):
        assert db._batch_mode is False
        async with db.batch():
            assert db._batch_mode is True
        assert db._batch_mode is False

    async def test_batch_with_findings(self, db):
        async with db.batch():
            await db.add_finding("prog", "a.com", "https://a.com/1", "xss", "high", "t", "e1", 0.9)
            await db.add_finding("prog", "b.com", "https://b.com/2", "sqli", "critical", "t", "e2", 0.9)
        findings = await db.get_findings("prog")
        assert len(findings) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_db_batch.py -v`
Expected: FAIL — `db.batch()` doesn't exist, `db._batch_mode` doesn't exist

- [ ] **Step 3: Implement batch mode**

In `src/bba/db.py`, add `from contextlib import asynccontextmanager` to the top imports.

Change `__init__` (line 131-133) to add `_batch_mode`:

```python
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._conn: aiosqlite.Connection | None = None
        self._batch_mode: bool = False
```

Add the `batch()` method right after `close()` (after line 145):

```python
    @asynccontextmanager
    async def batch(self):
        self._batch_mode = True
        try:
            yield
        finally:
            self._batch_mode = False
            await self._conn.commit()
```

Then replace every occurrence of `await self._conn.commit()` in the class (in methods like `add_subdomain`, `add_subdomains_bulk`, `add_service`, `add_finding`, `update_finding_status`, `log_action`, `add_port`, `add_ports_bulk`, `add_url`, `add_urls_bulk`, `add_js_file`, `update_js_file`, `add_secret`, `add_screenshot`) with:

```python
        if not self._batch_mode:
            await self._conn.commit()
```

Do NOT change the `await self._conn.commit()` inside `initialize()` (line 140) — that must always commit.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_db_batch.py -v`
Expected: All 4 PASS

- [ ] **Step 5: Run full test suite**

Run: `uv run pytest tests/ --ignore=tests/integration -v`
Expected: All existing tests still pass — non-batch behavior unchanged

- [ ] **Step 6: Commit**

```bash
git add src/bba/db.py tests/test_db_batch.py
git commit -m "feat: add transaction batching with db.batch() context manager"
```

---

### Task 6: Add validation_reason field and phase_outputs + coverage tables

**Files:**
- Modify: `src/bba/db.py` (schema + methods)
- Modify: `src/bba/scan_state.py` (phase_outputs methods, expanded ALL_PHASES)
- Test: `tests/test_db_new_features.py`

- [ ] **Step 1: Write tests for validation_reason**

Create `tests/test_db_new_features.py`:

```python
import pytest
from bba.db import Database
from bba.scan_state import ScanState, ALL_PHASES


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestValidationReason:
    async def test_update_finding_with_reason(self, db):
        fid = await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "t", "ev", 0.9)
        await db.update_finding_status(fid, "validated", reason="XSS confirmed in Chrome")
        findings = await db.get_findings("prog")
        assert findings[0]["validation_reason"] == "XSS confirmed in Chrome"
        assert findings[0]["status"] == "validated"

    async def test_update_finding_without_reason(self, db):
        fid = await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "t", "ev", 0.9)
        await db.update_finding_status(fid, "false_positive")
        findings = await db.get_findings("prog")
        assert findings[0]["validation_reason"] is None
        assert findings[0]["status"] == "false_positive"


class TestPhaseOutputs:
    async def test_set_and_get_phase_output(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("prog", {})
        await state.set_phase_output(run_id, "recon", "technology_profile", '{"frameworks":["Express.js"]}')
        value = await state.get_phase_output(run_id, "recon", "technology_profile")
        assert value == '{"frameworks":["Express.js"]}'

    async def test_get_missing_phase_output(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("prog", {})
        value = await state.get_phase_output(run_id, "recon", "nonexistent")
        assert value is None

    async def test_upsert_phase_output(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("prog", {})
        await state.set_phase_output(run_id, "recon", "live_count", "10")
        await state.set_phase_output(run_id, "recon", "live_count", "42")
        value = await state.get_phase_output(run_id, "recon", "live_count")
        assert value == "42"

    async def test_get_all_phase_outputs(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("prog", {})
        await state.set_phase_output(run_id, "recon", "key1", "val1")
        await state.set_phase_output(run_id, "recon", "key2", "val2")
        outputs = await state.get_all_phase_outputs(run_id, "recon")
        assert outputs == {"key1": "val1", "key2": "val2"}


class TestCoverage:
    async def test_add_and_get_coverage(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("prog", {})
        await db.add_coverage(run_id, "prog", "https://a.com/api", "scanning", "xss", True)
        await db.add_coverage(run_id, "prog", "https://a.com/login", "scanning", "sqli", False, "no query params")
        summary = await db.get_coverage_summary("prog")
        assert len(summary) > 0

    async def test_coverage_dedup(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("prog", {})
        await db.add_coverage(run_id, "prog", "https://a.com/x", "scanning", "xss", True)
        await db.add_coverage(run_id, "prog", "https://a.com/x", "scanning", "xss", True)
        # Should not raise — INSERT OR IGNORE


class TestExpandedPhases:
    def test_all_phases_includes_analysis_phases(self):
        assert "recon-analysis" in ALL_PHASES
        assert "scan-analysis" in ALL_PHASES
        assert "vuln-analysis" in ALL_PHASES
        assert "validation-analysis" in ALL_PHASES
        assert "diff-notify" in ALL_PHASES
        assert "precheck" in ALL_PHASES
        assert "initialize" in ALL_PHASES

    def test_all_phases_count(self):
        assert len(ALL_PHASES) == 16

    async def test_remaining_phases_with_new_list(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("prog", {})
        await state.update_phase(run_id, "precheck", "completed")
        await state.update_phase(run_id, "initialize", "completed")
        await state.update_phase(run_id, "recon", "completed")
        remaining = await state.get_remaining_phases(run_id)
        assert "precheck" not in remaining
        assert "recon" not in remaining
        assert "recon-analysis" in remaining
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_db_new_features.py -v`
Expected: FAIL — no `validation_reason` column, no `phase_outputs` table, no `coverage` table, `ALL_PHASES` has only 8 entries

- [ ] **Step 3: Add validation_reason to schema and update method**

In `src/bba/db.py`, in the SCHEMA string, add `validation_reason TEXT` to the findings table (after line 42, before the closing `);`):

```sql
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    domain TEXT NOT NULL,
    url TEXT,
    vuln_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    tool TEXT NOT NULL,
    evidence TEXT,
    confidence REAL DEFAULT 0.0,
    status TEXT DEFAULT 'new',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    validated_at TIMESTAMP,
    validation_reason TEXT
);
```

Add migration in `initialize()` method, after line 140 (`await self._conn.commit()`):

```python
        # Migration: add validation_reason if missing
        try:
            await self._conn.execute("ALTER TABLE findings ADD COLUMN validation_reason TEXT")
            await self._conn.commit()
        except Exception:
            pass
```

Update `update_finding_status()` (currently lines 218-223):

```python
    async def update_finding_status(self, finding_id: int, status: str, reason: str | None = None) -> None:
        await self._conn.execute(
            "UPDATE findings SET status = ?, validated_at = CURRENT_TIMESTAMP, validation_reason = ? WHERE id = ?",
            (status, reason, finding_id),
        )
        if not self._batch_mode:
            await self._conn.commit()
```

- [ ] **Step 4: Add phase_outputs table and coverage table to schema**

In `src/bba/db.py`, add to the end of the SCHEMA string (before the closing `"""`):

```sql
CREATE TABLE IF NOT EXISTS phase_outputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    phase TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(run_id, phase, key)
);

CREATE INDEX IF NOT EXISTS idx_phase_outputs_lookup ON phase_outputs(run_id, phase);

CREATE TABLE IF NOT EXISTS coverage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
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

Add coverage methods to the `Database` class (at the end, before the closing of the class):

```python
    # --- Coverage ---

    async def add_coverage(
        self, run_id: int, program: str, url: str, phase: str,
        category: str | None, tested: bool, skip_reason: str | None = None,
    ) -> None:
        await self._conn.execute(
            """INSERT OR IGNORE INTO coverage
               (run_id, program, url, phase, category, tested, skip_reason)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (run_id, program, url, phase, category, tested, skip_reason),
        )
        if not self._batch_mode:
            await self._conn.commit()

    async def get_coverage_summary(self, program: str) -> list[dict]:
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

- [ ] **Step 5: Add phase_outputs methods to ScanState and expand ALL_PHASES**

In `src/bba/scan_state.py`, replace `ALL_PHASES` (lines 39-42):

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

Add phase_outputs methods to the `ScanState` class (at the end):

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

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_db_new_features.py -v`
Expected: All 10 PASS

- [ ] **Step 7: Run full test suite**

Run: `uv run pytest tests/ --ignore=tests/integration -v`
Expected: All pass. Note: `test_scan_state.py::test_resume_skips_completed` will still pass because it uses phase names that exist in the new expanded list.

- [ ] **Step 8: Commit**

```bash
git add src/bba/db.py src/bba/scan_state.py tests/test_db_new_features.py
git commit -m "feat: add validation_reason, phase_outputs table, coverage table, expanded phases"
```

---

### Task 7: Add new CLI commands (phase outputs, coverage, update-finding --reason)

**Files:**
- Modify: `src/bba/cli/db_cmds.py`
- Modify: `src/bba/cli/__init__.py` (re-export new commands)
- Test: `tests/test_cli_new_cmds.py`

- [ ] **Step 1: Write tests for the new CLI commands**

Create `tests/test_cli_new_cmds.py`:

```python
import pytest
from unittest.mock import patch, AsyncMock
import argparse


class TestUpdateFindingWithReason:
    async def test_passes_reason_to_db(self):
        from bba.cli.db_cmds import cmd_db_update_finding
        mock_db = AsyncMock()
        mock_db.update_finding_status = AsyncMock()
        mock_db.close = AsyncMock()
        args = argparse.Namespace(finding_id=1, status="validated", reason="confirmed XSS")
        with patch("bba.cli._get_db", return_value=mock_db):
            await cmd_db_update_finding(args)
        mock_db.update_finding_status.assert_called_once_with(1, "validated", reason="confirmed XSS")

    async def test_reason_defaults_to_none(self):
        from bba.cli.db_cmds import cmd_db_update_finding
        mock_db = AsyncMock()
        mock_db.update_finding_status = AsyncMock()
        mock_db.close = AsyncMock()
        args = argparse.Namespace(finding_id=1, status="false_positive", reason=None)
        with patch("bba.cli._get_db", return_value=mock_db):
            await cmd_db_update_finding(args)
        mock_db.update_finding_status.assert_called_once_with(1, "false_positive", reason=None)


class TestParserRegistration:
    def test_update_finding_has_reason_flag(self):
        from bba.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["db", "update-finding", "1", "--status", "validated", "--reason", "test reason"])
        assert args.reason == "test reason"

    def test_update_finding_reason_defaults_none(self):
        from bba.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["db", "update-finding", "1", "--status", "validated"])
        assert args.reason is None

    def test_set_phase_output_parser(self):
        from bba.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["db", "set-phase-output", "--program", "prog", "--phase", "recon", "--key", "tech", "--value", '{"a":1}'])
        assert args.phase == "recon"
        assert args.key == "tech"

    def test_get_phase_output_parser(self):
        from bba.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["db", "get-phase-output", "--program", "prog", "--phase", "recon", "--key", "tech"])
        assert args.key == "tech"

    def test_coverage_parser(self):
        from bba.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["db", "coverage", "--program", "prog"])
        assert args.program == "prog"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cli_new_cmds.py -v`
Expected: FAIL — no `--reason` flag, no `set-phase-output` command, etc.

- [ ] **Step 3: Update cmd_db_update_finding to pass reason**

In `src/bba/cli/db_cmds.py`, update `cmd_db_update_finding` (lines 71-77):

```python
async def cmd_db_update_finding(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
    try:
        await db.update_finding_status(args.finding_id, args.status, reason=getattr(args, "reason", None))
        _bba_cli._output({"id": args.finding_id, "status": args.status, "updated": True})
    finally:
        await db.close()
```

- [ ] **Step 4: Add new command handlers**

Add these functions to `src/bba/cli/db_cmds.py`, before `register_db_commands`:

```python
async def cmd_db_set_phase_output(args: argparse.Namespace) -> None:
    from bba.scan_state import ScanState
    db = await _bba_cli._get_db()
    try:
        state = ScanState(db)
        await state.initialize()
        latest = await state.get_latest_run(args.program)
        if not latest:
            _bba_cli._output({"error": "No scan runs found for program"})
            return
        await state.set_phase_output(latest["id"], args.phase, args.key, args.value)
        _bba_cli._output({"run_id": latest["id"], "phase": args.phase, "key": args.key, "stored": True})
    finally:
        await db.close()


async def cmd_db_get_phase_output(args: argparse.Namespace) -> None:
    from bba.scan_state import ScanState
    db = await _bba_cli._get_db()
    try:
        state = ScanState(db)
        await state.initialize()
        latest = await state.get_latest_run(args.program)
        if not latest:
            _bba_cli._output({"error": "No scan runs found for program"})
            return
        value = await state.get_phase_output(latest["id"], args.phase, args.key)
        _bba_cli._output({"phase": args.phase, "key": args.key, "value": value})
    finally:
        await db.close()


async def cmd_db_coverage(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
    try:
        summary = await db.get_coverage_summary(args.program)
        _bba_cli._output(summary)
    finally:
        await db.close()


async def cmd_db_add_coverage(args: argparse.Namespace) -> None:
    from bba.scan_state import ScanState
    db = await _bba_cli._get_db()
    try:
        state = ScanState(db)
        await state.initialize()
        latest = await state.get_latest_run(args.program)
        if not latest:
            _bba_cli._output({"error": "No scan runs found for program"})
            return
        tested = args.tested.lower() in ("true", "1", "yes")
        await db.add_coverage(latest["id"], args.program, args.url, args.phase, args.category, tested, args.skip_reason)
        _bba_cli._output({"stored": True})
    finally:
        await db.close()
```

- [ ] **Step 5: Register new commands in parser**

In `src/bba/cli/db_cmds.py`, in `register_db_commands()`, add `--reason` to update-finding (after line 211):

```python
    db_upd.add_argument("--reason", default=None, help="Reason for status change")
```

Add new subcommands at the end of `register_db_commands()`:

```python
    db_spo = db_sub.add_parser("set-phase-output", help="Store structured phase output")
    db_spo.add_argument("--program", required=True, help="Program name")
    db_spo.add_argument("--phase", required=True, help="Phase name")
    db_spo.add_argument("--key", required=True, help="Output key")
    db_spo.add_argument("--value", required=True, help="Output value (JSON string)")
    db_spo.set_defaults(func=cmd_db_set_phase_output)

    db_gpo = db_sub.add_parser("get-phase-output", help="Retrieve structured phase output")
    db_gpo.add_argument("--program", required=True, help="Program name")
    db_gpo.add_argument("--phase", required=True, help="Phase name")
    db_gpo.add_argument("--key", required=True, help="Output key")
    db_gpo.set_defaults(func=cmd_db_get_phase_output)

    db_cov = db_sub.add_parser("coverage", help="Show coverage summary")
    db_cov.add_argument("--program", required=True, help="Program name")
    db_cov.set_defaults(func=cmd_db_coverage)

    db_acov = db_sub.add_parser("add-coverage", help="Add coverage entry")
    db_acov.add_argument("--program", required=True, help="Program name")
    db_acov.add_argument("--url", required=True, help="URL tested")
    db_acov.add_argument("--phase", required=True, help="Phase name")
    db_acov.add_argument("--category", default=None, help="Test category (e.g., xss, sqli)")
    db_acov.add_argument("--tested", required=True, help="Whether URL was tested (true/false)")
    db_acov.add_argument("--skip-reason", default=None, help="Reason for skipping")
    db_acov.set_defaults(func=cmd_db_add_coverage)
```

- [ ] **Step 6: Update cli/__init__.py re-exports**

In `src/bba/cli/__init__.py`, add the new imports to the `db_cmds` import block (around line 194-209):

```python
from bba.cli.db_cmds import (  # noqa: E402
    cmd_db_subdomains,
    cmd_db_services,
    cmd_db_findings,
    cmd_db_summary,
    cmd_db_add_finding,
    cmd_db_update_finding,
    cmd_db_ports,
    cmd_db_urls,
    cmd_db_js_files,
    cmd_db_secrets,
    cmd_db_screenshots,
    cmd_db_scan_history,
    cmd_db_scan_status,
    cmd_db_scan_diff,
    cmd_db_set_phase_output,
    cmd_db_get_phase_output,
    cmd_db_coverage,
    cmd_db_add_coverage,
)
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli_new_cmds.py -v`
Expected: All 7 PASS

- [ ] **Step 8: Run full test suite**

Run: `uv run pytest tests/ --ignore=tests/integration -v`
Expected: All pass

- [ ] **Step 9: Commit**

```bash
git add src/bba/cli/db_cmds.py src/bba/cli/__init__.py tests/test_cli_new_cmds.py
git commit -m "feat: add CLI commands for phase outputs, coverage, update-finding --reason"
```

---

### Task 8: Scope validation hardening — IDN, CIDR, API keys

**Files:**
- Modify: `src/bba/scope.py`
- Modify: `src/bba/scope_importer.py`
- Create: `src/bba/config.py`
- Test: `tests/test_scope_hardening.py`

- [ ] **Step 1: Write tests**

Create `tests/test_scope_hardening.py`:

```python
import ipaddress
import os
import pytest
from bba.scope import ScopeConfig, ScopeValidator, _normalize_domain
from bba.scope_importer import ScopeImporter
from bba.config import resolve_api_key


class TestIDNNormalization:
    def test_normalize_ascii_domain(self):
        assert _normalize_domain("Example.COM.") == "example.com"

    def test_normalize_punycode(self):
        result = _normalize_domain("xn--nxasmq6b.example.com")
        assert result == "xn--nxasmq6b.example.com"

    def test_idn_scope_matching(self):
        config = ScopeConfig.from_dict({
            "program": "test",
            "in_scope": {"domains": ["*.example.com"]},
        })
        validator = ScopeValidator(config)
        assert validator.is_domain_in_scope("shop.example.com") is True
        assert validator.is_domain_in_scope("SHOP.EXAMPLE.COM") is True
        assert validator.is_domain_in_scope("shop.example.com.") is True


class TestCIDRValidation:
    def test_valid_cidr_accepted(self):
        importer = ScopeImporter()
        assert importer._is_cidr("10.0.0.0/24") is True

    def test_invalid_cidr_rejected(self):
        importer = ScopeImporter()
        assert importer._is_cidr("999.999.999.999/32") is False

    def test_invalid_octet_rejected(self):
        importer = ScopeImporter()
        assert importer._is_cidr("256.0.0.0/24") is False

    def test_not_cidr_string(self):
        importer = ScopeImporter()
        assert importer._is_cidr("example.com") is False

    def test_ipv6_cidr_accepted(self):
        importer = ScopeImporter()
        assert importer._is_cidr("2001:db8::/32") is True


class TestAPIKeyConfig:
    def test_resolve_env_var(self):
        os.environ["TEST_BBA_KEY"] = "secret123"
        try:
            assert resolve_api_key("${TEST_BBA_KEY}") == "secret123"
        finally:
            del os.environ["TEST_BBA_KEY"]

    def test_resolve_missing_env_var(self):
        assert resolve_api_key("${NONEXISTENT_BBA_KEY_XYZ}") is None

    def test_resolve_literal_value(self):
        assert resolve_api_key("literal-key-value") == "literal-key-value"

    def test_resolve_empty_string(self):
        assert resolve_api_key("") is None

    def test_scope_config_with_api_keys(self):
        os.environ["TEST_SHODAN_KEY"] = "shodan123"
        try:
            config = ScopeConfig.from_dict({
                "program": "test",
                "in_scope": {"domains": ["*.example.com"]},
                "api_keys": {"shodan": "${TEST_SHODAN_KEY}", "custom": "inline-value"},
            })
            assert config.api_keys["shodan"] == "shodan123"
            assert config.api_keys["custom"] == "inline-value"
        finally:
            del os.environ["TEST_SHODAN_KEY"]

    def test_scope_config_without_api_keys(self):
        config = ScopeConfig.from_dict({
            "program": "test",
            "in_scope": {"domains": ["*.example.com"]},
        })
        assert config.api_keys == {}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_scope_hardening.py -v`
Expected: FAIL — `_normalize_domain` not exported, `_is_cidr` doesn't reject invalid octets, `config.py` doesn't exist, `ScopeConfig` has no `api_keys`

- [ ] **Step 3: Create config.py**

Create `src/bba/config.py`:

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

- [ ] **Step 4: Add IDN normalization to scope.py**

In `src/bba/scope.py`, add `_normalize_domain` function before `_domain_matches` (before line 44):

```python
def _normalize_domain(domain: str) -> str:
    domain = domain.lower().rstrip(".")
    try:
        domain = domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        pass
    return domain
```

Update `_domain_matches` (lines 44-55) to use it:

```python
def _domain_matches(pattern: str, domain: str) -> bool:
    domain = _normalize_domain(domain)
    pattern = _normalize_domain(pattern)

    if pattern == domain:
        return True

    if pattern.startswith("*."):
        suffix = pattern[1:]
        return domain.endswith(suffix) and domain != suffix.lstrip(".")

    return False
```

Update `is_domain_in_scope` (line 67) to normalize:

```python
    def is_domain_in_scope(self, domain: str) -> bool:
        domain = _normalize_domain(domain)
```

(Remove the existing `domain = domain.lower().rstrip(".")` on the next line, since `_normalize_domain` already does this.)

- [ ] **Step 5: Add api_keys to ScopeConfig**

In `src/bba/scope.py`, add import at top:

```python
from bba.config import resolve_api_key
```

Add `api_keys` field to the `ScopeConfig` dataclass (after line 19):

```python
    api_keys: dict[str, str | None] = field(default_factory=dict)
```

Update `from_dict` (around line 29-36) to parse api_keys:

```python
    @classmethod
    def from_dict(cls, data: dict) -> ScopeConfig:
        if "program" not in data:
            raise ValueError("Scope config must include 'program'")
        in_scope = data.get("in_scope")
        if not in_scope or not in_scope.get("domains"):
            raise ValueError("Scope config must include 'in_scope' with at least one domain")
        out_scope = data.get("out_of_scope", {})
        raw_keys = data.get("api_keys", {})
        resolved_keys = {k: resolve_api_key(v) for k, v in raw_keys.items()}
        return cls(
            program=data["program"],
            platform=data.get("platform", ""),
            in_scope_domains=in_scope.get("domains", []),
            in_scope_cidrs=in_scope.get("cidrs", []),
            out_of_scope_domains=out_scope.get("domains", []),
            out_of_scope_paths=out_scope.get("paths", []),
            api_keys=resolved_keys,
        )
```

- [ ] **Step 6: Fix CIDR validation in scope_importer.py**

In `src/bba/scope_importer.py`, add `import ipaddress` to the imports (line 2 area).

Replace `_is_cidr` (lines 21-22):

```python
    def _is_cidr(self, asset: str) -> bool:
        try:
            ipaddress.ip_network(asset, strict=False)
            return True
        except ValueError:
            return False
```

Remove the `import re` at line 3 if it's no longer used elsewhere in the file. Check first — `re` may be used by other code. If the only use was the regex in `_is_cidr`, remove it.

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/test_scope_hardening.py -v`
Expected: All 13 PASS

- [ ] **Step 8: Run full test suite**

Run: `uv run pytest tests/ --ignore=tests/integration -v`
Expected: All pass

- [ ] **Step 9: Commit**

```bash
git add src/bba/config.py src/bba/scope.py src/bba/scope_importer.py tests/test_scope_hardening.py
git commit -m "feat: IDN/Punycode normalization, CIDR validation, API key configuration"
```

---

### Task 9: Update agent prompts — structured handoffs, deep-dive clarity, validator reasons, reporter coverage

**Files:**
- Modify: `.claude/agents/recon.md`
- Modify: `.claude/agents/scanner.md`
- Modify: `.claude/agents/vuln-tester.md`
- Modify: `.claude/agents/deep-dive.md`
- Modify: `.claude/agents/validator.md`
- Modify: `.claude/agents/reporter.md`
- Modify: `.claude/commands/scan-target.md`

This task is prompt-only — no Python code, no tests. Read each file, apply the specified additions from the design spec, and commit.

- [ ] **Step 1: Update recon.md — add structured output storage**

Read `.claude/agents/recon.md`. Append the following section before the final output format section:

```markdown
## Structured Output Storage

Before finishing, store structured data for downstream agents:

```bash
uv run bba db set-phase-output --program $PROGRAM --phase recon --key technology_profile --value '{"frameworks":[],"languages":[],"waf":null,"cms":null}'
uv run bba db set-phase-output --program $PROGRAM --phase recon --key waf_detected --value '{"detected":false,"name":null,"confidence":0}'
uv run bba db set-phase-output --program $PROGRAM --phase recon --key high_value_targets --value '["target1.example.com"]'
uv run bba db set-phase-output --program $PROGRAM --phase recon --key live_count --value '42'
```

Fill in actual values from your analysis. Use valid JSON strings for all values.
```

- [ ] **Step 2: Update scanner.md — read phase outputs instead of prose**

Read `.claude/agents/scanner.md`. Add at the beginning of the process section:

```markdown
## Intelligence Gathering

Before scanning, query structured intelligence from prior phases:

```bash
uv run bba db get-phase-output --program $PROGRAM --phase recon --key technology_profile
uv run bba db get-phase-output --program $PROGRAM --phase recon --key waf_detected
uv run bba db get-phase-output --program $PROGRAM --phase recon --key high_value_targets
```

Use these outputs to inform your scan strategy. Do NOT rely solely on the coordinator's prose description.

Before finishing, store your own structured outputs:

```bash
uv run bba db set-phase-output --program $PROGRAM --phase scanning --key url_classifications --value '{"xss":0,"sqli":0,"ssrf":0,"redirect":0}'
uv run bba db set-phase-output --program $PROGRAM --phase scanning --key discovered_endpoints --value '[]'
```
```

- [ ] **Step 3: Update vuln-tester.md — read scanner outputs**

Read `.claude/agents/vuln-tester.md`. Add at the beginning of the process section:

```markdown
## Load Attack Surface

Before testing, load the latest attack surface from the database:

```bash
uv run bba db urls --program $PROGRAM
uv run bba db findings --program $PROGRAM --status new
uv run bba db get-phase-output --program $PROGRAM --phase scanning --key url_classifications
```

These include endpoints discovered by the scanner agent. Use the URL classifications to prioritize which categories to test.
```

- [ ] **Step 4: Update deep-dive.md — explicit tool field**

Read `.claude/agents/deep-dive.md`. Find the section about storing findings and ensure it says:

```markdown
When storing confirmed findings, always use `tool="manual-deep-dive"`:

```bash
uv run bba db add-finding --program $PROGRAM --domain <domain> --url <url> --vuln-type <type> --severity-level <severity> --tool manual-deep-dive --evidence "<detailed evidence>" --confidence <0.0-1.0>
```
```

- [ ] **Step 5: Update validator.md — origin tracking and validation_reason**

Read `.claude/agents/validator.md`. Add to the validation process section:

```markdown
## Origin-Aware Validation

When validating, note the finding source via the `tool` field:
- **Automated tools** (nuclei, dalfox, sqlmap) — higher false-positive rate, test thoroughly
- **Deep-dive** (manual-deep-dive) — already manually investigated, verify the PoC reproduces

Include `--reason` with EVERY status update:

```bash
uv run bba db update-finding <id> --status validated --reason "XSS fires in Chrome, reflected in unquoted attribute"
uv run bba db update-finding <id> --status false_positive --reason "Response is static 403 page, not actual injection"
uv run bba db update-finding <id> --status needs_review --reason "Intermittent — reproduced once but not consistently"
```

Never update a finding status without providing a reason.
```

- [ ] **Step 6: Update reporter.md — coverage and FP stats**

Read `.claude/agents/reporter.md`. Add to the report generation section:

```markdown
## Coverage Section

Query and include coverage data:

```bash
uv run bba db coverage --program $PROGRAM
```

Show: total endpoints discovered, tested count, skipped count, skip reasons breakdown.

## Validation Statistics Section

Include:
- Total findings before validation: [count from `uv run bba db findings --program $PROGRAM`]
- Validated: [count with status=validated]
- False positives: [count with status=false_positive] — break down by validation_reason if possible
- Needs review: [count with status=needs_review]
- False positive rate: [percentage]
```

- [ ] **Step 7: Update scan-target.md — expanded phases and deep-dive clarity**

Read `.claude/commands/scan-target.md`. Make these changes:

1. Update the Phase 9 (Deep Dives) section to be explicit:

```markdown
## PHASE 9: DEEP DIVES

For each deep-dive candidate identified in Phase 8c:
1. Spawn a deep-dive agent (can be parallel for independent targets)
2. Each deep-dive agent stores findings via `uv run bba db add-finding` with tool="manual-deep-dive"
3. WAIT for ALL deep-dive agents to complete before proceeding
4. Verify results: `uv run bba db findings --program $ARGUMENTS.program --status new`
5. Only then proceed to Phase 10 (Validation)

IMPORTANT: Do NOT proceed to validation until all deep-dive agents have finished. Check that the finding count in the DB reflects expected results from all deep-dive agents.
```

2. Add phase tracking instructions to coordinator reasoning blocks. After each COORDINATOR REASONING block, add:

```bash
uv run bba db update-phase <run_id> --phase <current-phase> --status completed
```

For skipped conditional phases:

```bash
uv run bba db update-phase <run_id> --phase infrastructure --status skipped --reason "no non-standard ports found"
```

- [ ] **Step 8: Commit**

```bash
git add .claude/agents/ .claude/commands/
git commit -m "feat: update agent prompts with structured handoffs, validation reasons, coverage"
```

---

### Task 10: Update README with full tools list and new commands

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Read current README**

Read `README.md` to understand the current state.

- [ ] **Step 2: Replace Tool Categories section**

Find the `## Tool Categories` section in `README.md`. Replace the summary table with the full tool listing from the design spec Section 6a. Organize into 14 category tables, each with Tool, Description, and Command columns.

The full content is specified in the design spec. Use the exact tables from the brainstorming conversation (Section 6 of the design presentation). Include all 56 tools across all 14 categories.

- [ ] **Step 3: Add new CLI commands to Database section**

In the `## Database` section, add the new commands:

```bash
# Phase outputs (for agent coordination)
uv run bba db set-phase-output --program example --phase recon --key technology_profile --value '{"frameworks":["Express.js"]}'
uv run bba db get-phase-output --program example --phase recon --key technology_profile

# Coverage tracking
uv run bba db coverage --program example
uv run bba db add-coverage --program example --url https://example.com/api --phase scanning --category xss --tested true

# Update finding with reason
uv run bba db update-finding 1 --status validated --reason "XSS confirmed in Chrome"
```

- [ ] **Step 4: Add API Keys section to prerequisites**

In the Prerequisites section, ensure the API Keys subsection is present:

```markdown
### API Keys (for enhanced recon)

Set these in your environment for tools that use external APIs:

```bash
export SHODAN_API_KEY="..."
export CENSYS_API_ID="..."
export CENSYS_API_SECRET="..."
export GITHUB_TOKEN="..."
```

Or add them to your scope YAML:

```yaml
api_keys:
  shodan: "${SHODAN_API_KEY}"
  censys_id: "${CENSYS_API_ID}"
```
```

- [ ] **Step 5: Update CLAUDE.md with new CLI commands**

In `CLAUDE.md`, add the new CLI commands to the BBA CLI reference section:

```bash
# Phase output storage (agent coordination)
uv run bba db set-phase-output --program <prog> --phase <phase> --key <key> --value <json>
uv run bba db get-phase-output --program <prog> --phase <phase> --key <key>

# Coverage tracking
uv run bba db coverage --program <prog>
uv run bba db add-coverage --program <prog> --url <url> --phase <phase> --category <cat> --tested <bool> [--skip-reason <text>]

# Updated: update-finding now accepts --reason
uv run bba db update-finding <id> --status <status> [--reason <text>]
```

- [ ] **Step 6: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: expand README with full tool reference, new CLI commands, API key config"
```

---

### Task 11: Final verification

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest tests/ --ignore=tests/integration -v`
Expected: All tests pass

- [ ] **Step 2: Verify CLI works end-to-end**

```bash
uv run bba --help
uv run bba db --help
```

Verify new commands show up: `set-phase-output`, `get-phase-output`, `coverage`, `add-coverage`.

Verify `update-finding` shows `--reason` flag.

- [ ] **Step 3: Verify no hardcoded paths remain**

Run: `grep -r "/home/sumo" src/`
Expected: No matches

- [ ] **Step 4: Commit summary (if any fixups needed)**

If any fixes were needed during verification:
```bash
git add -A
git commit -m "fix: address issues found during final verification"
```
