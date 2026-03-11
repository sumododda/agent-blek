# Phase 5A: Critical Fixes & Infrastructure Hardening

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden core infrastructure (tool_runner, db, rate_limiter), add interactsh OOB detection, and add finding deduplication — the highest-ROI improvements identified in the audit.

**Architecture:** Add interactsh as a new tool wrapper + integrate into nuclei. Harden tool_runner with process cleanup and timestamp collision fix. Add DB transaction batching and finding deduplication via UNIQUE constraint + evidence merging. Add adaptive rate limiting that reduces on 429/503.

**Note:** The qsreplace shell injection fix has been moved to Phase 5B as a complete native Python rewrite (eliminating the stale external dependency entirely).

**Tech Stack:** Python 3.13+, aiosqlite, asyncio, existing bba modules

---

## File Structure

```
src/bba/
    tool_runner.py       # MODIFY — process cleanup, retry, concurrency limit, timestamp fix
    db.py                # MODIFY — transaction batching, finding dedup, correlation queries, export
    rate_limiter.py      # MODIFY — adaptive rate limiting, global limit, lower default
    sanitizer.py         # MODIFY — ANSI stripping, command arg sanitization
    scope.py             # MODIFY — CIDR out-of-scope, validation caching

src/bba/tools/
    nuclei.py            # MODIFY — add --interactsh-url, --interactsh-server support
    interactsh.py        # CREATE — interactsh client wrapper for OOB detection
    nomore403.py         # CREATE — 403 bypass automation

tests/
    test_tool_runner.py  # CREATE — tests for retry, timeout cleanup, concurrency
    test_db_hardened.py  # CREATE — tests for dedup, batching, export
    test_rate_limiter.py # CREATE — tests for adaptive, global limit
    test_tools_interactsh.py # CREATE
    test_tools_nomore403.py  # CREATE
```

---

## Chunk 1: Tool Runner Hardening

### Task 1: Tool Runner — Process Cleanup on Timeout

When `asyncio.wait_for` raises `TimeoutError`, the child process is NOT killed — creating zombie processes.

**Files:**
- Modify: `src/bba/tool_runner.py`
- Create: `tests/test_tool_runner.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_tool_runner.py
import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from bba.tool_runner import ToolRunner, ToolResult
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {"program": "test", "in_scope": {"domains": ["*.example.com"], "cidrs": []}, "out_of_scope": {}}

@pytest.fixture
def runner(tmp_path):
    scope = ScopeValidator(ScopeConfig.from_dict(SCOPE))
    return ToolRunner(
        scope=scope,
        rate_limiter=MultiTargetRateLimiter(),
        sanitizer=Sanitizer(),
        output_dir=tmp_path / "output",
    )

class TestToolRunnerTimeout:
    @pytest.mark.asyncio
    async def test_timeout_kills_process(self, runner):
        """On timeout, the child process must be killed."""
        result = await runner.run_command(
            tool="test",
            command=["sleep", "60"],
            targets=["example.com"],
            timeout=1,
        )
        assert not result.success
        assert "timed out" in result.error.lower()

class TestToolRunnerTimestamp:
    @pytest.mark.asyncio
    async def test_no_timestamp_collision(self, runner):
        """Two runs in same second must not overwrite each other's output."""
        result1 = await runner.run_command(
            tool="test", command=["echo", "first"], targets=["example.com"], timeout=5,
        )
        result2 = await runner.run_command(
            tool="test", command=["echo", "second"], targets=["example.com"], timeout=5,
        )
        assert result1.raw_file != result2.raw_file
```

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Fix tool_runner.py**

In `run_command`, add process kill on timeout and use monotonic nanoseconds for filenames:

```python
async def run_command(self, tool, command, targets, timeout=600):
    self.validate_targets(targets)
    for target in targets:
        await self.rate_limiter.wait(target)

    tool_dir = self._ensure_output_dir(tool)
    # Use monotonic_ns to avoid timestamp collisions
    raw_file = tool_dir / f"{time.monotonic_ns()}.txt"

    start = time.monotonic()
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        duration = time.monotonic() - start

        raw_output = stdout.decode(errors="replace")
        raw_file.write_text(raw_output)
        sanitized = self.sanitizer.sanitize(raw_output)

        if proc.returncode == 0:
            return ToolResult(success=True, output=sanitized, raw_file=raw_file, duration=duration)
        else:
            return ToolResult(success=False, output=sanitized, raw_file=raw_file,
                              error=stderr.decode(errors="replace"), duration=duration)

    except asyncio.TimeoutError:
        # Kill the child process to prevent zombies
        if proc and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
        return ToolResult(success=False, output="",
                          error=f"Command timed out after {timeout}s",
                          duration=time.monotonic() - start)
```

- [ ] **Step 4: Run tests**
- [ ] **Step 5: Commit**

```bash
git add src/bba/tool_runner.py tests/test_tool_runner.py
git commit -m "fix: kill child process on timeout, prevent timestamp collisions"
```

---

### Task 3: Database — Finding Deduplication + Transaction Batching

**Files:**
- Modify: `src/bba/db.py`
- Create: `tests/test_db_hardened.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_db_hardened.py
import pytest
from bba.db import Database

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()

class TestFindingDedup:
    @pytest.mark.asyncio
    async def test_duplicate_finding_merges_evidence(self, db):
        """Same program+url+vuln_type should merge evidence, not create duplicate."""
        id1 = await db.add_finding("prog", "example.com", "https://example.com/vuln",
                                    "xss", "high", "dalfox", "payload1", 0.8)
        id2 = await db.add_finding("prog", "example.com", "https://example.com/vuln",
                                    "xss", "high", "xsstrike", "payload2", 0.85)
        findings = await db.get_findings("prog")
        # Should be 1 finding with merged evidence, not 2
        assert len(findings) == 1
        assert "payload1" in findings[0]["evidence"]
        assert "payload2" in findings[0]["evidence"]
        # Confidence should be the higher value
        assert findings[0]["confidence"] == 0.85

class TestBulkTransaction:
    @pytest.mark.asyncio
    async def test_bulk_urls_uses_transaction(self, db):
        """Bulk insert should use a single transaction, not N commits."""
        urls = [f"https://example.com/{i}" for i in range(1000)]
        count = await db.add_urls_bulk("prog", urls, "test")
        assert count == 1000
        result = await db.get_urls("prog")
        assert len(result) == 1000

class TestExport:
    @pytest.mark.asyncio
    async def test_export_findings_json(self, db):
        await db.add_finding("prog", "example.com", "https://example.com/x",
                              "xss", "high", "dalfox", "evidence", 0.9)
        data = await db.export_findings("prog", fmt="json")
        assert isinstance(data, str)
        import json
        parsed = json.loads(data)
        assert len(parsed) == 1

class TestFindingStats:
    @pytest.mark.asyncio
    async def test_severity_distribution(self, db):
        await db.add_finding("prog", "a.com", "https://a.com/1", "xss", "high", "t", "e", 0.9)
        await db.add_finding("prog", "b.com", "https://b.com/2", "sqli", "critical", "t", "e", 0.9)
        stats = await db.get_finding_stats("prog")
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_tool"]["t"] == 2
```

- [ ] **Step 2: Run to verify failures**

- [ ] **Step 3: Implement dedup, batching, export, stats**

Modify `src/bba/db.py`:

1. **Finding dedup**: Change `add_finding` to use `INSERT ... ON CONFLICT(program, url, vuln_type) DO UPDATE SET evidence = evidence || '; ' || excluded.evidence, confidence = MAX(confidence, excluded.confidence), tool = tool || ',' || excluded.tool`. Add UNIQUE index on `(program, url, vuln_type)`.

2. **Transaction batching**: Wrap bulk methods in `async with self._conn.execute("BEGIN")` ... `commit()` instead of commit-per-row.

3. **Export**: Add `export_findings(program, fmt="json"|"csv")` method.

4. **Stats**: Add `get_finding_stats(program)` returning `{by_severity: {}, by_tool: {}, total: N}`.

Schema migration — add to SCHEMA string:
```sql
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup ON findings(program, url, vuln_type);
```

- [ ] **Step 4: Run tests**
- [ ] **Step 5: Commit**

```bash
git add src/bba/db.py tests/test_db_hardened.py
git commit -m "feat: finding dedup, transaction batching, export, stats"
```

---

### Task 4: Adaptive Rate Limiting

**Files:**
- Modify: `src/bba/rate_limiter.py`
- Create: `tests/test_rate_limiter.py`

- [ ] **Step 1: Write tests**

```python
# tests/test_rate_limiter.py
import pytest
import asyncio
from bba.rate_limiter import RateLimiter, MultiTargetRateLimiter

class TestRateLimiter:
    def test_default_rps_is_reasonable(self):
        limiter = MultiTargetRateLimiter()
        assert limiter.default_rps <= 20  # Not 50

class TestAdaptiveRateLimiter:
    def test_backoff_reduces_rate(self):
        limiter = MultiTargetRateLimiter(default_rps=20)
        limiter.report_status("example.com", 429)
        rl = limiter._get_limiter("example.com")
        assert rl.max_rps < 20

    def test_success_restores_rate(self):
        limiter = MultiTargetRateLimiter(default_rps=20)
        limiter.report_status("example.com", 429)
        for _ in range(10):
            limiter.report_status("example.com", 200)
        rl = limiter._get_limiter("example.com")
        assert rl.max_rps >= 15  # Gradually restored

class TestGlobalRateLimit:
    @pytest.mark.asyncio
    async def test_global_limit_caps_total(self):
        limiter = MultiTargetRateLimiter(default_rps=20, global_rps=50)
        assert limiter.global_rps == 50
```

- [ ] **Step 2: Implement**

Modify `rate_limiter.py`:
- Lower default_rps from 50 to 20
- Add `report_status(target, http_status)` — on 429/503, halve the target's RPS (min 2)
- Add `global_rps` parameter and a global RateLimiter that's checked in addition to per-target
- On success (200), gradually restore rate (+1 RPS per 10 successes, up to original)

- [ ] **Step 3: Run tests, commit**

```bash
git add src/bba/rate_limiter.py tests/test_rate_limiter.py
git commit -m "feat: adaptive rate limiting with backoff on 429, lower default to 20 RPS"
```

---

## Chunk 2: Interactsh + nomore403

### Task 5: Interactsh OOB Detection Wrapper

`interactsh-client` is a Go binary from ProjectDiscovery. It generates unique callback URLs and polls for interactions (DNS, HTTP, SMTP). Critical for blind SSRF, blind XSS, blind SQLi detection.

**Files:**
- Create: `src/bba/tools/interactsh.py`
- Create: `tests/test_tools_interactsh.py`

- [ ] **Step 1: Write tests**

```python
# tests/test_tools_interactsh.py
import pytest
from unittest.mock import patch
from bba.tools.interactsh import InteractshTool
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {"program": "test", "in_scope": {"domains": ["*.example.com"], "cidrs": []}, "out_of_scope": {}}

@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))

@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(), sanitizer=Sanitizer(), output_dir=tmp_path / "output")

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()

class TestInteractshTool:
    def test_build_generate_command(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        cmd = tool.build_generate_command(count=5)
        assert "interactsh-client" in cmd[0]
        assert "-n" in cmd
        assert "5" in cmd

    def test_build_poll_command(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        cmd = tool.build_poll_command(session_file="/tmp/session.yaml")
        assert "-sf" in cmd

    def test_parse_interactions(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        output = '{"protocol":"dns","unique-id":"abc123","full-id":"abc123.interact.sh","remote-address":"1.2.3.4","timestamp":"2026-01-01T00:00:00Z"}\n'
        result = tool.parse_interactions(output)
        assert len(result) == 1
        assert result[0]["protocol"] == "dns"
        assert result[0]["unique-id"] == "abc123"

    def test_parse_empty(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        assert tool.parse_interactions("") == []

    @pytest.mark.asyncio
    async def test_generate_urls(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        mock_result = ToolResult(
            success=True,
            output="abc123.oast.live\ndef456.oast.live\n",
            raw_file=None, error=None, duration=1.0,
        )
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.generate_urls(count=2)
        assert result["total"] == 2
        assert "abc123.oast.live" in result["urls"]
```

- [ ] **Step 2: Implement**

```python
# src/bba/tools/interactsh.py
"""Out-of-band interaction detection via interactsh-client."""
from __future__ import annotations
import json
from bba.db import Database
from bba.tool_runner import ToolRunner


class InteractshTool:
    """Generate OOB callback URLs and poll for interactions."""

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_generate_command(self, count: int = 10, server: str | None = None) -> list[str]:
        cmd = ["interactsh-client", "-n", str(count), "-json", "-v"]
        if server:
            cmd.extend(["-server", server])
        return cmd

    def build_poll_command(self, session_file: str) -> list[str]:
        return ["interactsh-client", "-sf", session_file, "-json", "-poll"]

    def parse_interactions(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                if "protocol" in entry or "unique-id" in entry:
                    results.append(entry)
            except json.JSONDecodeError:
                # interactsh also outputs plain URLs during generation
                continue
        return results

    def parse_generated_urls(self, output: str) -> list[str]:
        urls = []
        for line in output.strip().splitlines():
            line = line.strip()
            if line and "." in line and not line.startswith("{"):
                urls.append(line)
        return urls

    async def generate_urls(self, count: int = 10, server: str | None = None) -> dict:
        result = await self.runner.run_command(
            tool="interactsh", command=self.build_generate_command(count, server),
            targets=["interactsh"], timeout=30,
        )
        if not result.success:
            return {"total": 0, "urls": [], "error": result.error}
        urls = self.parse_generated_urls(result.output)
        return {"total": len(urls), "urls": urls, "session_file": str(result.raw_file)}

    async def poll_interactions(self, session_file: str, domain: str) -> dict:
        result = await self.runner.run_command(
            tool="interactsh", command=self.build_poll_command(session_file),
            targets=["interactsh"], timeout=30,
        )
        if not result.success:
            return {"total": 0, "interactions": [], "error": result.error}
        interactions = self.parse_interactions(result.output)
        for interaction in interactions:
            protocol = interaction.get("protocol", "unknown")
            unique_id = interaction.get("unique-id", "")
            remote = interaction.get("remote-address", "")
            await self.db.add_finding(
                program=self.program, domain=domain,
                url=f"oob://{unique_id}",
                vuln_type=f"oob-{protocol}-interaction",
                severity="high", tool="interactsh",
                evidence=f"Protocol: {protocol}, Remote: {remote}, ID: {unique_id}",
                confidence=0.7,
            )
        return {"total": len(interactions), "interactions": interactions}
```

- [ ] **Step 3: Run tests, commit**

```bash
git add src/bba/tools/interactsh.py tests/test_tools_interactsh.py
git commit -m "feat: add interactsh OOB detection tool wrapper"
```

---

### Task 6: Enhance Nuclei with Interactsh Integration

**Files:**
- Modify: `src/bba/tools/nuclei.py`
- Modify: `tests/test_nuclei_enhanced.py`

- [ ] **Step 1: Add interactsh flags to build_command**

Add `interactsh_url` and `interactsh_server` parameters:

```python
def build_command(self, ..., interactsh_url: str | None = None, interactsh_server: str | None = None) -> list[str]:
    # ... existing code ...
    if interactsh_url:
        cmd.extend(["-iurl", interactsh_url])
    if interactsh_server:
        cmd.extend(["-iserver", interactsh_server])
    return cmd
```

- [ ] **Step 2: Add headless mode support**

```python
    if headless:
        cmd.append("-headless")
```

- [ ] **Step 3: Test and commit**

```bash
git commit -m "feat: add interactsh and headless support to nuclei wrapper"
```

---

### Task 7: nomore403 — Automated 403 Bypass

`nomore403` is a Go tool that tries multiple 403 bypass techniques automatically.

**Files:**
- Create: `src/bba/tools/nomore403.py`
- Create: `tests/test_tools_nomore403.py`

- [ ] **Step 1: Write tests**

```python
# tests/test_tools_nomore403.py
import pytest
from unittest.mock import patch
from bba.tools.nomore403 import Nomore403Tool
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {"program": "test", "in_scope": {"domains": ["*.example.com"], "cidrs": []}, "out_of_scope": {}}

@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))

@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(), sanitizer=Sanitizer(), output_dir=tmp_path / "output")

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()

class TestNomore403Tool:
    def test_build_command(self, runner, db):
        tool = Nomore403Tool(runner=runner, db=db, program="test")
        cmd = tool.build_command("https://example.com/admin")
        assert "nomore403" in cmd[0]
        assert "https://example.com/admin" in cmd

    def test_parse_output_finds_bypass(self, runner, db):
        tool = Nomore403Tool(runner=runner, db=db, program="test")
        output = "200 https://example.com/%2e/admin (Header: X-Original-URL)\n403 https://example.com/admin\n"
        result = tool.parse_output(output)
        assert len(result) == 1
        assert result[0]["status"] == 200

    def test_parse_output_no_bypass(self, runner, db):
        tool = Nomore403Tool(runner=runner, db=db, program="test")
        output = "403 https://example.com/admin\n403 https://example.com/%2e/admin\n"
        result = tool.parse_output(output)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_run_stores_finding(self, runner, db):
        tool = Nomore403Tool(runner=runner, db=db, program="test")
        mock = ToolResult(success=True, output="200 https://example.com/%2e/admin (Method: POST)\n", raw_file=None, error=None, duration=2.0)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run("https://example.com/admin")
        assert result["total"] == 1
        findings = await db.get_findings("test")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "403-bypass"
```

- [ ] **Step 2: Implement**

```python
# src/bba/tools/nomore403.py
"""Automated 403 bypass via nomore403."""
from __future__ import annotations
import re
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

_BYPASS_PATTERN = re.compile(r"^(200|30[0-9])\s+(\S+)(?:\s+\((.+)\))?", re.M)


class Nomore403Tool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["nomore403", "-u", url]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for match in _BYPASS_PATTERN.finditer(output):
            status = int(match.group(1))
            if status < 400:  # Bypass = non-4xx response
                results.append({
                    "status": status,
                    "url": match.group(2),
                    "technique": match.group(3) or "unknown",
                })
        return results

    async def run(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="nomore403", command=self.build_command(url),
            targets=[domain] if domain else [url], timeout=120,
        )
        if not result.success:
            return {"total": 0, "bypasses": [], "error": result.error}
        bypasses = self.parse_output(result.output)
        for b in bypasses:
            await self.db.add_finding(
                program=self.program, domain=domain, url=b["url"],
                vuln_type="403-bypass", severity="medium", tool="nomore403",
                evidence=f"Status {b['status']} via {b['technique']}. Original: {url}",
                confidence=0.8,
            )
        return {"total": len(bypasses), "bypasses": bypasses, "original_url": url}
```

- [ ] **Step 3: Run tests, commit**

```bash
git add src/bba/tools/nomore403.py tests/test_tools_nomore403.py
git commit -m "feat: add nomore403 automated 403 bypass tool"
```

---

### Task 8: CLI Commands + Install Script for New Tools

**Files:**
- Modify: `src/bba/cli.py`
- Modify: `scripts/install-tools.sh`

- [ ] **Step 1: Add CLI subparsers for interactsh, nomore403**

Under `scan`:
```python
# interactsh - generate OOB URLs
p = scan_sub.add_parser("interactsh-generate", help="Generate OOB callback URLs")
p.add_argument("--count", type=int, default=10)
p.add_argument("--server", default=None)
p.add_argument("--program", required=True)
p.set_defaults(func=cmd_scan_interactsh_generate)

# interactsh - poll for interactions
p = scan_sub.add_parser("interactsh-poll", help="Poll for OOB interactions")
p.add_argument("session_file", help="Session file from generate")
p.add_argument("--domain", required=True)
p.add_argument("--program", required=True)
p.set_defaults(func=cmd_scan_interactsh_poll)

# nomore403
p = scan_sub.add_parser("nomore403", help="403 bypass automation")
p.add_argument("url", help="URL returning 403")
p.add_argument("--program", required=True)
p.set_defaults(func=cmd_scan_nomore403)
```

- [ ] **Step 2: Add install commands**

```bash
install_go_tool "nomore403" "github.com/devploit/nomore403@latest"
install_go_tool "interactsh-client" "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
```

- [ ] **Step 3: Run full test suite, commit**

```bash
uv run python -m pytest tests/ --ignore=tests/integration -q
git add src/bba/cli.py scripts/install-tools.sh
git commit -m "feat: add CLI commands for interactsh and nomore403"
```

---

### Task 9: Update CLAUDE.md + Agent Prompts with Interactsh

**Files:**
- Modify: `CLAUDE.md`
- Modify: `.claude/agents/vuln-tester.md`
- Modify: `.claude/agents/scanner.md`

- [ ] **Step 1: Add interactsh commands to CLAUDE.md BBA CLI reference**

```
# Scan — OOB detection
uv run bba scan interactsh-generate --program <prog> [--count 10] [--server url]
uv run bba scan interactsh-poll <session-file> --program <prog> --domain <d>
uv run bba scan nomore403 <url> --program <prog>
```

- [ ] **Step 2: Update vuln-tester agent to use interactsh in blind testing pipelines**

Add to SSRF, XSS blind, SQLi blind, XXE blind sections:
```
# Generate OOB callback URLs for blind testing
uv run bba scan interactsh-generate --program <prog> --count 20
# Inject callback URLs as payloads...
# After injection, poll for interactions
uv run bba scan interactsh-poll <session-file> --program <prog> --domain <domain>
```

- [ ] **Step 3: Update scanner agent to use nuclei with --interactsh-url**

- [ ] **Step 4: Commit**

```bash
git commit -m "docs: integrate interactsh into agent prompts and CLI reference"
```

---

## Summary

| Task | Component | Impact |
|------|-----------|--------|
| 1 | tool_runner process cleanup + timestamp | RELIABILITY |
| 2 | DB dedup + batching + export + stats | PERFORMANCE + QUALITY |
| 3 | Adaptive rate limiting | STEALTH |
| 4 | interactsh OOB detection | CRITICAL CAPABILITY |
| 5 | nuclei + interactsh integration | CRITICAL CAPABILITY |
| 6 | nomore403 bypass tool | HIGH SIGNAL |
| 7 | CLI + install for new tools | INTEGRATION |
| 8 | Agent prompt updates | INTELLIGENCE |

**Note:** qsreplace shell injection fix moved to Phase 5B as a complete native Python rewrite.
