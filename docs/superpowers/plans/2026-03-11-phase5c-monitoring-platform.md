# Phase 5C: Continuous Monitoring & Platform Integration

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add continuous monitoring (diff mode, rescan detection), notification system (Slack/Discord/Telegram via ProjectDiscovery `notify`), scope import from bug bounty platforms (HackerOne/Bugcrowd APIs), CLI modularization (split 1500+ line monolith), `--dry-run` mode, and scan resume capability — transforming the framework from a one-shot scanner into a persistent monitoring platform.

**Architecture:** Scan state tracking via new DB tables enables resume and diff mode. The `notify` tool sends alerts on new findings. Scope import fetches program definitions from platform APIs and converts to our YAML format. CLI splits into per-group modules imported by the main entry point. Dry-run mode logs planned commands without executing them.

**Tech Stack:** Python 3.13+, aiosqlite, ProjectDiscovery `notify`, existing bba modules

**Depends on:** Phase 5A should be completed first (hardened tool_runner, adaptive rate limiter, DB improvements).

---

## File Structure

```
src/bba/
    cli.py               # MODIFY — refactor to import from cli/ submodules
    cli/
        __init__.py      # CREATE — main parser builder, imports submodules
        recon.py         # CREATE — all recon subcommands
        scan.py          # CREATE — all scan subcommands
        db_cmds.py       # CREATE — all db subcommands
        report.py        # CREATE — report + wordlist commands
    scan_state.py        # CREATE — scan state tracker for resume + diff
    notifier.py          # CREATE — notification dispatcher via notify
    scope_importer.py    # CREATE — HackerOne/Bugcrowd scope import

src/bba/tools/
    notify.py            # CREATE — ProjectDiscovery notify wrapper

tests/
    test_scan_state.py   # CREATE
    test_notifier.py     # CREATE
    test_scope_importer.py # CREATE
    test_tools_notify.py # CREATE
    test_cli_split.py    # CREATE — verify CLI still works after split
```

---

## Chunk 1: Scan State Tracking (Resume + Diff Mode)

### Task 1: Scan State Database Schema

Track scan execution state to enable resume-on-failure and diff-between-runs.

**Files:**
- Create: `src/bba/scan_state.py`
- Create: `tests/test_scan_state.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_scan_state.py
import pytest
from bba.scan_state import ScanState
from bba.db import Database


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestScanState:
    @pytest.mark.asyncio
    async def test_create_scan_run(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("test-prog", {"phases": "all"})
        assert run_id > 0

    @pytest.mark.asyncio
    async def test_update_phase(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("test-prog", {})
        await state.update_phase(run_id, "recon", "completed")
        phases = await state.get_completed_phases(run_id)
        assert "recon" in phases

    @pytest.mark.asyncio
    async def test_resume_skips_completed(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("test-prog", {})
        await state.update_phase(run_id, "recon", "completed")
        await state.update_phase(run_id, "infrastructure", "completed")
        remaining = await state.get_remaining_phases(run_id)
        assert "recon" not in remaining
        assert "infrastructure" not in remaining
        assert "scanning" in remaining

    @pytest.mark.asyncio
    async def test_mark_failed_allows_resume(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("test-prog", {})
        await state.update_phase(run_id, "scanning", "failed", error="timeout")
        status = await state.get_phase_status(run_id, "scanning")
        assert status["status"] == "failed"
        assert status["error"] == "timeout"

    @pytest.mark.asyncio
    async def test_get_latest_run(self, db):
        state = ScanState(db)
        await state.initialize()
        await state.create_run("test-prog", {"v": 1})
        run2 = await state.create_run("test-prog", {"v": 2})
        latest = await state.get_latest_run("test-prog")
        assert latest["id"] == run2

    @pytest.mark.asyncio
    async def test_diff_finds_new_subdomains(self, db):
        state = ScanState(db)
        await state.initialize()
        run1 = await state.create_run("test-prog", {})
        await state.record_snapshot(run1, "subdomains", ["a.example.com", "b.example.com"])
        await state.update_phase(run1, "recon", "completed")

        run2 = await state.create_run("test-prog", {})
        await state.record_snapshot(run2, "subdomains", ["a.example.com", "b.example.com", "c.example.com"])
        diff = await state.diff_snapshots(run1, run2, "subdomains")
        assert diff["added"] == ["c.example.com"]
        assert diff["removed"] == []

    @pytest.mark.asyncio
    async def test_diff_detects_removed(self, db):
        state = ScanState(db)
        await state.initialize()
        run1 = await state.create_run("test-prog", {})
        await state.record_snapshot(run1, "subdomains", ["a.example.com", "b.example.com"])
        run2 = await state.create_run("test-prog", {})
        await state.record_snapshot(run2, "subdomains", ["a.example.com"])
        diff = await state.diff_snapshots(run1, run2, "subdomains")
        assert diff["removed"] == ["b.example.com"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_scan_state.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'bba.scan_state'`

- [ ] **Step 3: Implement ScanState**

```python
# src/bba/scan_state.py
"""Scan state tracking for resume and diff mode."""
from __future__ import annotations

import json
import time
from bba.db import Database

SCAN_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    config TEXT NOT NULL DEFAULT '{}',
    status TEXT DEFAULT 'running',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_phases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    phase TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    error TEXT,
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    UNIQUE(run_id, phase)
);

CREATE TABLE IF NOT EXISTS scan_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    category TEXT NOT NULL,
    items TEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(run_id, category)
);
"""

ALL_PHASES = [
    "recon", "infrastructure", "osint", "scanning",
    "vuln-testing", "deep-dive", "validation", "reporting",
]


class ScanState:
    def __init__(self, db: Database):
        self.db = db

    async def initialize(self):
        async with self.db._conn.executescript(SCAN_STATE_SCHEMA) as _:
            pass
        await self.db._conn.commit()

    async def create_run(self, program: str, config: dict) -> int:
        cursor = await self.db._conn.execute(
            "INSERT INTO scan_runs (program, config) VALUES (?, ?)",
            (program, json.dumps(config)),
        )
        await self.db._conn.commit()
        return cursor.lastrowid

    async def update_phase(self, run_id: int, phase: str, status: str,
                           error: str | None = None):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        started = now if status == "running" else None
        finished = now if status in ("completed", "failed", "skipped") else None
        await self.db._conn.execute(
            """INSERT INTO scan_phases (run_id, phase, status, error, started_at, finished_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(run_id, phase) DO UPDATE SET
                   status=excluded.status, error=excluded.error,
                   finished_at=excluded.finished_at""",
            (run_id, phase, status, error, started, finished),
        )
        await self.db._conn.commit()

    async def get_completed_phases(self, run_id: int) -> list[str]:
        cursor = await self.db._conn.execute(
            "SELECT phase FROM scan_phases WHERE run_id = ? AND status = 'completed'",
            (run_id,),
        )
        rows = await cursor.fetchall()
        return [r[0] for r in rows]

    async def get_remaining_phases(self, run_id: int) -> list[str]:
        completed = set(await self.get_completed_phases(run_id))
        return [p for p in ALL_PHASES if p not in completed]

    async def get_phase_status(self, run_id: int, phase: str) -> dict | None:
        cursor = await self.db._conn.execute(
            "SELECT status, error, started_at, finished_at FROM scan_phases WHERE run_id = ? AND phase = ?",
            (run_id, phase),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return {"status": row[0], "error": row[1], "started_at": row[2], "finished_at": row[3]}

    async def get_latest_run(self, program: str) -> dict | None:
        cursor = await self.db._conn.execute(
            "SELECT id, config, status, started_at, finished_at FROM scan_runs WHERE program = ? ORDER BY id DESC LIMIT 1",
            (program,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return {"id": row[0], "config": json.loads(row[1]), "status": row[2],
                "started_at": row[3], "finished_at": row[4]}

    async def finish_run(self, run_id: int, status: str = "completed"):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        await self.db._conn.execute(
            "UPDATE scan_runs SET status = ?, finished_at = ? WHERE id = ?",
            (status, now, run_id),
        )
        await self.db._conn.commit()

    async def record_snapshot(self, run_id: int, category: str, items: list[str]):
        await self.db._conn.execute(
            """INSERT INTO scan_snapshots (run_id, category, items)
               VALUES (?, ?, ?)
               ON CONFLICT(run_id, category) DO UPDATE SET items = excluded.items""",
            (run_id, category, json.dumps(sorted(items))),
        )
        await self.db._conn.commit()

    async def diff_snapshots(self, run_id_old: int, run_id_new: int, category: str) -> dict:
        cursor = await self.db._conn.execute(
            "SELECT items FROM scan_snapshots WHERE run_id = ? AND category = ?",
            (run_id_old, category),
        )
        row_old = await cursor.fetchone()
        old_items = set(json.loads(row_old[0])) if row_old else set()

        cursor = await self.db._conn.execute(
            "SELECT items FROM scan_snapshots WHERE run_id = ? AND category = ?",
            (run_id_new, category),
        )
        row_new = await cursor.fetchone()
        new_items = set(json.loads(row_new[0])) if row_new else set()

        return {
            "added": sorted(new_items - old_items),
            "removed": sorted(old_items - new_items),
            "unchanged": len(old_items & new_items),
        }
```

- [ ] **Step 4: Run tests**

Run: `uv run python -m pytest tests/test_scan_state.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/bba/scan_state.py tests/test_scan_state.py
git commit -m "feat: scan state tracking for resume and diff mode"
```

---

### Task 2: CLI Commands for Resume and Diff

**Files:**
- Modify: `src/bba/cli.py`

- [ ] **Step 1: Add scan-state CLI subparsers**

Add under `db` subgroup:

```python
# Scan state commands
p = db_sub.add_parser("scan-history", help="List scan runs for a program")
p.add_argument("--program", required=True)
p.set_defaults(func=cmd_db_scan_history)

p = db_sub.add_parser("scan-status", help="Show status of a scan run")
p.add_argument("run_id", type=int)
p.add_argument("--program", required=True)
p.set_defaults(func=cmd_db_scan_status)

p = db_sub.add_parser("scan-diff", help="Diff two scan runs")
p.add_argument("old_run_id", type=int)
p.add_argument("new_run_id", type=int)
p.add_argument("--category", default="subdomains", choices=["subdomains", "urls", "services", "findings"])
p.add_argument("--program", required=True)
p.set_defaults(func=cmd_db_scan_diff)
```

- [ ] **Step 2: Implement command handlers**

```python
async def cmd_db_scan_history(args):
    scope_cfg = _load_scope(args.program)
    db = Database(Path("data/db/findings.db"))
    await db.initialize()
    try:
        state = ScanState(db)
        await state.initialize()
        cursor = await db._conn.execute(
            "SELECT id, status, started_at, finished_at FROM scan_runs WHERE program = ? ORDER BY id DESC LIMIT 20",
            (args.program,),
        )
        rows = await cursor.fetchall()
        runs = [{"id": r[0], "status": r[1], "started_at": r[2], "finished_at": r[3]} for r in rows]
        print(json.dumps(runs, indent=2))
    finally:
        await db.close()

async def cmd_db_scan_status(args):
    db = Database(Path("data/db/findings.db"))
    await db.initialize()
    try:
        state = ScanState(db)
        await state.initialize()
        cursor = await db._conn.execute(
            "SELECT phase, status, error, started_at, finished_at FROM scan_phases WHERE run_id = ? ORDER BY id",
            (args.run_id,),
        )
        rows = await cursor.fetchall()
        phases = [{"phase": r[0], "status": r[1], "error": r[2], "started_at": r[3], "finished_at": r[4]} for r in rows]
        print(json.dumps(phases, indent=2))
    finally:
        await db.close()

async def cmd_db_scan_diff(args):
    db = Database(Path("data/db/findings.db"))
    await db.initialize()
    try:
        state = ScanState(db)
        await state.initialize()
        diff = await state.diff_snapshots(args.old_run_id, args.new_run_id, args.category)
        print(json.dumps(diff, indent=2))
    finally:
        await db.close()
```

- [ ] **Step 3: Run full test suite**

Run: `uv run python -m pytest tests/ --ignore=tests/integration -q`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/bba/cli.py
git commit -m "feat: add scan-history, scan-status, scan-diff CLI commands"
```

---

## Chunk 2: Notification System

### Task 3: ProjectDiscovery `notify` Tool Wrapper

ProjectDiscovery's `notify` sends messages to Slack, Discord, Telegram, email, and more via a provider config file.

**Files:**
- Create: `src/bba/tools/notify.py`
- Create: `tests/test_tools_notify.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_tools_notify.py
import pytest
from unittest.mock import patch, AsyncMock
from bba.tools.notify import NotifyTool
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
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(),
                      sanitizer=Sanitizer(), output_dir=tmp_path / "output")


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestNotifyTool:
    def test_build_command_with_provider(self, runner, db):
        tool = NotifyTool(runner=runner, db=db, program="test")
        cmd = tool.build_command("New finding: XSS on example.com", provider_config="/etc/notify.yaml")
        assert "notify" in cmd[0]
        assert "-pc" in cmd
        assert "/etc/notify.yaml" in cmd

    def test_build_command_bulk(self, runner, db):
        tool = NotifyTool(runner=runner, db=db, program="test")
        cmd = tool.build_command_bulk("/tmp/messages.txt", provider_config="/etc/notify.yaml")
        assert "-data" in cmd

    def test_format_finding_message(self, runner, db):
        tool = NotifyTool(runner=runner, db=db, program="test")
        msg = tool.format_finding({
            "vuln_type": "xss", "severity": "high",
            "url": "https://example.com/search?q=test",
            "tool": "dalfox", "confidence": 0.9,
        })
        assert "xss" in msg.lower()
        assert "HIGH" in msg
        assert "example.com" in msg

    def test_format_diff_message(self, runner, db):
        tool = NotifyTool(runner=runner, db=db, program="test")
        msg = tool.format_diff({
            "added": ["new.example.com", "api.example.com"],
            "removed": ["old.example.com"],
            "unchanged": 5,
        }, category="subdomains", program="test-prog")
        assert "new.example.com" in msg
        assert "+2" in msg or "2 new" in msg.lower()

    @pytest.mark.asyncio
    async def test_send_message(self, runner, db):
        tool = NotifyTool(runner=runner, db=db, program="test")
        mock_result = ToolResult(success=True, output="sent", raw_file=None, error=None, duration=0.5)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.send("Test alert", provider_config="/etc/notify.yaml")
        assert result["sent"]
```

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run python -m pytest tests/test_tools_notify.py -v`
Expected: FAIL

- [ ] **Step 3: Implement NotifyTool**

```python
# src/bba/tools/notify.py
"""Notification dispatcher via ProjectDiscovery notify."""
from __future__ import annotations

import asyncio
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner


class NotifyTool:
    """Send alerts to Slack, Discord, Telegram via notify."""

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, message: str, provider_config: str | None = None,
                      bulk: bool = False) -> list[str]:
        cmd = ["notify"]
        if provider_config:
            cmd.extend(["-pc", provider_config])
        if not bulk:
            cmd.extend(["-data", message])
        return cmd

    def build_command_bulk(self, data_file: str, provider_config: str | None = None) -> list[str]:
        cmd = ["notify", "-data", data_file, "-bulk"]
        if provider_config:
            cmd.extend(["-pc", provider_config])
        return cmd

    def format_finding(self, finding: dict) -> str:
        severity = finding.get("severity", "unknown").upper()
        vuln_type = finding.get("vuln_type", "unknown")
        url = finding.get("url", "N/A")
        tool = finding.get("tool", "unknown")
        confidence = finding.get("confidence", 0)
        return (
            f"[{severity}] {vuln_type} | {url} | "
            f"Tool: {tool} | Confidence: {confidence:.0%}"
        )

    def format_diff(self, diff: dict, category: str, program: str) -> str:
        added = diff.get("added", [])
        removed = diff.get("removed", [])
        unchanged = diff.get("unchanged", 0)
        lines = [f"[DIFF] {program} — {category}: +{len(added)} new, -{len(removed)} removed, {unchanged} unchanged"]
        if added:
            lines.append(f"  New: {', '.join(added[:10])}")
            if len(added) > 10:
                lines.append(f"  ... and {len(added) - 10} more")
        if removed:
            lines.append(f"  Removed: {', '.join(removed[:10])}")
        return "\n".join(lines)

    def format_scan_complete(self, program: str, stats: dict) -> str:
        return (
            f"[SCAN COMPLETE] {program}\n"
            f"  Subdomains: {stats.get('subdomains', 0)}\n"
            f"  Services: {stats.get('services', 0)}\n"
            f"  Findings: {stats.get('findings', 0)}\n"
            f"  Critical/High: {stats.get('critical', 0)}/{stats.get('high', 0)}"
        )

    async def send(self, message: str, provider_config: str | None = None) -> dict:
        result = await self.runner.run_command(
            tool="notify",
            command=self.build_command(message, provider_config),
            targets=["notify"],
            timeout=30,
        )
        return {"sent": result.success, "error": result.error}

    async def send_finding(self, finding: dict, provider_config: str | None = None) -> dict:
        message = self.format_finding(finding)
        return await self.send(message, provider_config)

    async def send_bulk(self, messages: list[str], work_dir: Path,
                        provider_config: str | None = None) -> dict:
        data_file = work_dir / "notify_bulk.txt"
        data_file.write_text("\n".join(messages) + "\n")
        result = await self.runner.run_command(
            tool="notify",
            command=self.build_command_bulk(str(data_file), provider_config),
            targets=["notify"],
            timeout=60,
        )
        return {"sent": result.success, "count": len(messages), "error": result.error}
```

- [ ] **Step 4: Run tests**

Run: `uv run python -m pytest tests/test_tools_notify.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/bba/tools/notify.py tests/test_tools_notify.py
git commit -m "feat: add notify tool wrapper for Slack/Discord/Telegram alerts"
```

---

### Task 4: Notifier Service — Finding + Diff Alerts

Higher-level notifier that watches for new findings and diffs, auto-sends notifications.

**Files:**
- Create: `src/bba/notifier.py`
- Create: `tests/test_notifier.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_notifier.py
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from bba.notifier import Notifier
from bba.db import Database


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestNotifier:
    @pytest.mark.asyncio
    async def test_notify_new_findings(self, db, tmp_path):
        notifier = Notifier(db=db, provider_config=str(tmp_path / "notify.yaml"))
        # Add a finding
        await db.add_finding("prog", "example.com", "https://example.com/x",
                             "xss", "high", "dalfox", "evidence", 0.9)
        with patch.object(notifier, "_send_message", new_callable=AsyncMock) as mock_send:
            await notifier.notify_findings("prog", severity_threshold="medium")
            mock_send.assert_called_once()
            call_msg = mock_send.call_args[0][0]
            assert "xss" in call_msg.lower()

    @pytest.mark.asyncio
    async def test_severity_threshold_filters(self, db, tmp_path):
        notifier = Notifier(db=db, provider_config=str(tmp_path / "notify.yaml"))
        await db.add_finding("prog", "example.com", "https://example.com/x",
                             "info-disclosure", "low", "nikto", "evidence", 0.5)
        with patch.object(notifier, "_send_message", new_callable=AsyncMock) as mock_send:
            await notifier.notify_findings("prog", severity_threshold="high")
            mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_notify_diff(self, db, tmp_path):
        notifier = Notifier(db=db, provider_config=str(tmp_path / "notify.yaml"))
        diff = {"added": ["new.example.com"], "removed": [], "unchanged": 5}
        with patch.object(notifier, "_send_message", new_callable=AsyncMock) as mock_send:
            await notifier.notify_diff("prog", "subdomains", diff)
            mock_send.assert_called_once()
            call_msg = mock_send.call_args[0][0]
            assert "new.example.com" in call_msg
```

- [ ] **Step 2: Implement Notifier**

```python
# src/bba/notifier.py
"""High-level notification dispatcher for findings and diffs."""
from __future__ import annotations

from bba.db import Database

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class Notifier:
    def __init__(self, db: Database, provider_config: str | None = None):
        self.db = db
        self.provider_config = provider_config

    async def _send_message(self, message: str):
        """Send via notify CLI. Override in tests."""
        import asyncio
        cmd = ["notify"]
        if self.provider_config:
            cmd.extend(["-pc", self.provider_config])
        cmd.extend(["-data", message])
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

    async def notify_findings(self, program: str, severity_threshold: str = "medium",
                              status: str = "new"):
        threshold = SEVERITY_ORDER.get(severity_threshold, 2)
        findings = await self.db.get_findings(program, status=status)
        for f in findings:
            sev_level = SEVERITY_ORDER.get(f.get("severity", "info"), 0)
            if sev_level >= threshold:
                severity = f.get("severity", "unknown").upper()
                vuln_type = f.get("vuln_type", "unknown")
                url = f.get("url", "N/A")
                tool = f.get("tool", "unknown")
                msg = f"[{severity}] {vuln_type} | {url} | Tool: {tool}"
                await self._send_message(msg)

    async def notify_diff(self, program: str, category: str, diff: dict):
        added = diff.get("added", [])
        removed = diff.get("removed", [])
        if not added and not removed:
            return
        lines = [f"[DIFF] {program} — {category}: +{len(added)} new, -{len(removed)} removed"]
        if added:
            lines.append(f"  New: {', '.join(added[:10])}")
        if removed:
            lines.append(f"  Removed: {', '.join(removed[:10])}")
        await self._send_message("\n".join(lines))

    async def notify_scan_complete(self, program: str, stats: dict):
        msg = (
            f"[SCAN COMPLETE] {program}\n"
            f"  Findings: {stats.get('total', 0)} | "
            f"Critical: {stats.get('critical', 0)} | High: {stats.get('high', 0)}"
        )
        await self._send_message(msg)
```

- [ ] **Step 3: Run tests**

Run: `uv run python -m pytest tests/test_notifier.py -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/bba/notifier.py tests/test_notifier.py
git commit -m "feat: add notifier service for finding and diff alerts"
```

---

### Task 5: CLI + Install for Notify

**Files:**
- Modify: `src/bba/cli.py`
- Modify: `scripts/install-tools.sh`

- [ ] **Step 1: Add notify CLI subparsers**

```python
# Under scan subparser group
p = scan_sub.add_parser("notify", help="Send notification via notify")
p.add_argument("message", help="Message to send")
p.add_argument("--provider-config", default=None, help="Path to notify provider config")
p.add_argument("--program", required=True)
p.set_defaults(func=cmd_scan_notify)

p = scan_sub.add_parser("notify-findings", help="Send notifications for new findings")
p.add_argument("--program", required=True)
p.add_argument("--severity", default="medium", choices=["critical", "high", "medium", "low", "info"])
p.add_argument("--provider-config", default=None)
p.set_defaults(func=cmd_scan_notify_findings)
```

- [ ] **Step 2: Add install command**

```bash
install_go_tool "notify" "github.com/projectdiscovery/notify/cmd/notify@latest"
```

- [ ] **Step 3: Run full test suite, commit**

```bash
uv run python -m pytest tests/ --ignore=tests/integration -q
git add src/bba/cli.py scripts/install-tools.sh
git commit -m "feat: add notify CLI commands and install script"
```

---

## Chunk 3: Scope Import from Bug Bounty Platforms

### Task 6: Scope Importer — HackerOne + Bugcrowd

Convert public program scopes from HackerOne/Bugcrowd APIs into our YAML format.

**Files:**
- Create: `src/bba/scope_importer.py`
- Create: `tests/test_scope_importer.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_scope_importer.py
import pytest
import json
from bba.scope_importer import ScopeImporter


class TestScopeImporter:
    def test_parse_hackerone_scope(self):
        # HackerOne public API response for structured_scopes
        h1_data = {
            "relationships": {
                "structured_scopes": {
                    "data": [
                        {
                            "attributes": {
                                "asset_type": "URL",
                                "asset_identifier": "*.example.com",
                                "eligible_for_bounty": True,
                                "eligible_for_submission": True,
                                "instruction": "All subdomains",
                            }
                        },
                        {
                            "attributes": {
                                "asset_type": "URL",
                                "asset_identifier": "api.example.com",
                                "eligible_for_bounty": True,
                                "eligible_for_submission": True,
                            }
                        },
                        {
                            "attributes": {
                                "asset_type": "URL",
                                "asset_identifier": "staging.example.com",
                                "eligible_for_bounty": False,
                                "eligible_for_submission": False,
                            }
                        },
                        {
                            "attributes": {
                                "asset_type": "CIDR",
                                "asset_identifier": "10.0.0.0/24",
                                "eligible_for_bounty": True,
                                "eligible_for_submission": True,
                            }
                        },
                    ]
                }
            }
        }
        importer = ScopeImporter()
        scope = importer.parse_hackerone(h1_data, "example-corp")
        assert scope["program"] == "example-corp"
        assert scope["platform"] == "hackerone"
        assert "*.example.com" in scope["in_scope"]["domains"]
        assert "api.example.com" in scope["in_scope"]["domains"]
        assert "10.0.0.0/24" in scope["in_scope"]["cidrs"]
        assert "staging.example.com" in scope["out_of_scope"]["domains"]

    def test_parse_bugcrowd_scope(self):
        bc_data = {
            "target_groups": [
                {
                    "in_scope": True,
                    "targets": [
                        {"name": "*.example.com", "category": "website"},
                        {"name": "api.example.com", "category": "api"},
                    ]
                },
                {
                    "in_scope": False,
                    "targets": [
                        {"name": "blog.example.com", "category": "website"},
                    ]
                },
            ]
        }
        importer = ScopeImporter()
        scope = importer.parse_bugcrowd(bc_data, "example-corp")
        assert scope["program"] == "example-corp"
        assert scope["platform"] == "bugcrowd"
        assert "*.example.com" in scope["in_scope"]["domains"]
        assert "blog.example.com" in scope["out_of_scope"]["domains"]

    def test_to_yaml(self, tmp_path):
        importer = ScopeImporter()
        scope = {
            "program": "test-corp",
            "platform": "hackerone",
            "in_scope": {"domains": ["*.test.com"], "cidrs": []},
            "out_of_scope": {"domains": [], "paths": []},
        }
        output = tmp_path / "test-corp.yaml"
        importer.save_yaml(scope, output)
        assert output.exists()
        import yaml
        loaded = yaml.safe_load(output.read_text())
        assert loaded["program"] == "test-corp"
        assert "*.test.com" in loaded["in_scope"]["domains"]

    def test_normalize_domain(self):
        importer = ScopeImporter()
        assert importer._normalize_asset("https://example.com") == "example.com"
        assert importer._normalize_asset("http://example.com/") == "example.com"
        assert importer._normalize_asset("*.example.com") == "*.example.com"
        assert importer._normalize_asset("example.com") == "example.com"
```

- [ ] **Step 2: Implement ScopeImporter**

```python
# src/bba/scope_importer.py
"""Import program scope from HackerOne/Bugcrowd into our YAML format."""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

import yaml


class ScopeImporter:
    """Convert bug bounty platform scope data to our YAML format."""

    def _normalize_asset(self, asset: str) -> str:
        asset = asset.strip()
        if asset.startswith(("http://", "https://")):
            parsed = urlparse(asset)
            return parsed.hostname or asset
        return asset.rstrip("/")

    def _is_cidr(self, asset: str) -> bool:
        return bool(re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", asset))

    def parse_hackerone(self, data: dict, program_name: str) -> dict:
        in_domains = []
        in_cidrs = []
        out_domains = []
        scopes = (data.get("relationships", {})
                      .get("structured_scopes", {})
                      .get("data", []))
        for entry in scopes:
            attrs = entry.get("attributes", {})
            asset = attrs.get("asset_identifier", "")
            asset_type = attrs.get("asset_type", "")
            eligible = attrs.get("eligible_for_submission", False)
            normalized = self._normalize_asset(asset)
            if not normalized:
                continue
            if eligible:
                if asset_type == "CIDR" or self._is_cidr(normalized):
                    in_cidrs.append(normalized)
                else:
                    in_domains.append(normalized)
            else:
                if asset_type in ("URL", "WILDCARD"):
                    out_domains.append(normalized)
        return {
            "program": program_name,
            "platform": "hackerone",
            "in_scope": {"domains": in_domains, "cidrs": in_cidrs},
            "out_of_scope": {"domains": out_domains, "paths": []},
        }

    def parse_bugcrowd(self, data: dict, program_name: str) -> dict:
        in_domains = []
        in_cidrs = []
        out_domains = []
        for group in data.get("target_groups", []):
            in_scope = group.get("in_scope", True)
            for target in group.get("targets", []):
                asset = self._normalize_asset(target.get("name", ""))
                if not asset:
                    continue
                if in_scope:
                    if self._is_cidr(asset):
                        in_cidrs.append(asset)
                    else:
                        in_domains.append(asset)
                else:
                    out_domains.append(asset)
        return {
            "program": program_name,
            "platform": "bugcrowd",
            "in_scope": {"domains": in_domains, "cidrs": in_cidrs},
            "out_of_scope": {"domains": out_domains, "paths": []},
        }

    def save_yaml(self, scope: dict, output_path: Path):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(yaml.dump(scope, default_flow_style=False, sort_keys=False))
```

- [ ] **Step 3: Run tests**

Run: `uv run python -m pytest tests/test_scope_importer.py -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/bba/scope_importer.py tests/test_scope_importer.py
git commit -m "feat: scope importer for HackerOne and Bugcrowd programs"
```

---

### Task 7: CLI Commands for Scope Import

**Files:**
- Modify: `src/bba/cli.py`

- [ ] **Step 1: Add scope import CLI commands**

```python
# Add new top-level 'scope' subgroup
scope_parser = subparsers.add_parser("scope", help="Scope management")
scope_sub = scope_parser.add_subparsers(dest="scope_cmd")

p = scope_sub.add_parser("import-h1", help="Import scope from HackerOne")
p.add_argument("handle", help="HackerOne program handle")
p.add_argument("--name", help="Program name (defaults to handle)")
p.add_argument("--output", default=None, help="Output path (defaults to data/programs/<name>.yaml)")
p.set_defaults(func=cmd_scope_import_h1)

p = scope_sub.add_parser("import-bc", help="Import scope from Bugcrowd")
p.add_argument("handle", help="Bugcrowd program handle")
p.add_argument("--name", help="Program name (defaults to handle)")
p.add_argument("--output", default=None)
p.set_defaults(func=cmd_scope_import_bc)
```

- [ ] **Step 2: Implement handlers (fetch from public APIs)**

```python
async def cmd_scope_import_h1(args):
    import urllib.request
    import json
    from bba.scope_importer import ScopeImporter

    handle = args.handle
    name = args.name or handle
    url = f"https://hackerone.com/programs/{handle}/policy_scopes.json"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read().decode())
    except Exception as e:
        print(json.dumps({"error": f"Failed to fetch H1 scope: {e}"}))
        return

    importer = ScopeImporter()
    scope = importer.parse_hackerone(data, name)
    output = Path(args.output) if args.output else Path(f"data/programs/{name}.yaml")
    importer.save_yaml(scope, output)
    print(json.dumps({"saved": str(output), "in_scope_domains": len(scope["in_scope"]["domains"]),
                       "in_scope_cidrs": len(scope["in_scope"]["cidrs"]),
                       "out_of_scope": len(scope["out_of_scope"]["domains"])}))
```

- [ ] **Step 3: Run tests, commit**

```bash
git add src/bba/cli.py
git commit -m "feat: add scope import CLI commands for HackerOne and Bugcrowd"
```

---

## Chunk 4: Dry-Run Mode + CLI Modularization

### Task 8: Dry-Run Mode for ToolRunner

Add `--dry-run` flag that logs planned commands without executing them.

**Files:**
- Modify: `src/bba/tool_runner.py`
- Create: `tests/test_dry_run.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_dry_run.py
import pytest
from bba.tool_runner import ToolRunner, ToolResult
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {"program": "test", "in_scope": {"domains": ["*.example.com"], "cidrs": []}, "out_of_scope": {}}


@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))


class TestDryRun:
    @pytest.mark.asyncio
    async def test_dry_run_no_execution(self, scope, tmp_path):
        runner = ToolRunner(
            scope=scope, rate_limiter=MultiTargetRateLimiter(),
            sanitizer=Sanitizer(), output_dir=tmp_path / "output",
            dry_run=True,
        )
        result = await runner.run_command(
            tool="nuclei", command=["nuclei", "-u", "https://example.com"],
            targets=["example.com"], timeout=60,
        )
        assert result.success
        assert "dry-run" in result.output.lower() or "dry_run" in result.output.lower()
        # No actual subprocess was created
        assert result.duration < 0.1

    @pytest.mark.asyncio
    async def test_dry_run_logs_command(self, scope, tmp_path):
        runner = ToolRunner(
            scope=scope, rate_limiter=MultiTargetRateLimiter(),
            sanitizer=Sanitizer(), output_dir=tmp_path / "output",
            dry_run=True,
        )
        result = await runner.run_command(
            tool="ffuf", command=["ffuf", "-u", "https://example.com/FUZZ"],
            targets=["example.com"], timeout=60,
        )
        assert "ffuf" in result.output
        assert "example.com" in result.output

    @pytest.mark.asyncio
    async def test_dry_run_still_validates_scope(self, scope, tmp_path):
        runner = ToolRunner(
            scope=scope, rate_limiter=MultiTargetRateLimiter(),
            sanitizer=Sanitizer(), output_dir=tmp_path / "output",
            dry_run=True,
        )
        with pytest.raises(ValueError, match="out of scope"):
            await runner.run_command(
                tool="nuclei", command=["nuclei", "-u", "https://evil.com"],
                targets=["evil.com"], timeout=60,
            )
```

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run python -m pytest tests/test_dry_run.py -v`
Expected: FAIL — `TypeError: unexpected keyword argument 'dry_run'`

- [ ] **Step 3: Add dry_run to ToolRunner**

Add `dry_run: bool = False` to `__init__`. In `run_command`, if `dry_run`:

```python
async def run_command(self, tool, command, targets, timeout=600):
    self.validate_targets(targets)

    if self.dry_run:
        cmd_str = " ".join(str(c) for c in command)
        return ToolResult(
            success=True,
            output=f"[DRY-RUN] Would execute: {cmd_str}",
            duration=0.0,
        )

    # ... existing execution code ...
```

- [ ] **Step 4: Run tests**

Run: `uv run python -m pytest tests/test_dry_run.py -v`
Expected: PASS

- [ ] **Step 5: Add --dry-run flag to CLI**

In `src/bba/cli.py`, add `--dry-run` as a global argument:

```python
parser.add_argument("--dry-run", action="store_true", help="Log commands without executing")
```

Pass to ToolRunner: `ToolRunner(..., dry_run=args.dry_run)`

- [ ] **Step 6: Commit**

```bash
git add src/bba/tool_runner.py src/bba/cli.py tests/test_dry_run.py
git commit -m "feat: add --dry-run mode to log commands without execution"
```

---

### Task 9: CLI Modularization — Split into Submodules

The CLI is 1500+ lines. Split into logical submodules.

**Files:**
- Create: `src/bba/cli/__init__.py`
- Create: `src/bba/cli/recon.py`
- Create: `src/bba/cli/scan.py`
- Create: `src/bba/cli/db_cmds.py`
- Create: `src/bba/cli/report.py`
- Modify: `src/bba/cli.py` → rename to `src/bba/cli_legacy.py` (temporary backup)
- Create: `tests/test_cli_split.py`

**Important:** This task requires careful extraction. The approach is:
1. Create `src/bba/cli/` directory
2. Move recon command handlers to `cli/recon.py`
3. Move scan command handlers to `cli/scan.py`
4. Move db command handlers to `cli/db_cmds.py`
5. Move report/wordlist handlers to `cli/report.py`
6. `cli/__init__.py` builds the argument parser and imports from submodules
7. Update `pyproject.toml` entry point if needed

- [ ] **Step 1: Write test to verify CLI entry point works after split**

```python
# tests/test_cli_split.py
import pytest
import subprocess
import sys


class TestCLISplit:
    def test_help_works(self):
        result = subprocess.run(
            [sys.executable, "-m", "bba.cli", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "recon" in result.stdout
        assert "scan" in result.stdout
        assert "db" in result.stdout

    def test_recon_subfinder_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "bba.cli", "recon", "subfinder", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "--program" in result.stdout

    def test_scan_nuclei_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "bba.cli", "scan", "nuclei", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0

    def test_db_summary_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "bba.cli", "db", "summary", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
```

- [ ] **Step 2: Create cli/ directory and __init__.py**

`cli/__init__.py` imports `register_recon_commands`, `register_scan_commands`, `register_db_commands`, `register_report_commands` from submodules and calls them to attach subparsers.

- [ ] **Step 3: Extract recon commands to cli/recon.py**

Move all `cmd_recon_*` functions and their parser registrations.

- [ ] **Step 4: Extract scan commands to cli/scan.py**

Move all `cmd_scan_*` functions.

- [ ] **Step 5: Extract db commands to cli/db_cmds.py**

Move all `cmd_db_*` functions.

- [ ] **Step 6: Extract report/wordlist to cli/report.py**

- [ ] **Step 7: Run full test suite**

Run: `uv run python -m pytest tests/ --ignore=tests/integration -q`
Expected: All existing tests PASS (no behavior change, only file reorganization)

- [ ] **Step 8: Commit**

```bash
git add src/bba/cli/ src/bba/cli.py tests/test_cli_split.py
git commit -m "refactor: split monolithic CLI into recon/scan/db/report submodules"
```

---

## Chunk 5: Agent Prompt Updates + Integration

### Task 10: Update Agent Prompts for Monitoring Capabilities

**Files:**
- Modify: `.claude/commands/scan-target.md`
- Modify: `.claude/agents/scanner.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add resume + diff to scan-target coordinator**

Add Phase 0.5 after precheck:

```markdown
## Phase 0.5: Resume Check

Check if a previous scan exists for this program:

```bash
uv run bba db scan-history --program $ARGUMENTS.program
```

If a previous incomplete run exists, ask the coordinator:
- **Resume**: Skip completed phases, continue from the failed/pending phase
- **Fresh**: Start a new run (but diff results against the previous run)

Track this run:
```bash
# State tracking is automatic — the coordinator records phase completion
```
```

Add Phase 12.5 after reporting:

```markdown
## Phase 12.5: Diff & Notify

If this is not the first scan run, diff against the previous run:

```bash
uv run bba db scan-diff <old_run_id> <new_run_id> --category subdomains --program $ARGUMENTS.program
uv run bba db scan-diff <old_run_id> <new_run_id> --category findings --program $ARGUMENTS.program
```

Notify on new findings:
```bash
uv run bba scan notify-findings --program $ARGUMENTS.program --severity medium
```
```

- [ ] **Step 2: Update CLAUDE.md with new commands**

Add to CLI reference:

```
# Scan state & monitoring
uv run bba db scan-history --program <prog>
uv run bba db scan-status <run_id> --program <prog>
uv run bba db scan-diff <old_id> <new_id> --category subdomains --program <prog>

# Notifications
uv run bba scan notify <message> --program <prog> [--provider-config path]
uv run bba scan notify-findings --program <prog> [--severity medium]

# Scope import
uv run bba scope import-h1 <handle> [--name name] [--output path]
uv run bba scope import-bc <handle> [--name name]

# Dry-run mode (global flag)
uv run bba --dry-run scan nuclei <targets> --program <prog>
```

- [ ] **Step 3: Commit**

```bash
git add .claude/commands/scan-target.md .claude/agents/scanner.md CLAUDE.md
git commit -m "docs: integrate monitoring, notifications, and scope import into agent prompts"
```

---

## Summary

| Task | Component | Impact |
|------|-----------|--------|
| 1 | Scan state tracking (resume + diff) | RELIABILITY — resume failed scans, detect changes |
| 2 | CLI commands for scan state | USABILITY — expose resume/diff via CLI |
| 3 | Notify tool wrapper | NOTIFICATIONS — Slack/Discord/Telegram alerts |
| 4 | Notifier service | NOTIFICATIONS — auto-alert on findings/diffs |
| 5 | Notify CLI + install | INTEGRATION — wire into CLI |
| 6 | Scope importer (H1/BC) | PLATFORM — auto-import program scopes |
| 7 | Scope import CLI | USABILITY — CLI commands for import |
| 8 | Dry-run mode | SAFETY — test commands without execution |
| 9 | CLI modularization | MAINTAINABILITY — split 1500-line monolith |
| 10 | Agent prompt updates | INTELLIGENCE — agents use monitoring features |

### Phase Dependencies

```
Phase 5A (Critical Fixes) ← MUST complete first
  └── Phase 5B (Missing Tools) ← Can run in parallel with 5C
  └── Phase 5C (Monitoring) ← This plan
        ├── Chunk 1: Scan state (no deps)
        ├── Chunk 2: Notifications (no deps)
        ├── Chunk 3: Scope import (no deps)
        ├── Chunk 4: Dry-run + CLI split (no deps between chunks)
        └── Chunk 5: Agent updates (after all chunks)
```
