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


class ScanState:
    def __init__(self, db: Database):
        self.db = db

    async def initialize(self):
        await self.db._conn.executescript(SCAN_STATE_SCHEMA)
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
