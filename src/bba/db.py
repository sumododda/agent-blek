from __future__ import annotations

from pathlib import Path

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    domain TEXT NOT NULL,
    source TEXT NOT NULL,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program, domain)
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    domain TEXT NOT NULL,
    ip TEXT,
    port INTEGER,
    status_code INTEGER,
    title TEXT,
    technologies TEXT,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program, domain, port)
);

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
    validated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    tool TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_subdomains_program ON subdomains(program);
CREATE INDEX IF NOT EXISTS idx_services_program ON services(program);
CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(program);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
"""


class Database:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    async def initialize(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA)
        await self._conn.commit()

    async def close(self):
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def list_tables(self) -> list[str]:
        cursor = await self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        rows = await cursor.fetchall()
        return [row[0] for row in rows]

    async def add_subdomain(self, program: str, domain: str, source: str) -> None:
        await self._conn.execute(
            "INSERT OR IGNORE INTO subdomains (program, domain, source) VALUES (?, ?, ?)",
            (program, domain, source),
        )
        await self._conn.commit()

    async def add_subdomains_bulk(self, program: str, domains: list[str], source: str) -> int:
        rows = [(program, d, source) for d in domains]
        await self._conn.executemany(
            "INSERT OR IGNORE INTO subdomains (program, domain, source) VALUES (?, ?, ?)",
            rows,
        )
        await self._conn.commit()
        return len(domains)

    async def get_subdomains(self, program: str) -> list[dict]:
        cursor = await self._conn.execute(
            "SELECT * FROM subdomains WHERE program = ? ORDER BY domain",
            (program,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def add_service(
        self, program: str, domain: str, ip: str, port: int,
        status_code: int, title: str, technologies: str,
    ) -> None:
        await self._conn.execute(
            """INSERT INTO services (program, domain, ip, port, status_code, title, technologies)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(program, domain, port) DO UPDATE SET
                 ip=excluded.ip, status_code=excluded.status_code,
                 title=excluded.title, technologies=excluded.technologies""",
            (program, domain, ip, port, status_code, title, technologies),
        )
        await self._conn.commit()

    async def get_services(self, program: str) -> list[dict]:
        cursor = await self._conn.execute(
            "SELECT * FROM services WHERE program = ? ORDER BY domain",
            (program,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def add_finding(
        self, program: str, domain: str, url: str, vuln_type: str,
        severity: str, tool: str, evidence: str, confidence: float,
    ) -> int:
        cursor = await self._conn.execute(
            """INSERT INTO findings (program, domain, url, vuln_type, severity, tool, evidence, confidence)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (program, domain, url, vuln_type, severity, tool, evidence, confidence),
        )
        await self._conn.commit()
        return cursor.lastrowid

    async def update_finding_status(self, finding_id: int, status: str) -> None:
        await self._conn.execute(
            "UPDATE findings SET status = ?, validated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (status, finding_id),
        )
        await self._conn.commit()

    async def get_findings(
        self, program: str, severity: str | None = None, status: str | None = None,
    ) -> list[dict]:
        query = "SELECT * FROM findings WHERE program = ?"
        params: list = [program]
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        cursor = await self._conn.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def log_action(self, action: str, tool: str, target: str, details: str) -> None:
        await self._conn.execute(
            "INSERT INTO audit_log (action, tool, target, details) VALUES (?, ?, ?, ?)",
            (action, tool, target, details),
        )
        await self._conn.commit()

    async def get_audit_log(self, limit: int = 50) -> list[dict]:
        cursor = await self._conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC, id DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_program_summary(self, program: str) -> dict:
        result = {}
        for table in ("subdomains", "services", "findings"):
            cursor = await self._conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE program = ?",
                (program,),
            )
            row = await cursor.fetchone()
            result[table] = row[0]
        return result
