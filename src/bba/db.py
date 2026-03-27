from __future__ import annotations

from contextlib import asynccontextmanager
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
    validated_at TIMESTAMP,
    validation_reason TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    tool TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    domain TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    service TEXT,
    version TEXT,
    source TEXT NOT NULL,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program, ip, port, protocol)
);

CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    url TEXT NOT NULL,
    source TEXT NOT NULL,
    status_code INTEGER,
    content_type TEXT,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program, url)
);

CREATE TABLE IF NOT EXISTS js_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    url TEXT NOT NULL,
    source_page TEXT,
    endpoints_extracted INTEGER DEFAULT 0,
    secrets_found INTEGER DEFAULT 0,
    analyzed_at TIMESTAMP,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program, url)
);

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

CREATE TABLE IF NOT EXISTS screenshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    url TEXT NOT NULL,
    file_path TEXT NOT NULL,
    status_code INTEGER,
    title TEXT,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program, url)
);

CREATE INDEX IF NOT EXISTS idx_subdomains_program ON subdomains(program);
CREATE INDEX IF NOT EXISTS idx_services_program ON services(program);
CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(program);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_ports_program ON ports(program);
CREATE INDEX IF NOT EXISTS idx_urls_program ON urls(program);
CREATE INDEX IF NOT EXISTS idx_js_files_program ON js_files(program);
CREATE INDEX IF NOT EXISTS idx_secrets_program ON secrets(program);
CREATE INDEX IF NOT EXISTS idx_screenshots_program ON screenshots(program);
CREATE INDEX IF NOT EXISTS idx_audit_log_tool ON audit_log(tool);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target);

CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup ON findings(program, url, vuln_type);

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
"""


class Database:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._conn: aiosqlite.Connection | None = None
        self._batch_mode: bool = False

    async def initialize(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA)
        await self._conn.commit()

        # Migration: add validation_reason if missing
        try:
            await self._conn.execute("ALTER TABLE findings ADD COLUMN validation_reason TEXT")
            await self._conn.commit()
        except Exception:
            pass

    async def close(self):
        if self._conn:
            await self._conn.close()
            self._conn = None

    @asynccontextmanager
    async def batch(self):
        self._batch_mode = True
        try:
            yield
        finally:
            self._batch_mode = False
            await self._conn.commit()

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
        if not self._batch_mode:
            await self._conn.commit()

    async def add_subdomains_bulk(self, program: str, domains: list[str], source: str) -> int:
        rows = [(program, d, source) for d in domains]
        await self._conn.executemany(
            "INSERT OR IGNORE INTO subdomains (program, domain, source) VALUES (?, ?, ?)",
            rows,
        )
        if not self._batch_mode:
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
        if not self._batch_mode:
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
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(program, url, vuln_type) DO UPDATE SET
                 evidence = CASE WHEN LENGTH(findings.evidence) < 50000
                           THEN findings.evidence || '; ' || excluded.evidence
                           ELSE findings.evidence END,
                 confidence = MAX(findings.confidence, excluded.confidence),
                 tool = CASE WHEN ',' || findings.tool || ',' NOT LIKE '%,' || excluded.tool || ',%'
                        THEN findings.tool || ',' || excluded.tool
                        ELSE findings.tool END""",
            (program, domain, url, vuln_type, severity, tool, evidence, confidence),
        )
        if not self._batch_mode:
            await self._conn.commit()
        return cursor.lastrowid

    async def update_finding_status(self, finding_id: int, status: str, reason: str | None = None) -> None:
        await self._conn.execute(
            "UPDATE findings SET status = ?, validated_at = CURRENT_TIMESTAMP, validation_reason = ? WHERE id = ?",
            (status, reason, finding_id),
        )
        if not self._batch_mode:
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
        if not self._batch_mode:
            await self._conn.commit()

    async def get_audit_log(self, limit: int = 50) -> list[dict]:
        cursor = await self._conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC, id DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # --- Ports ---

    async def add_port(
        self, program: str, domain: str, ip: str, port: int,
        protocol: str, service: str, version: str, source: str,
    ) -> None:
        await self._conn.execute(
            """INSERT OR IGNORE INTO ports
               (program, domain, ip, port, protocol, service, version, source)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (program, domain, ip, port, protocol, service, version, source),
        )
        if not self._batch_mode:
            await self._conn.commit()

    async def add_ports_bulk(self, program: str, ports: list[dict], source: str) -> int:
        rows = [
            (program, p["domain"], p["ip"], p["port"], p.get("protocol", "tcp"),
             p.get("service"), p.get("version"), source)
            for p in ports
        ]
        await self._conn.executemany(
            """INSERT OR IGNORE INTO ports
               (program, domain, ip, port, protocol, service, version, source)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        if not self._batch_mode:
            await self._conn.commit()
        return len(ports)

    async def get_ports(self, program: str) -> list[dict]:
        cursor = await self._conn.execute(
            "SELECT * FROM ports WHERE program = ? ORDER BY ip, port",
            (program,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # --- URLs ---

    async def add_url(
        self, program: str, url: str, source: str,
        status_code: int | None = None, content_type: str | None = None,
    ) -> None:
        await self._conn.execute(
            """INSERT OR IGNORE INTO urls
               (program, url, source, status_code, content_type)
               VALUES (?, ?, ?, ?, ?)""",
            (program, url, source, status_code, content_type),
        )
        if not self._batch_mode:
            await self._conn.commit()

    async def add_urls_bulk(self, program: str, urls: list[str], source: str) -> int:
        rows = [(program, u, source) for u in urls]
        await self._conn.executemany(
            "INSERT OR IGNORE INTO urls (program, url, source) VALUES (?, ?, ?)",
            rows,
        )
        if not self._batch_mode:
            await self._conn.commit()
        return len(urls)

    async def get_urls(self, program: str, source: str | None = None) -> list[dict]:
        query = "SELECT * FROM urls WHERE program = ?"
        params: list = [program]
        if source:
            query += " AND source = ?"
            params.append(source)
        query += " ORDER BY url"
        cursor = await self._conn.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # --- JS Files ---

    async def add_js_file(self, program: str, url: str, source_page: str | None = None) -> None:
        await self._conn.execute(
            "INSERT OR IGNORE INTO js_files (program, url, source_page) VALUES (?, ?, ?)",
            (program, url, source_page),
        )
        if not self._batch_mode:
            await self._conn.commit()

    async def update_js_file(
        self, program: str, url: str, endpoints_extracted: int, secrets_found: int,
    ) -> None:
        await self._conn.execute(
            """UPDATE js_files SET endpoints_extracted = ?, secrets_found = ?,
               analyzed_at = CURRENT_TIMESTAMP WHERE program = ? AND url = ?""",
            (endpoints_extracted, secrets_found, program, url),
        )
        if not self._batch_mode:
            await self._conn.commit()

    async def get_js_files(self, program: str, analyzed: bool | None = None) -> list[dict]:
        query = "SELECT * FROM js_files WHERE program = ?"
        params: list = [program]
        if analyzed is True:
            query += " AND analyzed_at IS NOT NULL"
        elif analyzed is False:
            query += " AND analyzed_at IS NULL"
        query += " ORDER BY url"
        cursor = await self._conn.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # --- Secrets ---

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
        if not self._batch_mode:
            await self._conn.commit()

    async def get_secrets(self, program: str, status: str | None = None) -> list[dict]:
        query = "SELECT * FROM secrets WHERE program = ?"
        params: list = [program]
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY discovered_at DESC"
        cursor = await self._conn.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # --- Screenshots ---

    async def add_screenshot(
        self, program: str, url: str, file_path: str,
        status_code: int | None = None, title: str | None = None,
    ) -> None:
        await self._conn.execute(
            """INSERT OR IGNORE INTO screenshots
               (program, url, file_path, status_code, title)
               VALUES (?, ?, ?, ?, ?)""",
            (program, url, file_path, status_code, title),
        )
        if not self._batch_mode:
            await self._conn.commit()

    async def get_screenshots(self, program: str) -> list[dict]:
        cursor = await self._conn.execute(
            "SELECT * FROM screenshots WHERE program = ? ORDER BY url",
            (program,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # --- Export ---

    async def export_findings(self, program: str, fmt: str = "json") -> str:
        findings = await self.get_findings(program)
        if fmt == "json":
            import json
            return json.dumps(findings, indent=2, default=str)
        elif fmt == "csv":
            import csv
            import io
            if not findings:
                return ""
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=findings[0].keys())
            writer.writeheader()
            writer.writerows(findings)
            return output.getvalue()
        raise ValueError(f"Unsupported format: {fmt}")

    # --- Stats ---

    async def get_finding_stats(self, program: str) -> dict:
        by_severity: dict[str, int] = {}
        cursor = await self._conn.execute(
            "SELECT severity, COUNT(*) FROM findings WHERE program = ? GROUP BY severity",
            (program,),
        )
        for row in await cursor.fetchall():
            by_severity[row[0]] = row[1]

        by_tool: dict[str, int] = {}
        cursor = await self._conn.execute(
            "SELECT tool, COUNT(*) FROM findings WHERE program = ? GROUP BY tool",
            (program,),
        )
        for row in await cursor.fetchall():
            by_tool[row[0]] = row[1]

        total = sum(by_severity.values())
        return {"by_severity": by_severity, "by_tool": by_tool, "total": total}

    # --- Summary ---

    async def get_program_summary(self, program: str) -> dict:
        result = {}
        for table in ("subdomains", "services", "findings", "ports", "urls", "js_files", "secrets", "screenshots"):
            cursor = await self._conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE program = ?",
                (program,),
            )
            row = await cursor.fetchone()
            result[table] = row[0]
        return result

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
