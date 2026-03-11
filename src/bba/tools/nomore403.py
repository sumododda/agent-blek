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
