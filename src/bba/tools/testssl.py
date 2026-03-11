from __future__ import annotations
import json
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "OK": "info",
    "WARN": "medium",
}

class TestsslTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["testssl", "--jsonfile", "/dev/stdout", "--quiet", url]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        try:
            data = json.loads(output)
            if isinstance(data, list):
                for entry in data:
                    severity = entry.get("severity", "INFO")
                    if severity in ("OK", "INFO"):
                        continue
                    results.append({
                        "id": entry.get("id", ""),
                        "finding": entry.get("finding", ""),
                        "severity": SEVERITY_MAP.get(severity, "info"),
                        "cve": entry.get("cve", ""),
                        "cwe": entry.get("cwe", ""),
                    })
        except json.JSONDecodeError:
            pass
        return results

    async def run(self, url: str) -> dict:
        domain = urlparse(url).hostname or url
        result = await self.runner.run_command(
            tool="testssl",
            command=self.build_command(url),
            targets=[domain],
            timeout=600,
        )
        if not result.success:
            return {"total": 0, "findings": [], "error": result.error}
        entries = self.parse_output(result.output)
        for entry in entries:
            await self.db.add_finding(
                self.program, domain, url,
                f"tls-{entry['id']}", entry["severity"], "testssl",
                f"{entry['finding']}" + (f" (CVE: {entry['cve']})" if entry["cve"] else ""),
                0.9,
            )
        return {"total": len(entries), "findings": entries}
