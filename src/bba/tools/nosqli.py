"""NoSQL injection detection via nosqli."""
from __future__ import annotations
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class NosqliTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["nosqli", "scan", "-t", url]

    def parse_output(self, output: str) -> list[dict]:
        findings = []
        for line in output.strip().splitlines():
            lower = line.lower()
            if "vulnerable" in lower or "injection" in lower:
                findings.append({"detail": line.strip()})
        return findings

    async def run(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="nosqli", command=self.build_command(url),
            targets=[domain] if domain else [url], timeout=120,
        )
        if not result.success:
            return {"vulnerable": False, "url": url, "error": result.error}
        findings = self.parse_output(result.output)
        if findings:
            await self.db.add_finding(
                program=self.program, domain=domain, url=url,
                vuln_type="nosql-injection", severity="high", tool="nosqli",
                evidence="; ".join(f["detail"] for f in findings)[:2000],
                confidence=0.85,
            )
        return {"vulnerable": bool(findings), "url": url, "findings": findings}
