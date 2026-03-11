"""OS command injection detection via commix."""
from __future__ import annotations
import re
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

_VULN_PATTERN = re.compile(r"(?:is vulnerable|injectable|command injection)", re.I)
_TECHNIQUE_PATTERN = re.compile(r"(?:technique|via)\s*[:\-]\s*(.+)", re.I)


class CommixTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["commix", "--url", url, "--batch", "--output-dir=/dev/null"]

    def is_vulnerable(self, output: str) -> bool:
        return bool(_VULN_PATTERN.search(output))

    def extract_technique(self, output: str) -> str:
        match = _TECHNIQUE_PATTERN.search(output)
        return match.group(1).strip() if match else "unknown"

    async def run(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="commix", command=self.build_command(url),
            targets=[domain] if domain else [url], timeout=300,
        )
        if not result.success:
            return {"vulnerable": False, "url": url, "error": result.error}
        vulnerable = self.is_vulnerable(result.output)
        if vulnerable:
            technique = self.extract_technique(result.output)
            await self.db.add_finding(
                program=self.program, domain=domain, url=url,
                vuln_type="command-injection", severity="critical", tool="commix",
                evidence=f"Technique: {technique}. {result.output[:1000]}",
                confidence=0.9,
            )
        return {"vulnerable": vulnerable, "url": url, "technique": self.extract_technique(result.output) if vulnerable else None}
