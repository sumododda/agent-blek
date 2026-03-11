"""Advanced SQL injection detection via ghauri."""
from __future__ import annotations
import re
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

_VULN_PATTERN = re.compile(r"(?:is vulnerable|Parameter.*injectable|SQL injection)", re.I)
_PARAM_PATTERN = re.compile(r"Parameter:\s*['\"]?(\w+)", re.I)
_TECHNIQUE_PATTERN = re.compile(r"Type:\s*(.+)", re.I)


class GhauriTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str, level: int = 2, technique: str | None = None) -> list[str]:
        cmd = ["ghauri", "-u", url, "--batch", "--level", str(level)]
        if technique:
            cmd.extend(["--technique", technique])
        return cmd

    def is_vulnerable(self, output: str) -> bool:
        return bool(_VULN_PATTERN.search(output))

    async def run(self, url: str, level: int = 2, technique: str | None = None) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="ghauri", command=self.build_command(url, level, technique),
            targets=[domain] if domain else [url], timeout=300,
        )
        if not result.success:
            return {"vulnerable": False, "url": url, "error": result.error}
        vulnerable = self.is_vulnerable(result.output)
        if vulnerable:
            param = _PARAM_PATTERN.search(result.output)
            tech = _TECHNIQUE_PATTERN.search(result.output)
            await self.db.add_finding(
                program=self.program, domain=domain, url=url,
                vuln_type="sql-injection", severity="critical", tool="ghauri",
                evidence=f"Param: {param.group(1) if param else 'unknown'}, Type: {tech.group(1) if tech else 'unknown'}. {result.output[:1000]}",
                confidence=0.9,
            )
        return {"vulnerable": vulnerable, "url": url, "output_preview": result.output[:500]}
