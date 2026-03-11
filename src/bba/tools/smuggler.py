"""HTTP request smuggling detection via smuggler."""
from __future__ import annotations
import re
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

_VULN_PATTERN = re.compile(r"(?:VULNERABLE|DESYNC|smuggl)", re.I)
_TECHNIQUE_PATTERN = re.compile(r"(CL\.TE|TE\.CL|TE\.TE|H2\.CL|H2\.TE)", re.I)


class SmugglerTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["python3", "-m", "smuggler", "-u", url, "-q"]

    def parse_output(self, output: str) -> list[dict]:
        findings = []
        for line in output.strip().splitlines():
            if _VULN_PATTERN.search(line):
                technique = _TECHNIQUE_PATTERN.search(line)
                findings.append({
                    "detail": line.strip(),
                    "technique": technique.group(1) if technique else "unknown",
                })
        return findings

    async def run(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="smuggler", command=self.build_command(url),
            targets=[domain] if domain else [url], timeout=120,
        )
        if not result.success:
            return {"vulnerable": False, "url": url, "error": result.error}
        findings = self.parse_output(result.output)
        for f in findings:
            await self.db.add_finding(
                program=self.program, domain=domain, url=url,
                vuln_type="http-smuggling", severity="critical", tool="smuggler",
                evidence=f"Technique: {f['technique']}. {f['detail']}", confidence=0.85,
            )
        return {"vulnerable": bool(findings), "url": url, "findings": findings}
