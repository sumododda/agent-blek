"""Server-Side Template Injection detection via SSTImap."""
from __future__ import annotations
import re
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

_ENGINE_PATTERN = re.compile(r"(?:Identified|Confirmed|Detected).*?(?:engine|injection).*?:\s*(\S+)", re.I)
_VULN_PATTERN = re.compile(r"(?:exploitable|injectable|confirmed|identified)", re.I)


class SstimapTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["sstimap", "-u", url, "--no-color"]

    def parse_output(self, output: str) -> dict:
        engines = _ENGINE_PATTERN.findall(output)
        vulnerable = bool(_VULN_PATTERN.search(output))
        return {"vulnerable": vulnerable, "engines": engines, "raw": output[:2000]}

    async def run(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="sstimap", command=self.build_command(url),
            targets=[domain] if domain else [url], timeout=180,
        )
        if not result.success:
            return {"vulnerable": False, "url": url, "error": result.error}
        parsed_result = self.parse_output(result.output)
        if parsed_result["vulnerable"]:
            engine_str = ", ".join(parsed_result["engines"]) or "unknown"
            await self.db.add_finding(
                program=self.program, domain=domain, url=url,
                vuln_type="ssti", severity="critical", tool="sstimap",
                evidence=f"Template engine: {engine_str}. {parsed_result['raw'][:500]}",
                confidence=0.9,
            )
        return {"vulnerable": parsed_result["vulnerable"], "url": url, "engines": parsed_result["engines"]}
