"""XSS detection via XSStrike with WAF bypass and context analysis."""
from __future__ import annotations
import re
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

_VULN_PATTERN = re.compile(r"(?:Vulnerable|XSS confirmed|Payload:)\s*(.*)", re.I)
_WAF_PATTERN = re.compile(r"WAF detected:\s*(.+)", re.I)


class XSStrikeTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str, blind: bool = False, crawl: bool = False) -> list[str]:
        cmd = ["xsstrike", "-u", url, "--skip"]
        if blind:
            cmd.append("--blind")
        if crawl:
            cmd.extend(["--crawl", "-l", "2"])
        return cmd

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for match in _VULN_PATTERN.finditer(output):
            results.append({"payload": match.group(1).strip()})
        return results

    def detect_waf(self, output: str) -> str | None:
        match = _WAF_PATTERN.search(output)
        return match.group(1).strip() if match else None

    async def run(self, url: str, blind: bool = False, crawl: bool = False) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="xsstrike", command=self.build_command(url, blind, crawl),
            targets=[domain] if domain else [url], timeout=180,
        )
        if not result.success:
            return {"vulnerable": False, "url": url, "error": result.error}
        findings = self.parse_output(result.output)
        waf = self.detect_waf(result.output)
        for f in findings:
            await self.db.add_finding(
                program=self.program, domain=domain, url=url,
                vuln_type="xss", severity="high", tool="xsstrike",
                evidence=f"Payload: {f['payload']}" + (f", WAF: {waf}" if waf else ""),
                confidence=0.85,
            )
        return {"vulnerable": bool(findings), "url": url, "findings": findings, "waf": waf}
