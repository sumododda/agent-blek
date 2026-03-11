"""CRLF injection scanning via crlfuzz."""
from __future__ import annotations
from pathlib import Path
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class CrlfuzzTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["crlfuzz", "-u", url, "-s"]

    def build_command_list(self, urls: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "crlfuzz_input.txt"
        input_file.write_text("\n".join(urls) + "\n")
        return ["crlfuzz", "-l", str(input_file), "-s"]

    def parse_output(self, output: str) -> list[str]:
        return [line.strip() for line in output.strip().splitlines() if line.strip()]

    async def run(self, target: str, work_dir: Path | None = None) -> dict:
        parsed = urlparse(target)
        domain = parsed.hostname or target
        result = await self.runner.run_command(
            tool="crlfuzz", command=self.build_command(target), targets=[domain], timeout=120,
        )
        if not result.success:
            return {"total": 0, "vulnerable": [], "error": result.error}
        vulnerable = self.parse_output(result.output)
        for vuln_url in vulnerable:
            await self.db.add_finding(
                program=self.program, domain=domain, url=vuln_url,
                vuln_type="crlf-injection", severity="medium", tool="crlfuzz",
                evidence=f"CRLF injection confirmed at {vuln_url}", confidence=0.8,
            )
        return {"total": len(vulnerable), "vulnerable": vulnerable}

    async def run_list(self, urls: list[str], work_dir: Path) -> dict:
        domains = list({urlparse(u).hostname for u in urls if urlparse(u).hostname})
        result = await self.runner.run_command(
            tool="crlfuzz", command=self.build_command_list(urls, work_dir),
            targets=domains or ["unknown"], timeout=300,
        )
        if not result.success:
            return {"total": 0, "vulnerable": [], "error": result.error}
        vulnerable = self.parse_output(result.output)
        for vuln_url in vulnerable:
            p = urlparse(vuln_url)
            await self.db.add_finding(
                program=self.program, domain=p.hostname or "", url=vuln_url,
                vuln_type="crlf-injection", severity="medium", tool="crlfuzz",
                evidence=f"CRLF injection confirmed at {vuln_url}", confidence=0.8,
            )
        return {"total": len(vulnerable), "vulnerable": vulnerable, "scanned": len(urls)}
