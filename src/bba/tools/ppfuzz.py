"""Client-side prototype pollution detection via ppfuzz."""
from __future__ import annotations
from pathlib import Path
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class PpfuzzTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, urls: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "ppfuzz_input.txt"
        input_file.write_text("\n".join(urls) + "\n")
        return ["ppfuzz", "-l", str(input_file)]

    def parse_output(self, output: str) -> list[dict]:
        findings = []
        for line in output.strip().splitlines():
            lower = line.lower()
            if "vulnerable" in lower or "pollut" in lower or "proto" in lower:
                findings.append({"url": line.strip()})
        return findings

    async def run(self, urls: list[str], work_dir: Path) -> dict:
        domains = list({urlparse(u).hostname for u in urls if urlparse(u).hostname})
        result = await self.runner.run_command(
            tool="ppfuzz", command=self.build_command(urls, work_dir),
            targets=domains or ["unknown"], timeout=300,
        )
        if not result.success:
            return {"total": 0, "findings": [], "error": result.error}
        findings = self.parse_output(result.output)
        for f in findings:
            await self.db.add_finding(
                program=self.program, domain=domains[0] if domains else "",
                url=f["url"], vuln_type="prototype-pollution", severity="high",
                tool="ppfuzz", evidence=f["url"], confidence=0.75,
            )
        return {"total": len(findings), "findings": findings, "scanned": len(urls)}
