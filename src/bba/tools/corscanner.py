"""CORS misconfiguration detection via CORScanner."""
from __future__ import annotations
import json
from pathlib import Path
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class CORScannerTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["python3", "-m", "CORScanner.cors_scan", "-u", url, "-q"]

    def build_command_list(self, urls: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "cors_input.txt"
        input_file.write_text("\n".join(urls) + "\n")
        return ["python3", "-m", "CORScanner.cors_scan", "-i", str(input_file), "-q"]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            try:
                entry = json.loads(line)
                if entry.get("vulnerable"):
                    results.append(entry)
            except json.JSONDecodeError:
                if "vulnerable" in line.lower() or "misconfigured" in line.lower():
                    results.append({"url": line.strip(), "type": "cors-misconfiguration"})
        return results

    async def run(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="corscanner", command=self.build_command(url),
            targets=[domain] if domain else [url], timeout=60,
        )
        if not result.success:
            return {"total": 0, "findings": [], "error": result.error}
        findings = self.parse_output(result.output)
        for f in findings:
            severity = "critical" if f.get("credentials") else "medium"
            await self.db.add_finding(
                program=self.program, domain=domain, url=f.get("url", url),
                vuln_type="cors-misconfiguration", severity=severity, tool="corscanner",
                evidence=json.dumps(f)[:2000], confidence=0.85,
            )
        return {"total": len(findings), "findings": findings}
