"""Subdomain takeover detection via subzy (replaces archived subjack)."""
from __future__ import annotations
import json
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner


class SubzyTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, targets: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "subzy_targets.txt"
        input_file.write_text("\n".join(targets) + "\n")
        return ["subzy", "run", "--targets", str(input_file), "--output", "json"]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                if entry.get("vulnerable"):
                    results.append(entry)
            except json.JSONDecodeError:
                continue
        return results

    async def run(self, targets: list[str], work_dir: Path) -> dict:
        domains = [t for t in targets if not t.startswith("http")]
        result = await self.runner.run_command(
            tool="subzy", command=self.build_command(targets, work_dir),
            targets=domains or targets, timeout=300,
        )
        if not result.success:
            return {"total": 0, "vulnerable": [], "error": result.error}
        vulns = self.parse_output(result.output)
        for v in vulns:
            domain = v.get("subdomain", "")
            service = v.get("service", "unknown")
            await self.db.add_finding(
                program=self.program, domain=domain, url=f"https://{domain}",
                vuln_type="subdomain-takeover", severity="high", tool="subzy",
                evidence=f"Service: {service}. CNAME: {v.get('cname', '')}",
                confidence=0.9,
            )
        return {"total": len(vulns), "vulnerable": vulns, "scanned": len(targets)}
