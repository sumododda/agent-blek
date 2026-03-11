from __future__ import annotations
from bba.db import Database
from bba.tool_runner import ToolRunner

class BrutesprayTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, nmap_xml: str, threads: int = 5) -> list[str]:
        return ["brutespray", "-f", nmap_xml, "--threads", str(threads), "-q"]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            if "SUCCESS" in line.upper() or "ACCOUNT FOUND" in line.upper():
                results.append({"line": line, "success": True})
        return results

    async def run(self, nmap_xml: str, domain: str = "") -> dict:
        target = domain or nmap_xml
        result = await self.runner.run_command(
            tool="brutespray",
            command=self.build_command(nmap_xml),
            targets=[target],
            timeout=600,
        )
        if not result.success:
            return {"total": 0, "results": [], "error": result.error}
        entries = self.parse_output(result.output)
        for entry in entries:
            await self.db.add_finding(
                self.program, target, "",
                "weak-credentials", "critical", "brutespray",
                entry["line"], 0.95,
            )
        return {"total": len(entries), "results": entries}
