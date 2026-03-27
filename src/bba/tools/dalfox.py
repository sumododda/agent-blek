from __future__ import annotations
import json
from bba.db import Database
from bba.tool_runner import ToolRunner

class DalfoxTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, target_url: str) -> list[str]:
        return ["dalfox", "url", target_url, "--silence", "--format", "json"]

    def build_command_pipe(self, targets_file: str) -> list[str]:
        """Build command for pipe mode — reads URLs from file for mass scanning."""
        return ["dalfox", "file", targets_file, "--silence", "--format", "json"]

    def parse_output(self, output: str) -> list[dict]:
        return self.runner.parse_jsonl(output)

    async def run(self, target_url: str) -> dict:
        domain = self.runner.extract_domain(target_url)
        result = await self.runner.run_command(tool="dalfox", command=self.build_command(target_url), targets=[domain] if domain else [target_url])
        if not result.success:
            return {"total": 0, "findings": [], "error": result.error}
        entries = self.parse_output(result.output)
        for entry in entries:
            await self.db.add_finding(program=self.program, domain=domain, url=entry.get("data", target_url), vuln_type="xss", severity="high", tool="dalfox", evidence=f"param={entry.get('param', '')}, payload={entry.get('payload', '')}, type={entry.get('inject_type', '')}", confidence=0.85)
        return {"total": len(entries), "findings": [{"param": e.get("param"), "payload": e.get("payload"), "url": e.get("data")} for e in entries]}
