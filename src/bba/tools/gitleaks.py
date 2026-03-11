from __future__ import annotations
import json
from bba.db import Database
from bba.tool_runner import ToolRunner

class GitleaksTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, source_path: str) -> list[str]:
        return [
            "gitleaks", "detect", "--source", source_path,
            "--report-format", "json", "--report-path", "/dev/stdout",
            "--no-banner",
        ]

    def parse_output(self, output: str) -> list[dict]:
        try:
            data = json.loads(output)
            if isinstance(data, list):
                return data
            return [data]
        except json.JSONDecodeError:
            return []

    async def run(self, source_path: str) -> dict:
        result = await self.runner.run_command(
            tool="gitleaks",
            command=self.build_command(source_path),
            targets=[source_path],
            timeout=300,
        )
        # gitleaks exits with code 1 when leaks are found, so check output even on failure
        output_to_parse = result.output
        entries = self.parse_output(output_to_parse)
        secrets = []
        for entry in entries:
            rule_id = entry.get("RuleID", entry.get("ruleID", "unknown"))
            match_val = entry.get("Match", entry.get("match", ""))
            file_path = entry.get("File", entry.get("file", ""))
            secrets.append({
                "type": rule_id,
                "match": match_val[:100],
                "file": file_path,
            })
            await self.db.add_secret(
                self.program, rule_id, match_val[:200],
                source_url=None, source_file=file_path,
                tool="gitleaks", confidence=0.7,
            )
        return {"total": len(secrets), "secrets": secrets}
