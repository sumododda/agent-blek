from __future__ import annotations
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner

class KatanaTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, targets: list[str], work_dir: Path) -> list[str]:
        input_file = self.runner.create_input_file(targets, work_dir, filename="katana_input.txt")
        return ["katana", "-list", str(input_file), "-silent", "-json"]

    def parse_output(self, output: str) -> list[str]:
        urls = []
        for entry in self.runner.parse_jsonl(output):
            endpoint = entry.get("request", {}).get("endpoint", "")
            if endpoint:
                urls.append(endpoint)
        return urls

    async def run(self, targets: list[str], work_dir: Path) -> dict:
        from urllib.parse import urlparse
        domains = []
        for t in targets:
            parsed = urlparse(t)
            if parsed.hostname:
                domains.append(parsed.hostname)
        result = await self.runner.run_command(
            tool="katana", command=self.build_command(targets, work_dir), targets=domains or targets,
        )
        if not result.success:
            return {"total": 0, "urls": [], "error": result.error}
        urls = self.parse_output(result.output)
        return {"total": len(urls), "urls": urls}
