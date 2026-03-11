from __future__ import annotations
import json
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner

class KatanaTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, targets: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "katana_input.txt"
        input_file.write_text("\n".join(targets) + "\n")
        return ["katana", "-list", str(input_file), "-silent", "-json"]

    def parse_output(self, output: str) -> list[str]:
        urls = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                endpoint = data.get("request", {}).get("endpoint", "")
                if endpoint:
                    urls.append(endpoint)
            except json.JSONDecodeError:
                continue
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
