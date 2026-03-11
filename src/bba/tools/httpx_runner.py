from __future__ import annotations
import json
from collections import Counter
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner

class HttpxTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, domains: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "httpx_input.txt"
        input_file.write_text("\n".join(domains) + "\n")
        return ["httpx", "-l", str(input_file), "-silent", "-json", "-nc"]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results

    async def run(self, domains: list[str], work_dir: Path) -> dict:
        result = await self.runner.run_command(
            tool="httpx", command=self.build_command(domains, work_dir), targets=domains,
        )
        if not result.success:
            return {"live": 0, "services": [], "technologies": {}, "error": result.error}
        entries = self.parse_output(result.output)
        tech_counter: Counter = Counter()
        for entry in entries:
            domain = entry.get("input", "")
            ip = entry.get("host", "")
            port = int(entry.get("port", 0))
            status_code = entry.get("status_code", 0)
            title = entry.get("title", "")
            techs = entry.get("tech", [])
            tech_str = ",".join(techs) if techs else ""
            for t in techs:
                tech_counter[t.lower()] += 1
            if domain:
                await self.db.add_service(self.program, domain, ip, port, status_code, title, tech_str)
        return {"live": len(entries), "services": [e.get("input", "") for e in entries], "technologies": dict(tech_counter)}
