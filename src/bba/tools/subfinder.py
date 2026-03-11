from __future__ import annotations
import json
from collections import Counter
from bba.db import Database
from bba.tool_runner import ToolRunner

class SubfinderTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, domain: str) -> list[str]:
        return ["subfinder", "-d", domain, "-silent", "-json"]

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

    async def run(self, domain: str) -> dict:
        result = await self.runner.run_command(
            tool="subfinder", command=self.build_command(domain), targets=[domain],
        )
        if not result.success:
            return {"total": 0, "domains": [], "sources": {}, "error": result.error}
        entries = self.parse_output(result.output)
        domains = [e["host"] for e in entries if "host" in e]
        sources = Counter(e.get("source", "unknown") for e in entries)
        if domains:
            await self.db.add_subdomains_bulk(self.program, domains, "subfinder")
        return {"total": len(domains), "domains": domains, "sources": dict(sources)}
