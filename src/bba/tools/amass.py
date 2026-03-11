from __future__ import annotations
import json
from bba.db import Database
from bba.tool_runner import ToolRunner

class AmassTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, domain: str) -> list[str]:
        return ["amass", "enum", "-d", domain, "-json", "-silent"]

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
            tool="amass", command=self.build_command(domain), targets=[domain],
            timeout=900,
        )
        if not result.success:
            return {"total": 0, "domains": [], "error": result.error}
        entries = self.parse_output(result.output)
        domains = list({e["name"] for e in entries if "name" in e})
        if domains:
            await self.db.add_subdomains_bulk(self.program, domains, "amass")
        return {"total": len(domains), "domains": sorted(domains)}
