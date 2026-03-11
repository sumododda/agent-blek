from __future__ import annotations
import json
from bba.db import Database
from bba.tool_runner import ToolRunner

class CrtshTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_url(self, domain: str) -> str:
        return f"https://crt.sh/?q=%25.{domain}&output=json"

    def parse_output(self, output: str) -> list[str]:
        """Extract unique domain names from crt.sh JSON response."""
        domains = set()
        try:
            entries = json.loads(output)
            for entry in entries:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name and not name.startswith("*"):
                        domains.add(name)
        except (json.JSONDecodeError, TypeError):
            pass
        return sorted(domains)

    async def run(self, domain: str) -> dict:
        url = self.build_url(domain)
        result = await self.runner.run_http_request(
            tool="crtsh", url=url, targets=[domain], timeout=30,
        )
        if not result.success:
            return {"total": 0, "domains": [], "error": result.error}
        domains = self.parse_output(result.output)
        if domains:
            await self.db.add_subdomains_bulk(self.program, domains, "crtsh")
        return {"total": len(domains), "domains": domains}
