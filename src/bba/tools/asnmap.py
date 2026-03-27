from __future__ import annotations
from bba.db import Database
from bba.tool_runner import ToolRunner

class AsnmapTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, domain: str) -> list[str]:
        return ["asnmap", "-d", domain, "-json", "-silent"]

    def parse_output(self, output: str) -> list[dict]:
        return self.runner.parse_jsonl(output)

    async def run(self, domain: str) -> dict:
        result = await self.runner.run_command(
            tool="asnmap",
            command=self.build_command(domain),
            targets=[domain],
        )
        if not result.success:
            return {"total": 0, "ranges": [], "error": result.error}
        entries = self.parse_output(result.output)
        ranges = []
        for entry in entries:
            ranges.append({
                "as_number": entry.get("as_number", ""),
                "as_name": entry.get("as_name", ""),
                "as_country": entry.get("as_country", ""),
                "as_range": entry.get("as_range", ""),
            })
        await self.db.log_action(
            "asn_mapping", "asnmap", domain,
            f"Found {len(ranges)} IP ranges across {len({r['as_number'] for r in ranges})} ASNs",
        )
        return {"total": len(ranges), "ranges": ranges}
