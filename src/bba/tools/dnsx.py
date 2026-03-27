from __future__ import annotations
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner

class DnsxTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, domains: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "dnsx_input.txt"
        input_file.write_text("\n".join(domains) + "\n")
        return ["dnsx", "-l", str(input_file), "-json", "-silent", "-a", "-aaaa", "-cname", "-resp"]

    def parse_output(self, output: str) -> list[dict]:
        return self.runner.parse_jsonl(output)

    async def run(self, domains: list[str], work_dir: Path) -> dict:
        result = await self.runner.run_command(
            tool="dnsx",
            command=self.build_command(domains, work_dir),
            targets=domains,
        )
        if not result.success:
            return {"resolved": 0, "records": [], "error": result.error}
        entries = self.parse_output(result.output)
        resolved = []
        for entry in entries:
            host = entry.get("host", "")
            a_records = entry.get("a", [])
            cnames = entry.get("cname", [])
            for ip in a_records:
                await self.db.add_port(
                    self.program, host, ip, 0, "tcp", "dns-resolved", "", "dnsx",
                )
            for cname in cnames:
                await self.db.add_subdomain(self.program, cname, "dnsx-cname")
            if host:
                resolved.append({"host": host, "a": a_records, "cname": cnames})
        return {"resolved": len(resolved), "records": resolved}
