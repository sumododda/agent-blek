from __future__ import annotations
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner

class HakrevdnsTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, ips: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "hakrevdns_input.txt"
        input_file.write_text("\n".join(ips) + "\n")
        return ["hakrevdns", "-l", str(input_file), "-t", "150"]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0].strip()
                hostname = parts[1].strip().rstrip(".")
                if hostname:
                    results.append({"ip": ip, "hostname": hostname})
        return results

    async def run(self, ips: list[str], work_dir: Path) -> dict:
        result = await self.runner.run_command(
            tool="hakrevdns",
            command=self.build_command(ips, work_dir),
            targets=ips,
            timeout=300,
        )
        if not result.success:
            return {"total": 0, "records": [], "error": result.error}
        entries = self.parse_output(result.output)
        hostnames = list({e["hostname"] for e in entries})
        if hostnames:
            await self.db.add_subdomains_bulk(self.program, hostnames, "hakrevdns")
        return {"total": len(entries), "records": entries, "unique_hostnames": len(hostnames)}
