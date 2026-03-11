from __future__ import annotations
import json
from bba.db import Database
from bba.tool_runner import ToolRunner

class UncoverTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, query: str, engines: str = "shodan,censys,fofa") -> list[str]:
        return ["uncover", "-q", query, "-json", "-silent", "-e", engines]

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

    async def run(self, query: str, engines: str = "shodan,censys,fofa") -> dict:
        result = await self.runner.run_command(
            tool="uncover",
            command=self.build_command(query, engines),
            targets=[query],
            timeout=120,
        )
        if not result.success:
            return {"total": 0, "results": [], "error": result.error}
        entries = self.parse_output(result.output)
        hosts = []
        for entry in entries:
            host = entry.get("host", "")
            ip = entry.get("ip", host)
            port = entry.get("port", 0)
            if host:
                hosts.append({"host": host, "ip": ip, "port": port})
                if port:
                    await self.db.add_port(
                        self.program, host, ip, port, "tcp", "", "", "uncover",
                    )
        return {"total": len(hosts), "results": hosts}
