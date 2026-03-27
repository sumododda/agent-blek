from __future__ import annotations

from pathlib import Path

from bba.db import Database
from bba.tool_runner import ToolRunner


class NaabuTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(
        self,
        targets: list[str],
        work_dir: Path,
        ports: str = "top-1000",
        scan_type: str = "connect",
    ) -> list[str]:
        input_file = work_dir / "naabu_input.txt"
        input_file.write_text("\n".join(targets) + "\n")
        cmd = ["naabu", "-list", str(input_file), "-json", "-silent"]
        if ports == "all":
            cmd.extend(["-p", "-"])
        elif ports == "top-1000":
            cmd.extend(["-top-ports", "1000"])
        else:
            cmd.extend(["-p", ports])
        if scan_type == "connect":
            cmd.extend(["-scan-type", "c"])
        return cmd

    def parse_output(self, output: str) -> list[dict]:
        return self.runner.parse_jsonl(output)

    async def run(
        self,
        targets: list[str],
        work_dir: Path,
        ports: str = "top-1000",
        scan_type: str = "connect",
    ) -> dict:
        result = await self.runner.run_command(
            tool="naabu",
            command=self.build_command(targets, work_dir, ports, scan_type),
            targets=targets,
            timeout=900,
        )
        if not result.success:
            return {"total": 0, "ports": [], "error": result.error}
        entries = self.parse_output(result.output)
        port_records = []
        for entry in entries:
            port_records.append({
                "domain": entry.get("host", ""),
                "ip": entry.get("ip", entry.get("host", "")),
                "port": entry.get("port", 0),
                "protocol": entry.get("protocol", "tcp"),
                "service": "",
                "version": "",
            })
        if port_records:
            await self.db.add_ports_bulk(self.program, port_records, "naabu")
        return {
            "total": len(port_records),
            "ports": [
                {"host": p["domain"], "ip": p["ip"], "port": p["port"]}
                for p in port_records
            ],
        }
