from __future__ import annotations

import xml.etree.ElementTree as ET

from bba.db import Database
from bba.tool_runner import ToolRunner


class NmapTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, target: str, ports: str) -> list[str]:
        return ["nmap", "-sV", "-p", ports, target, "-oX", "-"]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        try:
            root = ET.fromstring(output)
            for host_elem in root.findall(".//host"):
                addr_elem = host_elem.find("address")
                ip = addr_elem.get("addr", "") if addr_elem is not None else ""
                hostname = ""
                hostname_elem = host_elem.find(".//hostname")
                if hostname_elem is not None:
                    hostname = hostname_elem.get("name", "")
                for port_elem in host_elem.findall(".//port"):
                    state_elem = port_elem.find("state")
                    if state_elem is not None and state_elem.get("state") != "open":
                        continue
                    service_elem = port_elem.find("service")
                    results.append({
                        "ip": ip,
                        "hostname": hostname,
                        "port": int(port_elem.get("portid", 0)),
                        "protocol": port_elem.get("protocol", "tcp"),
                        "service": (
                            service_elem.get("name", "")
                            if service_elem is not None
                            else ""
                        ),
                        "version": (
                            f"{service_elem.get('product', '')} {service_elem.get('version', '')}".strip()
                            if service_elem is not None
                            else ""
                        ),
                    })
        except ET.ParseError:
            pass
        return results

    async def run(self, target: str, ports: str) -> dict:
        result = await self.runner.run_command(
            tool="nmap",
            command=self.build_command(target, ports),
            targets=[target],
            timeout=600,
        )
        if not result.success:
            return {"total": 0, "services": [], "error": result.error}
        entries = self.parse_output(result.output)
        for entry in entries:
            await self.db.add_port(
                self.program,
                entry["hostname"] or target,
                entry["ip"],
                entry["port"],
                entry["protocol"],
                entry["service"],
                entry["version"],
                "nmap",
            )
        return {
            "total": len(entries),
            "services": entries,
        }
