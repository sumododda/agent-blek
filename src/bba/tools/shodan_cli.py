from __future__ import annotations
import json
import os
from urllib.parse import quote_plus
from bba.db import Database
from bba.tool_runner import ToolRunner

class ShodanTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_url(self, query: str) -> str:
        api_key = os.environ.get("SHODAN_API_KEY", "")
        return f"https://api.shodan.io/shodan/host/search?key={api_key}&query={quote_plus(query)}"

    def parse_output(self, output: str) -> dict:
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return {}

    async def run(self, query: str, domain: str = "") -> dict:
        api_key = os.environ.get("SHODAN_API_KEY")
        if not api_key:
            return {"total": 0, "results": [], "error": "SHODAN_API_KEY not set"}
        target = domain or query
        url = self.build_url(query)
        result = await self.runner.run_http_request(
            tool="shodan", url=url, targets=[target], timeout=30,
        )
        if not result.success:
            return {"total": 0, "results": [], "error": result.error}
        data = self.parse_output(result.output)
        matches = data.get("matches", [])
        hosts = []
        for match in matches:
            ip = match.get("ip_str", "")
            port = match.get("port", 0)
            transport = match.get("transport", "tcp")
            product = match.get("product", "")
            version = match.get("version", "")
            hostnames = match.get("hostnames", [])
            host_domain = hostnames[0] if hostnames else ip
            await self.db.add_port(
                self.program, host_domain, ip, port, transport,
                product, version, "shodan",
            )
            hosts.append({
                "ip": ip, "port": port, "product": product,
                "version": version, "hostnames": hostnames,
            })
        return {"total": len(hosts), "results": hosts}
