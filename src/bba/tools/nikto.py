from __future__ import annotations
import json
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

class NiktoTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["nikto", "-h", url, "-Format", "json", "-output", "/dev/stdout", "-nointeractive"]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        try:
            data = json.loads(output)
            vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
            for vuln in vulns:
                results.append({
                    "id": vuln.get("id", vuln.get("OSVDB", "")),
                    "msg": vuln.get("msg", vuln.get("message", "")),
                    "method": vuln.get("method", "GET"),
                    "url": vuln.get("url", ""),
                })
        except json.JSONDecodeError:
            # nikto sometimes outputs non-standard JSON, try line-by-line
            for line in output.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    results.append(entry)
                except json.JSONDecodeError:
                    continue
        return results

    async def run(self, url: str) -> dict:
        domain = urlparse(url).hostname or url
        result = await self.runner.run_command(
            tool="nikto",
            command=self.build_command(url),
            targets=[domain],
            timeout=600,
        )
        if not result.success:
            return {"total": 0, "findings": [], "error": result.error}
        entries = self.parse_output(result.output)
        for entry in entries:
            vuln_url = entry.get("url", url)
            if not vuln_url.startswith("http"):
                vuln_url = f"{url.rstrip('/')}{vuln_url}"
            await self.db.add_finding(
                self.program, domain, vuln_url,
                "web-server-misconfiguration", "medium", "nikto",
                f"[{entry.get('id', 'N/A')}] {entry.get('msg', '')}",
                0.6,
            )
        return {"total": len(entries), "findings": entries}
