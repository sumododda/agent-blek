from __future__ import annotations
import json
from bba.db import Database
from bba.tool_runner import ToolRunner

class Wafw00fTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["wafw00f", url, "-o", "-", "-f", "json"]

    def parse_output(self, output: str) -> list[dict]:
        try:
            data = json.loads(output)
            if isinstance(data, list):
                return data
            return [data]
        except json.JSONDecodeError:
            return []

    async def run(self, url: str) -> dict:
        from urllib.parse import urlparse
        domain = urlparse(url).hostname or url
        result = await self.runner.run_command(
            tool="wafw00f", command=self.build_command(url), targets=[domain],
        )
        if not result.success:
            return {"detected": False, "waf": None, "error": result.error}
        entries = self.parse_output(result.output)
        waf_name = None
        detected = False
        for entry in entries:
            if entry.get("detected"):
                detected = True
                waf_name = entry.get("firewall", "Unknown")
                break
        await self.db.log_action(
            "waf_detection", "wafw00f", domain,
            f"WAF: {waf_name}" if detected else "No WAF detected",
        )
        return {"detected": detected, "waf": waf_name, "url": url}
