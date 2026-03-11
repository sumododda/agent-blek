from __future__ import annotations
import json
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

class Graphw00fTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["graphw00f", "-t", url, "--json"]

    def parse_output(self, output: str) -> dict:
        try:
            data = json.loads(output)
            return data
        except json.JSONDecodeError:
            return {}

    async def run(self, url: str) -> dict:
        domain = urlparse(url).hostname or url
        result = await self.runner.run_command(
            tool="graphw00f",
            command=self.build_command(url),
            targets=[domain],
            timeout=60,
        )
        if not result.success:
            return {"detected": False, "engine": None, "error": result.error}
        data = self.parse_output(result.output)
        detected = bool(data.get("detected") or data.get("engine"))
        engine = data.get("engine", None)
        if detected:
            await self.db.add_finding(
                self.program, domain, url,
                "graphql-detected", "info", "graphw00f",
                f"GraphQL endpoint detected: engine={engine}", 0.9,
            )
            await self.db.add_url(self.program, url, "graphw00f")
        return {"detected": detected, "engine": engine, "url": url, "data": data}
