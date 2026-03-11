from __future__ import annotations
from bba.db import Database
from bba.tool_runner import ToolRunner

class ParamspiderTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, domain: str) -> list[str]:
        return ["paramspider", "-d", domain, "--output", "-"]

    def parse_output(self, output: str) -> list[str]:
        urls = []
        for line in output.strip().splitlines():
            line = line.strip()
            if line and line.startswith("http"):
                urls.append(line)
        return urls

    async def run(self, domain: str) -> dict:
        result = await self.runner.run_command(
            tool="paramspider",
            command=self.build_command(domain),
            targets=[domain],
            timeout=300,
        )
        if not result.success:
            return {"total": 0, "urls": [], "error": result.error}
        urls = self.parse_output(result.output)
        if urls:
            await self.db.add_urls_bulk(self.program, urls, "paramspider")
        return {"total": len(urls), "urls": urls}
