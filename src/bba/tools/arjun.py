from __future__ import annotations
import json
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

class ArjunTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["arjun", "-u", url, "-oJ", "/dev/stdout"]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                for url, params in data.items():
                    results.append({"url": url, "params": params})
            elif isinstance(data, list):
                results = data
        except json.JSONDecodeError:
            pass
        return results

    async def run(self, url: str) -> dict:
        domain = urlparse(url).hostname or url
        result = await self.runner.run_command(
            tool="arjun",
            command=self.build_command(url),
            targets=[domain],
            timeout=300,
        )
        if not result.success:
            return {"total": 0, "params": [], "error": result.error}
        entries = self.parse_output(result.output)
        all_params = []
        for entry in entries:
            params = entry.get("params", [])
            all_params.extend(params)
            if params:
                param_url = f"{url}?{'&'.join(f'{p}=FUZZ' for p in params)}"
                await self.db.add_url(self.program, param_url, "arjun")
        await self.db.log_action(
            "param_discovery", "arjun", url,
            f"Found {len(all_params)} parameters: {', '.join(all_params[:20])}",
        )
        return {"total": len(all_params), "params": all_params, "url": url}
