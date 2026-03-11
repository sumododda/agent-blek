"""GraphQL schema reconstruction when introspection is disabled."""
from __future__ import annotations
import json
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class ClairvoyanceTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str, wordlist: str | None = None) -> list[str]:
        cmd = ["clairvoyance", "-u", url, "-o", "-"]
        if wordlist:
            cmd.extend(["-w", wordlist])
        return cmd

    def parse_output(self, output: str) -> dict:
        try:
            schema = json.loads(output)
            types = schema.get("data", {}).get("__schema", {}).get("types", [])
            return {"schema": schema, "type_count": len(types)}
        except json.JSONDecodeError:
            return {"schema": None, "type_count": 0, "raw": output[:2000]}

    async def run(self, url: str, wordlist: str | None = None) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="clairvoyance", command=self.build_command(url, wordlist),
            targets=[domain] if domain else [url], timeout=300,
        )
        if not result.success:
            return {"success": False, "url": url, "error": result.error}
        parsed_result = self.parse_output(result.output)
        if parsed_result["type_count"] > 0:
            await self.db.log_action(
                "graphql_schema_reconstructed", "clairvoyance", url,
                f"Reconstructed {parsed_result['type_count']} types",
            )
        return {"success": parsed_result["type_count"] > 0, "url": url,
                "types_found": parsed_result["type_count"]}
