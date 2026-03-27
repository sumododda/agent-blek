"""JavaScript URL/path/secret extraction via jsluice (AST-based)."""
from __future__ import annotations
import json
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class JsluiceTool:
    """Extract URLs, paths, and secrets from JS files using AST analysis."""

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command_urls(self, js_file: str) -> list[str]:
        return ["jsluice", "urls", "-R", js_file]

    def build_command_secrets(self, js_file: str) -> list[str]:
        return ["jsluice", "secrets", js_file]

    def parse_output(self, output: str) -> list[dict]:
        return self.runner.parse_jsonl(output)

    async def run_urls(self, js_url: str, domain: str) -> dict:
        result = await self.runner.run_command(
            tool="jsluice", command=self.build_command_urls(js_url),
            targets=[domain], timeout=60,
        )
        if not result.success:
            return {"total": 0, "urls": [], "error": result.error}
        entries = self.parse_output(result.output)
        urls = [e.get("url", "") for e in entries if e.get("url")]
        if urls:
            await self.db.add_urls_bulk(self.program, urls, "jsluice")
        return {"total": len(urls), "urls": urls, "source": js_url}

    async def run_secrets(self, js_url: str, domain: str) -> dict:
        result = await self.runner.run_command(
            tool="jsluice", command=self.build_command_secrets(js_url),
            targets=[domain], timeout=60,
        )
        if not result.success:
            return {"total": 0, "secrets": [], "error": result.error}
        entries = self.parse_output(result.output)
        for entry in entries:
            kind = entry.get("kind", "unknown")
            data = json.dumps(entry.get("data", {}))
            await self.db.add_secret(
                program=self.program, secret_type=kind, value=data,
                source_url=js_url, source_file="", tool="jsluice",
                confidence=0.8,
            )
        return {"total": len(entries), "secrets": entries, "source": js_url}
