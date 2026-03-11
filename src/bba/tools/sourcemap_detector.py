"""Source map detector — checks JS files for exposed .js.map files.

Exposed source maps leak original source code, internal paths, and comments.
"""
from __future__ import annotations

from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class SourcemapDetectorTool:
    """Check JS file URLs for exposed webpack/vite source maps."""

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    async def run(self, js_urls: list[str]) -> dict:
        """Check each JS URL for a corresponding .map file."""
        found = []
        checked = 0

        for js_url in js_urls:
            map_url = js_url + ".map"
            domain = urlparse(js_url).hostname or js_url
            checked += 1

            result = await self.runner.run_http_request(
                tool="sourcemap-detector",
                url=map_url,
                targets=[domain],
                timeout=10,
            )
            if result.success and len(result.output) > 50:
                # Verify it looks like a source map (starts with JSON containing "version")
                if '"version"' in result.output[:200] and '"sources"' in result.output[:500]:
                    found.append(map_url)
                    await self.db.add_finding(
                        self.program, domain, map_url,
                        "exposed-source-map", "medium", "sourcemap-detector",
                        f"Source map exposed at {map_url} ({len(result.output)} bytes)",
                        0.9,
                    )

        return {
            "checked": checked,
            "found": len(found),
            "source_maps": found,
        }
