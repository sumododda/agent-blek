from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from bba.db import Database
from bba.tool_runner import ToolRunner


class GowitnessTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, urls: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "gowitness_input.txt"
        input_file.write_text("\n".join(urls) + "\n")
        screenshot_dir = work_dir / "screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        return [
            "gowitness",
            "scan",
            "file",
            "-f",
            str(input_file),
            "--screenshot-path",
            str(screenshot_dir),
            "--write-json",
        ]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results

    async def run(self, urls: list[str], work_dir: Path) -> dict:
        domains = [urlparse(u).hostname or u for u in urls]
        result = await self.runner.run_command(
            tool="gowitness",
            command=self.build_command(urls, work_dir),
            targets=domains,
            timeout=600,
        )
        if not result.success:
            return {"total": 0, "screenshots": [], "error": result.error}
        entries = self.parse_output(result.output)
        screenshots = []
        for entry in entries:
            url = entry.get("url", "")
            file_path = entry.get("filename", entry.get("screenshot", ""))
            status_code = entry.get("status_code", entry.get("response_code", 0))
            title = entry.get("title", "")
            if url:
                await self.db.add_screenshot(
                    self.program, url, file_path, status_code, title,
                )
                screenshots.append({
                    "url": url,
                    "file": file_path,
                    "status_code": status_code,
                    "title": title,
                })
        return {"total": len(screenshots), "screenshots": screenshots}
