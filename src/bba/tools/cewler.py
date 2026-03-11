"""Custom wordlist generation from target content via cewler."""
from __future__ import annotations
from pathlib import Path
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class CewlerTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str, depth: int = 2, output_file: str | None = None) -> list[str]:
        cmd = ["cewler", "-u", url, "-d", str(depth)]
        if output_file:
            cmd.extend(["-o", output_file])
        return cmd

    def parse_output(self, output: str) -> list[str]:
        return [w.strip() for w in output.strip().splitlines() if w.strip() and len(w.strip()) > 2]

    async def run(self, url: str, work_dir: Path, depth: int = 2) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        output_file = work_dir / f"cewler_{domain}.txt"
        result = await self.runner.run_command(
            tool="cewler", command=self.build_command(url, depth, str(output_file)),
            targets=[domain] if domain else [url], timeout=120,
        )
        if not result.success:
            return {"total": 0, "wordlist": None, "error": result.error}
        words = self.parse_output(result.output)
        if output_file.exists():
            words = [w.strip() for w in output_file.read_text().splitlines() if w.strip()]
        return {"total": len(words), "wordlist": str(output_file) if output_file.exists() else None,
                "sample": words[:20], "url": url}
