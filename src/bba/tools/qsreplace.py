"""Query string parameter value replacement for payload injection pipelines."""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

from bba.db import Database
from bba.tool_runner import ToolRunner


class QsreplaceTool:
    """Replace all query string parameter values with a given payload."""

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, urls: list[str], payload: str, work_dir: Path) -> list[str]:
        input_file = work_dir / "qsreplace_input.txt"
        input_file.write_text("\n".join(urls) + "\n")
        return ["qsreplace", payload]

    def parse_output(self, output: str) -> list[str]:
        return [line.strip() for line in output.strip().splitlines() if line.strip()]

    async def run(self, urls: list[str], payload: str, work_dir: Path) -> dict:
        if not urls:
            return {"total": 0, "urls": [], "payload": payload}

        domains = list({u.split("/")[2] for u in urls if "://" in u})
        targets = domains or ["unknown"]

        # Validate scope and apply rate limiting
        self.runner.validate_targets(targets)
        for target in targets:
            await self.runner.rate_limiter.wait(target)

        cmd = self.build_command(urls, payload, work_dir)
        stdin_data = "\n".join(urls) + "\n"

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_data.encode()), timeout=60
            )
            duration = time.monotonic() - start

            if proc.returncode != 0:
                return {
                    "total": 0,
                    "urls": [],
                    "payload": payload,
                    "error": stderr.decode(errors="replace"),
                }

            output = stdout.decode(errors="replace")
            replaced = self.parse_output(output)
            return {"total": len(replaced), "urls": replaced, "payload": payload}

        except asyncio.TimeoutError:
            return {
                "total": 0,
                "urls": [],
                "payload": payload,
                "error": "Command timed out after 60s",
            }
        except FileNotFoundError:
            return {
                "total": 0,
                "urls": [],
                "payload": payload,
                "error": "qsreplace not found in PATH",
            }
