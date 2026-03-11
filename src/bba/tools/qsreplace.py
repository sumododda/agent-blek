"""Query string parameter value replacement for payload injection pipelines."""
from __future__ import annotations
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
        return ["sh", "-c", f"cat {input_file} | qsreplace '{payload}'"]

    def parse_output(self, output: str) -> list[str]:
        return [line.strip() for line in output.strip().splitlines() if line.strip()]

    async def run(self, urls: list[str], payload: str, work_dir: Path) -> dict:
        if not urls:
            return {"total": 0, "urls": [], "payload": payload}
        domains = list({u.split("/")[2] for u in urls if "://" in u})
        result = await self.runner.run_command(
            tool="qsreplace", command=self.build_command(urls, payload, work_dir),
            targets=domains or ["unknown"], timeout=60,
        )
        if not result.success:
            return {"total": 0, "urls": [], "payload": payload, "error": result.error}
        replaced = self.parse_output(result.output)
        return {"total": len(replaced), "urls": replaced, "payload": payload}
