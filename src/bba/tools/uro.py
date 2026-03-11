"""URL deduplication via uro — removes duplicate/similar URLs."""
from __future__ import annotations
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner


class UroTool:
    """Deduplicate URLs by normalizing query params and collapsing similar paths."""

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, urls: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "uro_input.txt"
        input_file.write_text("\n".join(urls) + "\n")
        return ["uro", "-i", str(input_file)]

    def parse_output(self, output: str) -> list[str]:
        return [line.strip() for line in output.strip().splitlines() if line.strip()]

    async def run(self, urls: list[str], work_dir: Path) -> dict:
        if not urls:
            return {"total": 0, "urls": [], "original_count": 0}
        domains = list({u.split("/")[2] for u in urls if "://" in u})
        result = await self.runner.run_command(
            tool="uro", command=self.build_command(urls, work_dir),
            targets=domains or ["unknown"], timeout=120,
        )
        if not result.success:
            return {"total": 0, "urls": [], "original_count": len(urls), "error": result.error}
        deduped = self.parse_output(result.output)
        return {"total": len(deduped), "urls": deduped, "original_count": len(urls), "reduced_by": len(urls) - len(deduped)}
