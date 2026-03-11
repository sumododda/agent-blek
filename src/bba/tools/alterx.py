from __future__ import annotations
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner

class AlterxTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, domains: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "alterx_input.txt"
        input_file.write_text("\n".join(domains) + "\n")
        return ["alterx", "-l", str(input_file), "-silent"]

    def parse_output(self, output: str) -> list[str]:
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if line:
                results.append(line)
        return results

    async def run(self, domains: list[str], work_dir: Path) -> dict:
        result = await self.runner.run_command(
            tool="alterx",
            command=self.build_command(domains, work_dir),
            targets=domains,
        )
        if not result.success:
            return {"total": 0, "permutations": [], "error": result.error}
        permutations = self.parse_output(result.output)
        return {"total": len(permutations), "permutations": permutations}
