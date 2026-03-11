from __future__ import annotations
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner

DEFAULT_RESOLVERS = Path(__file__).resolve().parent.parent.parent.parent / "data" / "wordlists" / "resolvers"

class PurednsTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, domains: list[str], work_dir: Path, resolvers: str | None = None) -> list[str]:
        input_file = work_dir / "puredns_input.txt"
        input_file.write_text("\n".join(domains) + "\n")
        cmd = ["puredns", "resolve", str(input_file), "-q"]
        resolver_path = resolvers or str(DEFAULT_RESOLVERS)
        if Path(resolver_path).exists():
            cmd.extend(["-r", resolver_path])
        return cmd

    def parse_output(self, output: str) -> list[str]:
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if line:
                results.append(line)
        return results

    async def run(self, domains: list[str], work_dir: Path, resolvers: str | None = None) -> dict:
        result = await self.runner.run_command(
            tool="puredns",
            command=self.build_command(domains, work_dir, resolvers),
            targets=domains[:1],  # validate at least one target for scope
            timeout=900,
        )
        if not result.success:
            return {"total": 0, "resolved": [], "error": result.error}
        resolved = self.parse_output(result.output)
        if resolved:
            await self.db.add_subdomains_bulk(self.program, resolved, "puredns")
        return {"total": len(resolved), "resolved": resolved}
