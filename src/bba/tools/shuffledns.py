from __future__ import annotations
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner

DEFAULT_RESOLVERS = Path(__file__).resolve().parent.parent.parent.parent / "data" / "wordlists" / "resolvers"
DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent.parent.parent / "data" / "wordlists" / "assetnote-best-dns"

class ShufflednsTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, domain: str, wordlist: str | None = None, resolvers: str | None = None) -> list[str]:
        cmd = ["shuffledns", "-d", domain, "-silent"]
        wl = wordlist or str(DEFAULT_WORDLIST)
        if Path(wl).exists():
            cmd.extend(["-w", wl])
        res = resolvers or str(DEFAULT_RESOLVERS)
        if Path(res).exists():
            cmd.extend(["-r", res])
        return cmd

    def parse_output(self, output: str) -> list[str]:
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if line:
                results.append(line)
        return results

    async def run(self, domain: str, wordlist: str | None = None, resolvers: str | None = None) -> dict:
        result = await self.runner.run_command(
            tool="shuffledns",
            command=self.build_command(domain, wordlist, resolvers),
            targets=[domain],
            timeout=900,
        )
        if not result.success:
            return {"total": 0, "domains": [], "error": result.error}
        domains = self.parse_output(result.output)
        if domains:
            await self.db.add_subdomains_bulk(self.program, domains, "shuffledns")
        return {"total": len(domains), "domains": domains}
