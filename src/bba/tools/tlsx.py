from __future__ import annotations
import json
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner

class TlsxTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, domains: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "tlsx_input.txt"
        input_file.write_text("\n".join(domains) + "\n")
        return ["tlsx", "-l", str(input_file), "-json", "-silent", "-san", "-cn", "-so"]

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

    async def run(self, domains: list[str], work_dir: Path) -> dict:
        result = await self.runner.run_command(
            tool="tlsx",
            command=self.build_command(domains, work_dir),
            targets=domains,
        )
        if not result.success:
            return {"total": 0, "certs": [], "new_domains": [], "error": result.error}
        entries = self.parse_output(result.output)
        new_domains = set()
        certs = []
        for entry in entries:
            host = entry.get("host", "")
            san = entry.get("san", []) or []
            cn = entry.get("subject_cn", "")
            issuer = entry.get("issuer_org", "")
            for name in san:
                name = name.strip().lower()
                if name and not name.startswith("*"):
                    new_domains.add(name)
            if cn and not cn.startswith("*"):
                new_domains.add(cn.strip().lower())
            certs.append({
                "host": host, "cn": cn, "san_count": len(san),
                "issuer": issuer,
            })
        new_domains_list = sorted(new_domains)
        if new_domains_list:
            await self.db.add_subdomains_bulk(self.program, new_domains_list, "tlsx-san")
        return {
            "total": len(certs),
            "certs": certs,
            "new_domains": new_domains_list,
        }
