from __future__ import annotations
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner

class CdncheckTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, targets: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "cdncheck_input.txt"
        input_file.write_text("\n".join(targets) + "\n")
        return ["cdncheck", "-i", str(input_file), "-json", "-silent"]

    def parse_output(self, output: str) -> list[dict]:
        return self.runner.parse_jsonl(output)

    async def run(self, targets: list[str], work_dir: Path) -> dict:
        result = await self.runner.run_command(
            tool="cdncheck",
            command=self.build_command(targets, work_dir),
            targets=targets,
        )
        if not result.success:
            return {"total": 0, "results": [], "error": result.error}
        entries = self.parse_output(result.output)
        cdn_hosts = []
        waf_hosts = []
        for entry in entries:
            host = entry.get("input", "")
            if entry.get("cdn"):
                cdn_hosts.append({"host": host, "cdn": entry.get("cdn_name", "unknown")})
            if entry.get("waf"):
                waf_hosts.append({"host": host, "waf": entry.get("waf_name", "unknown")})
            await self.db.log_action(
                "cdn_waf_check", "cdncheck", host,
                f"CDN: {entry.get('cdn_name', 'none')}, WAF: {entry.get('waf_name', 'none')}",
            )
        return {
            "total": len(entries),
            "cdn_hosts": cdn_hosts,
            "waf_hosts": waf_hosts,
            "results": entries,
        }
