from __future__ import annotations
import json
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

INTERESTING_PATHS = {".env", "backup", ".git", "config", "debug", "phpinfo", "server-status", "wp-config"}
INTERESTING_STATUS = {200, 403}

class FfufTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, target_url: str, wordlist: str, filter_codes: str = "404") -> list[str]:
        return ["ffuf", "-u", target_url, "-w", wordlist, "-json", "-silent", "-fc", filter_codes]

    def parse_output(self, output: str) -> list[dict]:
        if not output.strip():
            return []
        try:
            data = json.loads(output)
            return data.get("results", [])
        except json.JSONDecodeError:
            return []

    def _is_interesting(self, result: dict) -> bool:
        fuzz_value = result.get("input", {}).get("FUZZ", "").lower()
        return any(p in fuzz_value for p in INTERESTING_PATHS)

    async def run(self, target_url: str, wordlist: str, filter_codes: str = "404") -> dict:
        parsed = urlparse(target_url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(tool="ffuf", command=self.build_command(target_url, wordlist, filter_codes), targets=[domain] if domain else [target_url])
        if not result.success:
            return {"total": 0, "results": [], "interesting": 0, "error": result.error}
        entries = self.parse_output(result.output)
        interesting_count = 0
        for entry in entries:
            if self._is_interesting(entry):
                interesting_count += 1
                await self.db.add_finding(program=self.program, domain=domain, url=entry.get("url", ""), vuln_type="directory-exposure", severity="medium", tool="ffuf", evidence=f"status={entry.get('status')}, length={entry.get('length')}, fuzz={entry.get('input', {}).get('FUZZ', '')}", confidence=0.7)
        return {"total": len(entries), "results": [{"url": e.get("url"), "status": e.get("status")} for e in entries], "interesting": interesting_count}
