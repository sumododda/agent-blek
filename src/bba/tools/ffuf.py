from __future__ import annotations
import base64
import json
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

INTERESTING_PATHS = {".env", "backup", ".git", "config", "debug", "phpinfo", "server-status", "wp-config"}

class FfufVhostTool:
    """Virtual host fuzzing mode — discovers hidden vhosts via Host header."""

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, target_url: str, wordlist: str, domain: str) -> list[str]:
        return [
            "ffuf", "-u", target_url,
            "-H", f"Host: FUZZ.{domain}",
            "-w", wordlist, "-json", "-s",
            "-fc", "404", "-noninteractive", "-ac",
        ]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if "results" in data:
                    results.extend(data["results"])
                elif "url" in data or "input" in data:
                    results.append(data)
            except json.JSONDecodeError:
                continue
        return results

    async def run(self, target_url: str, wordlist: str, domain: str) -> dict:
        parsed = urlparse(target_url)
        host = parsed.hostname or domain
        result = await self.runner.run_command(
            tool="ffuf-vhost",
            command=self.build_command(target_url, wordlist, domain),
            targets=[host],
        )
        if not result.success:
            return {"total": 0, "vhosts": [], "error": result.error}
        entries = self.parse_output(result.output)
        vhosts = []
        for entry in entries:
            fuzz = entry.get("input", {}).get("FUZZ", "")
            vhost = f"{fuzz}.{domain}"
            vhosts.append(vhost)
            await self.db.add_subdomain(self.program, vhost, "ffuf-vhost")
        return {"total": len(vhosts), "vhosts": vhosts}


class FfufTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, target_url: str, wordlist: str, filter_codes: str = "404") -> list[str]:
        return ["ffuf", "-u", target_url, "-w", wordlist, "-json", "-s", "-fc", filter_codes, "-noninteractive", "-ac"]

    def parse_output(self, output: str) -> list[dict]:
        if not output.strip():
            return []
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                # ffuf v2 outputs one JSON object per line (JSONL)
                if "results" in data:
                    results.extend(data["results"])
                elif "url" in data or "input" in data:
                    results.append(data)
            except json.JSONDecodeError:
                continue
        return results

    def _get_fuzz_value(self, result: dict) -> str:
        """Extract the FUZZ value, decoding base64 if needed (ffuf v2)."""
        raw = result.get("input", {}).get("FUZZ", "")
        try:
            decoded = base64.b64decode(raw).decode("utf-8", errors="replace")
            return decoded.lower()
        except Exception:
            return raw.lower()

    def _is_interesting(self, result: dict) -> bool:
        fuzz_value = self._get_fuzz_value(result)
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
                fuzz = self._get_fuzz_value(entry)
                await self.db.add_finding(program=self.program, domain=domain, url=entry.get("url", ""), vuln_type="directory-exposure", severity="medium", tool="ffuf", evidence=f"status={entry.get('status')}, length={entry.get('length')}, fuzz={fuzz}", confidence=0.7)
        return {"total": len(entries), "results": [{"url": e.get("url"), "status": e.get("status")} for e in entries], "interesting": interesting_count}
