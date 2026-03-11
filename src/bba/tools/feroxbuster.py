from __future__ import annotations
import json
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

INTERESTING_PATHS = [
    ".env", ".git", "backup", "config", "debug", "phpinfo",
    "server-status", "wp-config", "admin", ".htaccess", "web.config",
    ".svn", ".DS_Store", "wp-admin", "phpmyadmin", "actuator",
]

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

class FeroxbusterTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str, wordlist: str = DEFAULT_WORDLIST, depth: int = 3) -> list[str]:
        return [
            "feroxbuster", "-u", url, "-w", wordlist,
            "--json", "--silent", "--depth", str(depth),
            "--rate-limit", "100", "--auto-tune",
        ]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if entry.get("type") == "response" or "url" in entry:
                    results.append(entry)
            except json.JSONDecodeError:
                continue
        return results

    def _is_interesting(self, url: str) -> bool:
        lower = url.lower()
        return any(p in lower for p in INTERESTING_PATHS)

    async def run(self, url: str, wordlist: str = DEFAULT_WORDLIST, depth: int = 3) -> dict:
        domain = urlparse(url).hostname or url
        result = await self.runner.run_command(
            tool="feroxbuster",
            command=self.build_command(url, wordlist, depth),
            targets=[domain],
            timeout=600,
        )
        if not result.success:
            return {"total": 0, "urls": [], "interesting": [], "error": result.error}
        entries = self.parse_output(result.output)
        discovered_urls = []
        interesting = []
        for entry in entries:
            found_url = entry.get("url", "")
            status = entry.get("status", 0)
            if not found_url or status == 404:
                continue
            discovered_urls.append(found_url)
            await self.db.add_url(
                self.program, found_url, "feroxbuster",
                status_code=status,
                content_type=entry.get("content_type", ""),
            )
            if self._is_interesting(found_url):
                interesting.append(found_url)
                await self.db.add_finding(
                    self.program, domain, found_url,
                    "interesting-path", "info", "feroxbuster",
                    f"Discovered: {found_url} (status={status})", 0.6,
                )
        return {
            "total": len(discovered_urls),
            "urls": discovered_urls,
            "interesting": interesting,
        }
