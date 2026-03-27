from __future__ import annotations
import os
import tempfile
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner

INTERESTING_PATHS = [
    ".env", ".git", "backup", "config", "debug", "phpinfo",
    "server-status", "wp-config", "admin", ".htaccess", "web.config",
    ".svn", ".DS_Store", "wp-admin", "phpmyadmin", "actuator",
]

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_WORDLIST = str(_PROJECT_ROOT / "data" / "wordlists" / "seclists" / "Discovery" / "Web-Content" / "common.txt")

class FeroxbusterTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str, wordlist: str = DEFAULT_WORDLIST, depth: int = 3, output_file: str = "/dev/stdout") -> list[str]:
        return [
            "feroxbuster", "-u", url, "-w", wordlist,
            "--json", "--silent", "--depth", str(depth),
            "--rate-limit", "50", "--output", output_file,
        ]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for entry in self.runner.parse_jsonl(output):
            if entry.get("type") == "response" or "url" in entry:
                results.append(entry)
        return results

    def _is_interesting(self, url: str) -> bool:
        lower = url.lower()
        return any(p in lower for p in INTERESTING_PATHS)

    async def run(self, url: str, wordlist: str = DEFAULT_WORDLIST, depth: int = 3) -> dict:
        domain = self.runner.extract_domain(url)
        # feroxbuster requires --output when using --json --silent, write to temp file
        tmpfile = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmpfile.close()
        try:
            result = await self.runner.run_command(
                tool="feroxbuster",
                command=self.build_command(url, wordlist, depth, output_file=tmpfile.name),
                targets=[domain],
                timeout=600,
            )
            # Read output from temp file
            raw_output = ""
            if os.path.exists(tmpfile.name):
                with open(tmpfile.name, "r") as f:
                    raw_output = f.read()
            # Fallback to result.output if temp file is empty
            if not raw_output.strip() and result.output:
                raw_output = result.output
            if not raw_output.strip() and not result.success:
                return {"total": 0, "urls": [], "interesting": [], "error": result.error}
        finally:
            try:
                os.unlink(tmpfile.name)
            except OSError:
                pass

        entries = self.parse_output(raw_output)
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
