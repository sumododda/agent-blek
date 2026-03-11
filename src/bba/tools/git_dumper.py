from __future__ import annotations
import tempfile
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

class GitDumperTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str, output_dir: str) -> list[str]:
        git_url = url.rstrip("/")
        if not git_url.endswith("/.git"):
            git_url += "/.git"
        return ["git-dumper", git_url, output_dir]

    async def run(self, url: str) -> dict:
        domain = urlparse(url).hostname or url
        output_dir = tempfile.mkdtemp(prefix="gitdump_")
        result = await self.runner.run_command(
            tool="git-dumper",
            command=self.build_command(url, output_dir),
            targets=[domain],
            timeout=300,
        )
        if not result.success:
            return {"success": False, "error": result.error}
        await self.db.add_finding(
            self.program, domain, url,
            "exposed-git-directory", "high", "git-dumper",
            f"Successfully dumped .git directory from {url} to {output_dir}",
            0.95,
        )
        return {
            "success": True,
            "output_dir": output_dir,
            "url": url,
            "message": "Git directory successfully dumped. Run trufflehog/gitleaks on output.",
        }
