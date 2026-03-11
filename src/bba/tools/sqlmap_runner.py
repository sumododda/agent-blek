from __future__ import annotations
import re
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

_VULN_PATTERN = re.compile(r"is vulnerable|injectable", re.I)
_NOT_VULN_PATTERN = re.compile(r"do not appear to be injectable|not vulnerable", re.I)

class SqlmapTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, target_url: str, tamper: str | None = None,
                      headers: str | None = None, cookie: str | None = None,
                      data: str | None = None, method: str | None = None) -> list[str]:
        cmd = ["sqlmap", "-u", target_url, "--batch", "--level=2", "--risk=2"]
        if tamper:
            cmd.extend(["--tamper", tamper])
        if headers:
            cmd.extend(["--headers", headers])
        if cookie:
            cmd.extend(["--cookie", cookie])
        if data:
            cmd.extend(["--data", data])
        if method:
            cmd.extend(["--method", method])
        return cmd

    def is_vulnerable(self, output: str) -> bool:
        if _NOT_VULN_PATTERN.search(output):
            return False
        return bool(_VULN_PATTERN.search(output))

    async def run(self, target_url: str, tamper: str | None = None,
                  headers: str | None = None, cookie: str | None = None,
                  data: str | None = None, method: str | None = None) -> dict:
        parsed = urlparse(target_url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(tool="sqlmap", command=self.build_command(target_url, tamper, headers, cookie, data, method), targets=[domain] if domain else [target_url], timeout=300)
        if not result.success:
            return {"vulnerable": False, "error": result.error}
        vulnerable = self.is_vulnerable(result.output)
        if vulnerable:
            await self.db.add_finding(program=self.program, domain=domain, url=target_url, vuln_type="sql-injection", severity="critical", tool="sqlmap", evidence=result.output[:2000], confidence=0.9)
        return {"vulnerable": vulnerable, "url": target_url, "output_preview": result.output[:500]}
