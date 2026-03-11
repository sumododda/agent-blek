"""JWT vulnerability testing via jwt_tool."""
from __future__ import annotations
import re
from bba.db import Database
from bba.tool_runner import ToolRunner

_VULN_PATTERN = re.compile(r"(?:VULNERABLE|EXPLOITABLE|WEAK SECRET|alg.*none.*accepted)", re.I)
_ALG_NONE = re.compile(r"alg.*none.*accepted", re.I)
_WEAK_SECRET = re.compile(r"(?:weak.*secret|cracked|secret.*found).*?[:\-]\s*(.+)", re.I)


class JwtToolTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command_scan(self, token: str) -> list[str]:
        return ["jwt_tool", token, "-M", "at", "-t", "https://example.com", "-np"]

    def build_command_crack(self, token: str, wordlist: str) -> list[str]:
        return ["jwt_tool", token, "-C", "-d", wordlist, "-np"]

    def parse_output(self, output: str) -> dict:
        vulns = []
        if _ALG_NONE.search(output):
            vulns.append({"type": "alg-none", "detail": "Algorithm 'none' accepted"})
        weak_match = _WEAK_SECRET.search(output)
        if weak_match:
            vulns.append({"type": "weak-secret", "detail": f"Secret: {weak_match.group(1)}"})
        for match in _VULN_PATTERN.finditer(output):
            text = match.group(0).strip()
            if not any(v["detail"] in text for v in vulns):
                vulns.append({"type": "jwt-vuln", "detail": text})
        return {"vulnerable": bool(vulns), "vulns": vulns}

    async def run(self, token: str, domain: str, mode: str = "scan", wordlist: str | None = None) -> dict:
        if mode == "crack" and wordlist:
            cmd = self.build_command_crack(token, wordlist)
        else:
            cmd = self.build_command_scan(token)
        result = await self.runner.run_command(
            tool="jwt_tool", command=cmd, targets=[domain], timeout=300,
        )
        if not result.success:
            return {"vulnerable": False, "error": result.error}
        parsed = self.parse_output(result.output)
        for vuln in parsed["vulns"]:
            await self.db.add_finding(
                program=self.program, domain=domain, url=f"jwt://{domain}",
                vuln_type=f"jwt-{vuln['type']}", severity="critical" if vuln["type"] == "alg-none" else "high",
                tool="jwt_tool", evidence=vuln["detail"], confidence=0.9,
            )
        return {"vulnerable": parsed["vulnerable"], "vulns": parsed["vulns"]}
