from __future__ import annotations
import json
from bba.db import Database
from bba.tool_runner import ToolRunner

class RetirejsTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, target_path: str) -> list[str]:
        return ["retire", "--path", target_path, "--outputformat", "json", "--outputpath", "/dev/stdout"]

    def parse_output(self, output: str) -> list[dict]:
        try:
            data = json.loads(output)
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "data" in data:
                return data["data"]
            return [data]
        except json.JSONDecodeError:
            return []

    async def run(self, target_path: str, domain: str = "") -> dict:
        target = domain or target_path
        result = await self.runner.run_command(
            tool="retirejs",
            command=self.build_command(target_path),
            targets=[target],
            timeout=120,
        )
        if not result.success:
            return {"total": 0, "vulnerabilities": [], "error": result.error}
        entries = self.parse_output(result.output)
        vulns = []
        for entry in entries:
            file_path = entry.get("file", "")
            results = entry.get("results", [])
            for r in results:
                component = r.get("component", "")
                version = r.get("version", "")
                for vuln in r.get("vulnerabilities", []):
                    severity = vuln.get("severity", "medium")
                    info = vuln.get("info", [])
                    identifiers = vuln.get("identifiers", {})
                    vulns.append({
                        "component": component,
                        "version": version,
                        "severity": severity,
                        "info": info,
                        "cve": identifiers.get("CVE", []),
                    })
                    await self.db.add_finding(
                        self.program, target, file_path,
                        "vulnerable-js-library", severity, "retirejs",
                        f"{component} {version}: {', '.join(info[:2])}",
                        0.8,
                    )
        return {"total": len(vulns), "vulnerabilities": vulns}
