from __future__ import annotations
import json
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

class SslyzeTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, target: str) -> list[str]:
        return ["sslyze", "--json_out=-", target]

    def parse_output(self, output: str) -> list[dict]:
        findings = []
        try:
            data = json.loads(output)
            results = data.get("server_scan_results", [])
            for result in results:
                cmds = result.get("scan_result", result.get("scan_commands_results", {}))
                if not isinstance(cmds, dict):
                    continue
                # Check for SSL 2.0/3.0
                for old_proto in ("ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites"):
                    proto_data = cmds.get(old_proto, {})
                    if isinstance(proto_data, dict):
                        accepted = proto_data.get("accepted_cipher_suites", [])
                        if accepted:
                            findings.append({
                                "type": f"deprecated-{old_proto.replace('_cipher_suites', '')}",
                                "severity": "high",
                                "detail": f"{len(accepted)} accepted cipher suites",
                            })
                # Check for Heartbleed
                heartbleed = cmds.get("heartbleed", {})
                if isinstance(heartbleed, dict) and heartbleed.get("is_vulnerable_to_heartbleed"):
                    findings.append({
                        "type": "heartbleed",
                        "severity": "critical",
                        "detail": "Server is vulnerable to Heartbleed (CVE-2014-0160)",
                    })
                # Check certificate
                cert_info = cmds.get("certificate_info", {})
                if isinstance(cert_info, dict):
                    deployments = cert_info.get("certificate_deployments", [])
                    for dep in deployments:
                        if isinstance(dep, dict):
                            validations = dep.get("path_validation_results", [])
                            for v in validations:
                                if isinstance(v, dict) and not v.get("was_validation_successful"):
                                    findings.append({
                                        "type": "certificate-validation-failure",
                                        "severity": "medium",
                                        "detail": f"Certificate validation failed: {v.get('openssl_error_string', 'unknown')}",
                                    })
        except (json.JSONDecodeError, TypeError):
            pass
        return findings

    async def run(self, target: str) -> dict:
        domain = urlparse(f"https://{target}").hostname or target.split(":")[0]
        result = await self.runner.run_command(
            tool="sslyze",
            command=self.build_command(target),
            targets=[domain],
            timeout=300,
        )
        if not result.success:
            return {"total": 0, "findings": [], "error": result.error}
        entries = self.parse_output(result.output)
        for entry in entries:
            await self.db.add_finding(
                self.program, domain, f"https://{target}",
                entry["type"], entry["severity"], "sslyze",
                entry["detail"], 0.85,
            )
        return {"total": len(entries), "findings": entries}
