from __future__ import annotations
from collections import Counter
from dataclasses import dataclass
from bba.db import Database
from bba.tool_runner import ToolRunner

@dataclass
class ValidationResult:
    finding_id: int
    status: str  # validated, false_positive, needs_review
    confidence: float
    evidence: str = ""

_VULN_INDICATORS = {
    "xss": ["<script", "alert(", "onerror=", "<svg", "onload=", "javascript:"],
    "sql-injection": ["sql error", "mysql", "syntax error", "unclosed quotation", "ORA-", "postgresql"],
    "directory-exposure": [".env", "DB_PASSWORD", "APP_KEY", "SECRET_KEY", "index of /", "directory listing", '"status":', '"data":', "application/json"],
}

class FindingValidator:
    def __init__(self, runner: ToolRunner, db: Database):
        self.runner = runner
        self.db = db

    def _check_response(self, vuln_type: str, response: str) -> tuple[str, float]:
        response_lower = response.lower()
        indicators = _VULN_INDICATORS.get(vuln_type, [])
        matches = sum(1 for ind in indicators if ind.lower() in response_lower)
        if matches >= 2:
            return "validated", 0.95
        elif matches == 1:
            return "validated", 0.8
        else:
            return "false_positive", 0.1

    async def validate_findings(self, program: str) -> list[ValidationResult]:
        findings = await self.db.get_findings(program, status="new")
        results = []
        for finding in findings:
            url = finding.get("url", "")
            domain = finding.get("domain", "")
            vuln_type = finding.get("vuln_type", "")
            result = await self.runner.run_command(tool="curl", command=["curl", "-s", "-k", "-L", "--max-time", "10", url], targets=[domain])
            if not result.success:
                status = "needs_review"
                confidence = finding.get("confidence", 0.5)
                evidence = f"Re-test failed: {result.error}"
            else:
                status, confidence = self._check_response(vuln_type, result.output)
                evidence = f"Re-test response ({len(result.output)} bytes)"
            await self.db.update_finding_status(finding["id"], status)
            results.append(ValidationResult(finding_id=finding["id"], status=status, confidence=confidence, evidence=evidence))
        return results

    def get_summary(self, results: list[ValidationResult]) -> dict:
        status_counter = Counter(r.status for r in results)
        return {"total": len(results), "by_status": dict(status_counter)}
