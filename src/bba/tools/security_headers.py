from __future__ import annotations
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "Missing HSTS header — vulnerable to protocol downgrade attacks",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "Missing CSP header — increased XSS risk",
    },
    "X-Frame-Options": {
        "severity": "low",
        "description": "Missing X-Frame-Options — potential clickjacking",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "Missing X-Content-Type-Options — MIME sniffing risk",
    },
    "Referrer-Policy": {
        "severity": "info",
        "description": "Missing Referrer-Policy — information leakage via referer",
    },
    "Permissions-Policy": {
        "severity": "info",
        "description": "Missing Permissions-Policy header",
    },
    "X-XSS-Protection": {
        "severity": "info",
        "description": "Missing X-XSS-Protection header",
    },
}

DANGEROUS_HEADERS = {
    "Server": "Server header reveals software version",
    "X-Powered-By": "X-Powered-By reveals technology stack",
    "X-AspNet-Version": "ASP.NET version disclosed",
}


class SecurityHeadersTool:
    """Analyze HTTP response headers for security misconfigurations."""

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def analyze_headers(self, response_text: str) -> dict:
        """Analyze response for missing and dangerous headers."""
        response_lower = response_text.lower()
        missing = []
        for header, info in REQUIRED_HEADERS.items():
            if header.lower() not in response_lower:
                missing.append({"header": header, **info})
        dangerous = []
        for header, desc in DANGEROUS_HEADERS.items():
            if header.lower() in response_lower:
                dangerous.append({"header": header, "description": desc})
        return {"missing": missing, "dangerous": dangerous}

    async def run(self, url: str) -> dict:
        domain = urlparse(url).hostname or url
        result = await self.runner.run_http_request(
            tool="security-headers", url=url, targets=[domain], timeout=15,
        )
        if not result.success:
            return {"missing": [], "dangerous": [], "error": result.error}
        analysis = self.analyze_headers(result.output)
        for item in analysis["missing"]:
            if item["severity"] in ("medium", "high", "critical"):
                await self.db.add_finding(
                    self.program, domain, url,
                    "missing-security-header", item["severity"],
                    "security-headers", f"{item['header']}: {item['description']}",
                    0.8,
                )
        for item in analysis["dangerous"]:
            await self.db.add_finding(
                self.program, domain, url,
                "information-disclosure", "info", "security-headers",
                f"{item['header']}: {item['description']}", 0.7,
            )
        return {
            "url": url,
            "missing_count": len(analysis["missing"]),
            "dangerous_count": len(analysis["dangerous"]),
            **analysis,
        }
