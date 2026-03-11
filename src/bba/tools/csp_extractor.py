"""CSP header domain extraction — extracts hidden domains from Content-Security-Policy headers."""
from __future__ import annotations

import re
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class CspExtractorTool:
    """Extract domains from Content-Security-Policy headers to discover hidden subdomains/APIs."""

    DOMAIN_RE = re.compile(r"(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)")

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def parse_csp(self, csp_header: str) -> list[str]:
        """Extract unique domains from a CSP header value."""
        domains = set()
        for match in self.DOMAIN_RE.finditer(csp_header):
            domain = match.group(1).lower()
            if "." in domain and not domain.endswith(".w3.org"):
                domains.add(domain)
        return sorted(domains)

    async def run(self, urls: list[str]) -> dict:
        """Fetch each URL's headers and extract CSP domains."""
        all_domains = set()

        for url in urls:
            domain = urlparse(url).hostname or url
            result = await self.runner.run_http_request(
                tool="csp-extractor", url=url, targets=[domain], timeout=10,
            )
            if not result.success:
                continue
            # Look for CSP in response (headers may be mixed in depending on tool output)
            csp_domains = self.parse_csp(result.output)
            all_domains.update(csp_domains)

        domains_list = sorted(all_domains)
        if domains_list:
            await self.db.add_subdomains_bulk(self.program, domains_list, "csp-header")

        return {
            "total": len(domains_list),
            "domains": domains_list,
        }
