from __future__ import annotations
from collections import Counter
from datetime import datetime
from pathlib import Path
from bba.db import Database

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

class ReportGenerator:
    def __init__(self, db: Database):
        self.db = db

    async def generate(self, program: str) -> str:
        validated = await self.db.get_findings(program, status="validated")
        if not validated:
            return f"# Bug Bounty Report: {program}\n\nNo validated findings for this program.\n"
        validated.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 99))
        severity_counts = Counter(f["severity"] for f in validated)
        lines = [
            f"# Bug Bounty Report: {program}",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Total Validated Findings:** {len(validated)}",
            "",
            "## Summary",
            "",
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                lines.append(f"- **{sev.upper()}:** {count}")
        lines.extend(["", "## Findings", ""])
        for i, finding in enumerate(validated, 1):
            lines.extend([
                f"### {i}. [{finding['severity'].upper()}] {finding['vuln_type']}",
                "",
                f"- **Domain:** {finding['domain']}",
                f"- **URL:** {finding['url']}",
                f"- **Tool:** {finding['tool']}",
                f"- **Confidence:** {finding['confidence']:.0%}",
                "",
            ])
            if finding.get("evidence"):
                lines.extend(["**Evidence:**", "```", finding["evidence"], "```", ""])
        return "\n".join(lines)

    async def save(self, program: str, output_dir: Path) -> Path:
        report = await self.generate(program)
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = output_dir / f"report_{program}_{timestamp}.md"
        path.write_text(report)
        return path
