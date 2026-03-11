from __future__ import annotations
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

TECH_TAG_MAP = {
    "wordpress": "wordpress,wp-plugin,wp-theme", "joomla": "joomla", "drupal": "drupal",
    "apache": "apache", "nginx": "nginx", "iis": "iis", "tomcat": "tomcat",
    "jenkins": "jenkins", "grafana": "grafana", "gitlab": "gitlab",
}

class NucleiTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, targets: list[str], work_dir: Path, severity: str = "high,critical", rate_limit: int = 100, tags: str | None = None) -> list[str]:
        input_file = work_dir / "nuclei_targets.txt"
        input_file.write_text("\n".join(targets) + "\n")
        cmd = ["nuclei", "-l", str(input_file), "-jsonl", "-silent", "-nc"]
        if severity:
            cmd.extend(["-severity", severity])
        if rate_limit:
            cmd.extend(["-rl", str(rate_limit)])
        if tags:
            cmd.extend(["-tags", tags])
        return cmd

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results

    def select_scan_options(self, technologies: list[str]) -> dict:
        tags = []
        for tech in technologies:
            tech_lower = tech.lower()
            if tech_lower in TECH_TAG_MAP:
                tags.append(TECH_TAG_MAP[tech_lower])
        return {"severity": "high,critical", "tags": ",".join(tags) if tags else None}

    async def run(self, targets: list[str], work_dir: Path, severity: str = "high,critical", rate_limit: int = 100, tags: str | None = None) -> dict:
        domains = []
        for t in targets:
            parsed = urlparse(t)
            domains.append(parsed.hostname if parsed.hostname else t)
        result = await self.runner.run_command(tool="nuclei", command=self.build_command(targets, work_dir, severity, rate_limit, tags), targets=domains)
        if not result.success:
            return {"total": 0, "findings": [], "by_severity": {}, "error": result.error}
        entries = self.parse_output(result.output)
        severity_counter: Counter = Counter()
        for entry in entries:
            info = entry.get("info", {})
            sev = info.get("severity", "unknown")
            severity_counter[sev] += 1
            matched_at = entry.get("matched-at", "")
            host = entry.get("host", "")
            parsed_host = urlparse(host)
            domain = parsed_host.hostname or host
            evidence_parts = []
            if entry.get("template-id"):
                evidence_parts.append(f"template: {entry['template-id']}")
            if entry.get("extracted-results"):
                evidence_parts.append(f"extracted: {entry['extracted-results']}")
            if entry.get("matcher-name"):
                evidence_parts.append(f"matcher: {entry['matcher-name']}")
            confidence = {"critical": 0.95, "high": 0.85, "medium": 0.7, "low": 0.5, "info": 0.3}.get(sev, 0.5)
            await self.db.add_finding(program=self.program, domain=domain, url=matched_at, vuln_type=info.get("name", entry.get("template-id", "unknown")), severity=sev, tool="nuclei", evidence="; ".join(evidence_parts), confidence=confidence)
        return {"total": len(entries), "findings": [{"template": e.get("template-id"), "severity": e.get("info", {}).get("severity"), "url": e.get("matched-at")} for e in entries], "by_severity": dict(severity_counter)}
