from __future__ import annotations
from collections import Counter
from pathlib import Path
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

    def build_command(self, targets: list[str], work_dir: Path, severity: str = "high,critical", rate_limit: int = 100, tags: str | None = None, templates: list[str] | None = None, dast: bool = False, concurrency: int | None = None, interactsh_url: str | None = None, interactsh_server: str | None = None, headless: bool = False) -> list[str]:
        input_file = self.runner.create_input_file(targets, work_dir, filename="nuclei_targets.txt")
        cmd = ["nuclei", "-l", str(input_file), "-jsonl", "-silent", "-nc"]
        if severity:
            cmd.extend(["-severity", severity])
        if rate_limit:
            cmd.extend(["-rl", str(rate_limit)])
        if tags:
            cmd.extend(["-tags", tags])
        if templates:
            for tmpl in templates:
                cmd.extend(["-t", tmpl])
        if dast:
            cmd.append("-dast")
        if concurrency:
            cmd.extend(["-c", str(concurrency)])
        if interactsh_url:
            cmd.extend(["-iurl", interactsh_url])
        if interactsh_server:
            cmd.extend(["-iserver", interactsh_server])
        if headless:
            cmd.append("-headless")
        return cmd

    def parse_output(self, output: str) -> list[dict]:
        return self.runner.parse_jsonl(output)

    def select_scan_options(self, technologies: list[str]) -> dict:
        tags = []
        for tech in technologies:
            tech_lower = tech.lower()
            if tech_lower in TECH_TAG_MAP:
                tags.append(TECH_TAG_MAP[tech_lower])
        return {"severity": "high,critical", "tags": ",".join(tags) if tags else None}

    async def run(self, targets: list[str], work_dir: Path, severity: str = "high,critical", rate_limit: int = 100, tags: str | None = None, templates: list[str] | None = None, dast: bool = False, concurrency: int | None = None, interactsh_url: str | None = None, interactsh_server: str | None = None, headless: bool = False) -> dict:
        domains = [self.runner.extract_domain(t) for t in targets]
        result = await self.runner.run_command(tool="nuclei", command=self.build_command(targets, work_dir, severity, rate_limit, tags, templates, dast, concurrency, interactsh_url, interactsh_server, headless), targets=domains)
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
            domain = self.runner.extract_domain(host)
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
