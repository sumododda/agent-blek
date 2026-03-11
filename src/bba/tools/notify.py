"""Notification dispatcher via ProjectDiscovery notify."""
from __future__ import annotations

from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner


class NotifyTool:
    """Send alerts to Slack, Discord, Telegram via notify."""

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, message: str, provider_config: str | None = None,
                      bulk: bool = False) -> list[str]:
        cmd = ["notify"]
        if provider_config:
            cmd.extend(["-pc", provider_config])
        if not bulk:
            cmd.extend(["-data", message])
        return cmd

    def build_command_bulk(self, data_file: str, provider_config: str | None = None) -> list[str]:
        cmd = ["notify", "-data", data_file, "-bulk"]
        if provider_config:
            cmd.extend(["-pc", provider_config])
        return cmd

    def format_finding(self, finding: dict) -> str:
        severity = finding.get("severity", "unknown").upper()
        vuln_type = finding.get("vuln_type", "unknown")
        url = finding.get("url", "N/A")
        tool = finding.get("tool", "unknown")
        confidence = finding.get("confidence", 0)
        return (
            f"[{severity}] {vuln_type} | {url} | "
            f"Tool: {tool} | Confidence: {confidence:.0%}"
        )

    def format_diff(self, diff: dict, category: str, program: str) -> str:
        added = diff.get("added", [])
        removed = diff.get("removed", [])
        unchanged = diff.get("unchanged", 0)
        lines = [f"[DIFF] {program} — {category}: +{len(added)} new, -{len(removed)} removed, {unchanged} unchanged"]
        if added:
            lines.append(f"  New: {', '.join(added[:10])}")
            if len(added) > 10:
                lines.append(f"  ... and {len(added) - 10} more")
        if removed:
            lines.append(f"  Removed: {', '.join(removed[:10])}")
        return "\n".join(lines)

    def format_scan_complete(self, program: str, stats: dict) -> str:
        return (
            f"[SCAN COMPLETE] {program}\n"
            f"  Subdomains: {stats.get('subdomains', 0)}\n"
            f"  Services: {stats.get('services', 0)}\n"
            f"  Findings: {stats.get('findings', 0)}\n"
            f"  Critical/High: {stats.get('critical', 0)}/{stats.get('high', 0)}"
        )

    async def send(self, message: str, provider_config: str | None = None) -> dict:
        result = await self.runner.run_command(
            tool="notify",
            command=self.build_command(message, provider_config),
            targets=["notify"],
            timeout=30,
        )
        return {"sent": result.success, "error": result.error}

    async def send_finding(self, finding: dict, provider_config: str | None = None) -> dict:
        message = self.format_finding(finding)
        return await self.send(message, provider_config)

    async def send_bulk(self, messages: list[str], work_dir: Path,
                        provider_config: str | None = None) -> dict:
        data_file = work_dir / "notify_bulk.txt"
        data_file.write_text("\n".join(messages) + "\n")
        result = await self.runner.run_command(
            tool="notify",
            command=self.build_command_bulk(str(data_file), provider_config),
            targets=["notify"],
            timeout=60,
        )
        return {"sent": result.success, "count": len(messages), "error": result.error}
