"""High-level notification dispatcher for findings and diffs."""
from __future__ import annotations

from bba.db import Database

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class Notifier:
    def __init__(self, db: Database, provider_config: str | None = None):
        self.db = db
        self.provider_config = provider_config

    async def _send_message(self, message: str):
        """Send via notify CLI. Override in tests."""
        import asyncio
        cmd = ["notify"]
        if self.provider_config:
            cmd.extend(["-pc", self.provider_config])
        cmd.extend(["-data", message])
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

    async def notify_findings(self, program: str, severity_threshold: str = "medium",
                              status: str = "new"):
        threshold = SEVERITY_ORDER.get(severity_threshold, 2)
        findings = await self.db.get_findings(program, status=status)
        for f in findings:
            sev_level = SEVERITY_ORDER.get(f.get("severity", "info"), 0)
            if sev_level >= threshold:
                severity = f.get("severity", "unknown").upper()
                vuln_type = f.get("vuln_type", "unknown")
                url = f.get("url", "N/A")
                tool = f.get("tool", "unknown")
                msg = f"[{severity}] {vuln_type} | {url} | Tool: {tool}"
                await self._send_message(msg)

    async def notify_diff(self, program: str, category: str, diff: dict):
        added = diff.get("added", [])
        removed = diff.get("removed", [])
        if not added and not removed:
            return
        lines = [f"[DIFF] {program} — {category}: +{len(added)} new, -{len(removed)} removed"]
        if added:
            lines.append(f"  New: {', '.join(added[:10])}")
        if removed:
            lines.append(f"  Removed: {', '.join(removed[:10])}")
        await self._send_message("\n".join(lines))

    async def notify_scan_complete(self, program: str, stats: dict):
        msg = (
            f"[SCAN COMPLETE] {program}\n"
            f"  Findings: {stats.get('total', 0)} | "
            f"Critical: {stats.get('critical', 0)} | High: {stats.get('high', 0)}"
        )
        await self._send_message(msg)
