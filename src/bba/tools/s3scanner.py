from __future__ import annotations
import json
from bba.db import Database
from bba.tool_runner import ToolRunner

class S3ScannerTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, bucket_name: str) -> list[str]:
        return ["s3scanner", "scan", "--bucket", bucket_name]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                # s3scanner may emit plain text — wrap as raw line
                results.append({"raw": line})
        return results

    def _check_accessible(self, entries: list[dict], raw_output: str) -> tuple[bool, list]:
        """Inspect parsed entries and raw output for accessibility signals."""
        accessible = False
        permissions = []
        for entry in entries:
            if entry.get("bucket_exists") or entry.get("exists"):
                accessible = True
            perms = entry.get("permissions", entry.get("acl", {}))
            if perms:
                permissions.append(perms)
            # Plain-text output analysis
            raw = entry.get("raw", "")
            if raw and any(kw in raw.lower() for kw in ("exists", "open", "readable", "listable", "public")):
                accessible = True
                permissions.append({"raw_signal": raw})
        # Also check raw output directly for common s3scanner signals
        for kw in ("exists", "AuthUsers", "AllUsers", "FULL_CONTROL", "READ", "WRITE"):
            if kw in raw_output:
                accessible = True
        return accessible, permissions

    async def run(self, bucket_name: str) -> dict:
        bucket_url = f"https://{bucket_name}.s3.amazonaws.com"
        result = await self.runner.run_command(
            tool="s3scanner",
            command=self.build_command(bucket_name),
            targets=[bucket_name],
            timeout=120,
        )
        if not result.success:
            return {"bucket": bucket_name, "accessible": False, "error": result.error}
        entries = self.parse_output(result.output)
        accessible, permissions = self._check_accessible(entries, result.output)
        if accessible:
            await self.db.add_finding(
                self.program, bucket_name, bucket_url,
                "s3-bucket-accessible", "medium", "s3scanner",
                f"S3 bucket '{bucket_name}' is accessible. Permissions: {permissions}",
                0.8,
            )
        return {
            "bucket": bucket_name,
            "accessible": accessible,
            "permissions": permissions,
        }
