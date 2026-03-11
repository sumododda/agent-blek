from __future__ import annotations
import json
from bba.db import Database
from bba.tool_runner import ToolRunner

class TrufflehogTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, target: str, scan_type: str = "git") -> list[str]:
        cmd = ["trufflehog", scan_type, target, "--json", "--no-update"]
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

    async def run(self, target: str, scan_type: str = "git") -> dict:
        result = await self.runner.run_command(
            tool="trufflehog",
            command=self.build_command(target, scan_type),
            targets=[target],
            timeout=600,
        )
        if not result.success:
            return {"total": 0, "secrets": [], "error": result.error}
        entries = self.parse_output(result.output)
        secrets = []
        for entry in entries:
            detector = entry.get("DetectorType", entry.get("detectorType", "unknown"))
            redacted = entry.get("Redacted", entry.get("redacted", ""))
            raw = entry.get("Raw", entry.get("raw", ""))
            source_meta = entry.get("SourceMetadata", entry.get("sourceMetadata", {}))
            source_file = ""
            if isinstance(source_meta, dict):
                data = source_meta.get("Data", source_meta.get("data", {}))
                if isinstance(data, dict):
                    git_data = data.get("Git", data.get("git", {}))
                    if isinstance(git_data, dict):
                        source_file = git_data.get("file", "")
            verified = entry.get("Verified", entry.get("verified", False))
            confidence = 0.95 if verified else 0.6
            secrets.append({
                "type": str(detector),
                "redacted": redacted,
                "verified": verified,
                "source_file": source_file,
            })
            await self.db.add_secret(
                self.program, str(detector), redacted or raw[:200],
                source_url=target, source_file=source_file,
                tool="trufflehog", confidence=confidence,
            )
        return {"total": len(secrets), "secrets": secrets}
