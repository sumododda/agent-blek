"""Out-of-band interaction detection via interactsh-client."""
from __future__ import annotations
import json
from bba.db import Database
from bba.tool_runner import ToolRunner


class InteractshTool:
    """Generate OOB callback URLs and poll for interactions."""

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_generate_command(self, count: int = 10, server: str | None = None) -> list[str]:
        cmd = ["interactsh-client", "-n", str(count), "-json", "-v"]
        if server:
            cmd.extend(["-server", server])
        return cmd

    def build_poll_command(self, session_file: str) -> list[str]:
        return ["interactsh-client", "-sf", session_file, "-json", "-poll"]

    def parse_interactions(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                if "protocol" in entry or "unique-id" in entry:
                    results.append(entry)
            except json.JSONDecodeError:
                # interactsh also outputs plain URLs during generation
                continue
        return results

    def parse_generated_urls(self, output: str) -> list[str]:
        urls = []
        for line in output.strip().splitlines():
            line = line.strip()
            if line and "." in line and not line.startswith("{"):
                urls.append(line)
        return urls

    async def generate_urls(self, count: int = 10, server: str | None = None) -> dict:
        result = await self.runner.run_command(
            tool="interactsh", command=self.build_generate_command(count, server),
            targets=["interactsh"], timeout=30,
        )
        if not result.success:
            return {"total": 0, "urls": [], "error": result.error}
        urls = self.parse_generated_urls(result.output)
        return {"total": len(urls), "urls": urls, "session_file": str(result.raw_file)}

    async def poll_interactions(self, session_file: str, domain: str) -> dict:
        result = await self.runner.run_command(
            tool="interactsh", command=self.build_poll_command(session_file),
            targets=["interactsh"], timeout=30,
        )
        if not result.success:
            return {"total": 0, "interactions": [], "error": result.error}
        interactions = self.parse_interactions(result.output)
        for interaction in interactions:
            protocol = interaction.get("protocol", "unknown")
            unique_id = interaction.get("unique-id", "")
            remote = interaction.get("remote-address", "")
            await self.db.add_finding(
                program=self.program, domain=domain,
                url=f"oob://{unique_id}",
                vuln_type=f"oob-{protocol}-interaction",
                severity="high", tool="interactsh",
                evidence=f"Protocol: {protocol}, Remote: {remote}, ID: {unique_id}",
                confidence=0.7,
            )
        return {"total": len(interactions), "interactions": interactions}
