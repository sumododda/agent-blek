from __future__ import annotations
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner
from bba.tools.subfinder import SubfinderTool
from bba.tools.httpx_runner import HttpxTool
from bba.tools.katana import KatanaTool
from bba.tools.gau import GauTool

class ReconPipeline:
    def __init__(self, runner: ToolRunner, db: Database, program: str, work_dir: Path):
        self.runner = runner
        self.db = db
        self.program = program
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)

    async def _run_subfinder(self, domain: str) -> dict:
        tool = SubfinderTool(runner=self.runner, db=self.db, program=self.program)
        return await tool.run(domain)

    async def _run_httpx(self, domains: list[str]) -> dict:
        tool = HttpxTool(runner=self.runner, db=self.db, program=self.program)
        return await tool.run(domains, work_dir=self.work_dir)

    async def _run_katana(self, targets: list[str]) -> dict:
        tool = KatanaTool(runner=self.runner, db=self.db, program=self.program)
        return await tool.run(targets, work_dir=self.work_dir)

    async def _run_gau(self, domain: str) -> dict:
        tool = GauTool(runner=self.runner, db=self.db, program=self.program)
        return await tool.run(domain)

    async def run(self, domain: str) -> dict:
        sub_summary = await self._run_subfinder(domain)
        domains = sub_summary.get("domains", [])
        if domains:
            httpx_summary = await self._run_httpx(domains)
        else:
            httpx_summary = {"live": 0, "services": [], "technologies": {}}
        live_services = httpx_summary.get("services", [])
        if live_services:
            live_urls = [f"https://{s}" for s in live_services]
            katana_summary = await self._run_katana(live_urls)
        else:
            katana_summary = {"total": 0, "urls": []}
        if domains:
            gau_summary = await self._run_gau(domain)
        else:
            gau_summary = {"total": 0, "urls": []}
        return {
            "subdomains": {"total": sub_summary.get("total", 0), "sources": sub_summary.get("sources", {})},
            "services": {"live": httpx_summary.get("live", 0), "technologies": httpx_summary.get("technologies", {})},
            "urls": {"katana": katana_summary.get("total", 0), "gau": gau_summary.get("total", 0)},
        }

    def format_summary(self, result: dict) -> str:
        lines = []
        sub = result["subdomains"]
        lines.append(f"Found {sub['total']} subdomains")
        if sub.get("sources"):
            src_parts = [f"{k}: {v}" for k, v in sub["sources"].items()]
            lines.append(f"  Sources: {', '.join(src_parts)}")
        svc = result["services"]
        lines.append(f"{svc['live']} live HTTP services")
        if svc.get("technologies"):
            tech_parts = [f"{k}: {v}" for k, v in svc["technologies"].items()]
            lines.append(f"  Technologies: {', '.join(tech_parts)}")
        urls = result["urls"]
        lines.append(f"URLs harvested: {urls['katana']} (katana), {urls['gau']} (gau)")
        return "\n".join(lines)
