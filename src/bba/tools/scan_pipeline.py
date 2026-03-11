from __future__ import annotations
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner
from bba.tools.nuclei import NucleiTool
from bba.tools.ffuf import FfufTool

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

class ScanPipeline:
    def __init__(self, runner: ToolRunner, db: Database, program: str, work_dir: Path):
        self.runner = runner
        self.db = db
        self.program = program
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)

    async def _run_nuclei(self, targets: list[str], technologies: list[str]) -> dict:
        tool = NucleiTool(runner=self.runner, db=self.db, program=self.program)
        opts = tool.select_scan_options(technologies=technologies)
        return await tool.run(targets=targets, work_dir=self.work_dir, severity=opts["severity"], tags=opts.get("tags"))

    async def _run_ffuf(self, targets: list[str]) -> dict:
        tool = FfufTool(runner=self.runner, db=self.db, program=self.program)
        all_results = {"total": 0, "results": [], "interesting": 0}
        for target in targets:
            summary = await tool.run(target_url=f"{target}/FUZZ", wordlist=DEFAULT_WORDLIST)
            all_results["total"] += summary.get("total", 0)
            all_results["results"].extend(summary.get("results", []))
            all_results["interesting"] += summary.get("interesting", 0)
        return all_results

    async def run(self) -> dict:
        services = await self.db.get_services(self.program)
        if not services:
            return {"services_scanned": 0, "nuclei": {"total": 0, "findings": [], "by_severity": {}}, "ffuf": {"total": 0, "results": [], "interesting": 0}}
        targets = []
        all_techs = []
        for svc in services:
            port = svc.get("port", 443)
            scheme = "https" if port == 443 else "http"
            targets.append(f"{scheme}://{svc['domain']}")
            if svc.get("technologies"):
                all_techs.extend(svc["technologies"].split(","))
        nuclei_summary = await self._run_nuclei(targets, all_techs)
        try:
            ffuf_summary = await self._run_ffuf(targets)
        except Exception:
            ffuf_summary = {"total": 0, "results": [], "interesting": 0}
        return {"services_scanned": len(services), "nuclei": nuclei_summary, "ffuf": ffuf_summary}

    def format_summary(self, result: dict) -> str:
        lines = []
        lines.append(f"Scanned {result['services_scanned']} services")
        nuclei = result["nuclei"]
        if nuclei["total"] > 0:
            lines.append(f"Nuclei: {nuclei['total']} findings")
            for sev, count in nuclei.get("by_severity", {}).items():
                lines.append(f"  {sev}: {count}")
        else:
            lines.append("Nuclei: no findings")
        ffuf = result["ffuf"]
        lines.append(f"Ffuf: {ffuf['total']} paths found, {ffuf.get('interesting', 0)} interesting")
        return "\n".join(lines)
