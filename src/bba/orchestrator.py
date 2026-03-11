from __future__ import annotations
from pathlib import Path
from bba.db import Database
from bba.reporter import ReportGenerator
from bba.scope import ScopeConfig
from bba.tool_runner import ToolRunner
from bba.tools.pipeline import ReconPipeline
from bba.tools.scan_pipeline import ScanPipeline
from bba.validator import FindingValidator

class Orchestrator:
    def __init__(self, runner: ToolRunner, db: Database, program: str, work_dir: Path):
        self.runner = runner
        self.db = db
        self.program = program
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def load_scope(scope_file: Path) -> ScopeConfig:
        return ScopeConfig.from_yaml(scope_file)

    async def _run_recon(self, domain: str) -> dict:
        pipeline = ReconPipeline(runner=self.runner, db=self.db, program=self.program, work_dir=self.work_dir / "recon")
        return await pipeline.run(domain)

    async def _run_scan(self) -> dict:
        pipeline = ScanPipeline(runner=self.runner, db=self.db, program=self.program, work_dir=self.work_dir / "scan")
        return await pipeline.run()

    async def _run_validation(self) -> list:
        validator = FindingValidator(runner=self.runner, db=self.db)
        return await validator.validate_findings(self.program)

    async def _generate_report(self) -> str:
        reporter = ReportGenerator(db=self.db)
        await reporter.save(self.program, output_dir=self.work_dir / "reports")
        return await reporter.generate(self.program)

    async def run(self, domain: str) -> dict:
        recon_result = await self._run_recon(domain)
        if recon_result["services"]["live"] > 0:
            scan_result = await self._run_scan()
        else:
            scan_result = {"services_scanned": 0, "nuclei": {"total": 0, "findings": [], "by_severity": {}}, "ffuf": {"total": 0, "results": [], "interesting": 0}}
        validation_results = await self._run_validation()
        report = await self._generate_report()
        return {
            "recon": recon_result,
            "scan": scan_result,
            "validation": {"total": len(validation_results), "results": [{"id": r.finding_id, "status": r.status, "confidence": r.confidence} for r in validation_results]},
            "report": report,
        }

    def format_final_summary(self, result: dict) -> str:
        lines = []
        recon = result["recon"]
        lines.append(f"Recon: {recon['subdomains']['total']} subdomains, {recon['services']['live']} live services")
        scan = result["scan"]
        if scan["services_scanned"] > 0:
            nuclei = scan["nuclei"]
            lines.append(f"Scan: {nuclei['total']} findings from {scan['services_scanned']} services")
            for sev, count in nuclei.get("by_severity", {}).items():
                lines.append(f"  {sev}: {count}")
        else:
            lines.append("Scan: skipped (no live services)")
        validation = result.get("validation", {})
        lines.append(f"Validation: {validation.get('total', 0)} findings re-tested")
        return "\n".join(lines)
