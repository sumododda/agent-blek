import pytest
from unittest.mock import patch
from pathlib import Path
from bba.orchestrator import Orchestrator
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner
from bba.db import Database

SCOPE = {"program": "test-corp", "in_scope": {"domains": ["*.example.com", "example.com"]}}

@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))
@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(default_rps=100), sanitizer=Sanitizer(), output_dir=tmp_path / "output")
@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()

class TestOrchestrator:
    async def test_full_pipeline_execution(self, runner, db, tmp_path):
        orch = Orchestrator(runner=runner, db=db, program="test-corp", work_dir=tmp_path)
        recon_result = {"subdomains": {"total": 5, "sources": {}}, "services": {"live": 3, "technologies": {}}, "urls": {"katana": 10, "gau": 20}}
        scan_result = {"services_scanned": 3, "nuclei": {"total": 2, "findings": [], "by_severity": {"high": 1, "critical": 1}}, "ffuf": {"total": 5, "results": [], "interesting": 1}}
        validation_results = []
        report_text = "# Bug Bounty Report: test-corp\n\nFindings here."
        with patch.object(orch, "_run_recon", return_value=recon_result), \
             patch.object(orch, "_run_scan", return_value=scan_result), \
             patch.object(orch, "_run_validation", return_value=validation_results), \
             patch.object(orch, "_generate_report", return_value=report_text):
            result = await orch.run("example.com")
        assert result["recon"]["subdomains"]["total"] == 5
        assert result["scan"]["nuclei"]["total"] == 2
        assert "report" in result

    async def test_skips_scan_when_no_services(self, runner, db, tmp_path):
        orch = Orchestrator(runner=runner, db=db, program="test-corp", work_dir=tmp_path)
        recon_result = {"subdomains": {"total": 0, "sources": {}}, "services": {"live": 0, "technologies": {}}, "urls": {"katana": 0, "gau": 0}}
        with patch.object(orch, "_run_recon", return_value=recon_result), \
             patch.object(orch, "_run_validation", return_value=[]), \
             patch.object(orch, "_generate_report", return_value="report"):
            result = await orch.run("example.com")
        assert result["scan"]["services_scanned"] == 0

    async def test_generates_final_summary(self, runner, db, tmp_path):
        orch = Orchestrator(runner=runner, db=db, program="test-corp", work_dir=tmp_path)
        recon_result = {"subdomains": {"total": 10, "sources": {"crtsh": 10}}, "services": {"live": 5, "technologies": {"nginx": 3}}, "urls": {"katana": 50, "gau": 100}}
        scan_result = {"services_scanned": 5, "nuclei": {"total": 3, "findings": [], "by_severity": {"critical": 1, "high": 2}}, "ffuf": {"total": 10, "results": [], "interesting": 2}}
        with patch.object(orch, "_run_recon", return_value=recon_result), \
             patch.object(orch, "_run_scan", return_value=scan_result), \
             patch.object(orch, "_run_validation", return_value=[]), \
             patch.object(orch, "_generate_report", return_value="report"):
            result = await orch.run("example.com")
        summary = orch.format_final_summary(result)
        assert "10 subdomains" in summary and "5 live" in summary and "critical" in summary.lower()

    def test_loads_scope_from_yaml(self, tmp_path):
        scope_file = tmp_path / "programs" / "test.yaml"
        scope_file.parent.mkdir(parents=True)
        scope_file.write_text("program: test-corp\nin_scope:\n  domains:\n    - '*.example.com'\n    - 'example.com'\n")
        config = Orchestrator.load_scope(scope_file)
        assert config.program == "test-corp" and "*.example.com" in config.in_scope_domains
