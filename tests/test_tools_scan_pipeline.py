import pytest
from unittest.mock import patch
from pathlib import Path
from bba.tools.scan_pipeline import ScanPipeline
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

class TestScanPipeline:
    async def test_runs_nuclei_on_all_services(self, runner, db, tmp_path):
        await db.add_service("test-corp", "api.example.com", "1.2.3.4", 443, 200, "API", "nginx,python")
        await db.add_service("test-corp", "shop.example.com", "5.6.7.8", 443, 200, "Shop", "apache,wordpress")
        pipeline = ScanPipeline(runner=runner, db=db, program="test-corp", work_dir=tmp_path)
        nuclei_summary = {"total": 2, "findings": [], "by_severity": {"high": 1, "critical": 1}}
        with patch.object(pipeline, "_run_nuclei", return_value=nuclei_summary) as mock_nuclei:
            result = await pipeline.run()
        mock_nuclei.assert_called_once()
        assert result["nuclei"]["total"] == 2

    async def test_runs_ffuf_on_services(self, runner, db, tmp_path):
        await db.add_service("test-corp", "shop.example.com", "5.6.7.8", 443, 200, "Shop", "apache")
        pipeline = ScanPipeline(runner=runner, db=db, program="test-corp", work_dir=tmp_path)
        nuclei_summary = {"total": 0, "findings": [], "by_severity": {}}
        ffuf_summary = {"total": 5, "results": [], "interesting": 2}
        with patch.object(pipeline, "_run_nuclei", return_value=nuclei_summary), \
             patch.object(pipeline, "_run_ffuf", return_value=ffuf_summary):
            result = await pipeline.run()
        assert result["ffuf"]["total"] == 5

    async def test_skips_scan_when_no_services(self, runner, db, tmp_path):
        pipeline = ScanPipeline(runner=runner, db=db, program="test-corp", work_dir=tmp_path)
        result = await pipeline.run()
        assert result["nuclei"]["total"] == 0 and result["services_scanned"] == 0

    def test_format_summary(self, runner, db, tmp_path):
        pipeline = ScanPipeline(runner=runner, db=db, program="test-corp", work_dir=tmp_path)
        result = {
            "services_scanned": 10,
            "nuclei": {"total": 5, "by_severity": {"critical": 1, "high": 2, "medium": 2}},
            "ffuf": {"total": 20, "interesting": 3},
        }
        text = pipeline.format_summary(result)
        assert "10 services" in text and "critical" in text.lower()
