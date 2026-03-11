import pytest
from unittest.mock import patch
from pathlib import Path
from bba.tools.pipeline import ReconPipeline
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

class TestReconPipeline:
    async def test_pipeline_runs_subfinder_then_httpx(self, runner, db, tmp_path):
        pipeline = ReconPipeline(runner=runner, db=db, program="test-corp", work_dir=tmp_path)
        subfinder_summary = {"total": 3, "domains": ["api.example.com", "shop.example.com", "mail.example.com"], "sources": {"crtsh": 2, "virustotal": 1}}
        httpx_summary = {"live": 2, "services": ["api.example.com", "shop.example.com"], "technologies": {"nginx": 1, "apache": 1}}
        katana_summary = {"total": 5, "urls": ["https://api.example.com/v1"] * 5}
        gau_summary = {"total": 10, "urls": ["https://example.com/page"] * 10}
        with patch.object(pipeline, "_run_subfinder", return_value=subfinder_summary), \
             patch.object(pipeline, "_run_httpx", return_value=httpx_summary), \
             patch.object(pipeline, "_run_katana", return_value=katana_summary), \
             patch.object(pipeline, "_run_gau", return_value=gau_summary):
            result = await pipeline.run("example.com")
        assert result["subdomains"]["total"] == 3
        assert result["services"]["live"] == 2
        assert result["urls"]["katana"] == 5
        assert result["urls"]["gau"] == 10

    async def test_pipeline_skips_httpx_when_no_subdomains(self, runner, db, tmp_path):
        pipeline = ReconPipeline(runner=runner, db=db, program="test-corp", work_dir=tmp_path)
        subfinder_summary = {"total": 0, "domains": [], "sources": {}}
        with patch.object(pipeline, "_run_subfinder", return_value=subfinder_summary):
            result = await pipeline.run("example.com")
        assert result["subdomains"]["total"] == 0
        assert result["services"]["live"] == 0

    def test_format_summary_for_llm(self, runner, db, tmp_path):
        pipeline = ReconPipeline(runner=runner, db=db, program="test-corp", work_dir=tmp_path)
        result = {
            "subdomains": {"total": 100, "sources": {"crtsh": 60, "virustotal": 40}},
            "services": {"live": 45, "technologies": {"nginx": 20, "apache": 15, "wordpress": 10}},
            "urls": {"katana": 500, "gau": 1200},
        }
        text = pipeline.format_summary(result)
        assert "100 subdomains" in text
        assert "45 live" in text
        assert "nginx" in text
