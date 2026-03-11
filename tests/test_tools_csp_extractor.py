import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.csp_extractor import CspExtractorTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

CSP_HEADER = "default-src 'self'; script-src https://cdn.example.com https://api.internal.example.com; connect-src https://ws.example.com https://analytics.thirdparty.io; img-src *"


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


class TestCspExtractorTool:
    def test_parse_csp_extracts_domains(self, runner, db):
        tool = CspExtractorTool(runner=runner, db=db, program="test-corp")
        domains = tool.parse_csp(CSP_HEADER)
        assert "cdn.example.com" in domains
        assert "api.internal.example.com" in domains
        assert "ws.example.com" in domains
        assert "analytics.thirdparty.io" in domains

    def test_parse_csp_empty(self, runner, db):
        tool = CspExtractorTool(runner=runner, db=db, program="test-corp")
        domains = tool.parse_csp("")
        assert domains == []

    def test_parse_csp_no_domains(self, runner, db):
        tool = CspExtractorTool(runner=runner, db=db, program="test-corp")
        domains = tool.parse_csp("default-src 'self' 'unsafe-inline'")
        assert domains == []

    async def test_run_stores_domains(self, runner, db):
        tool = CspExtractorTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=CSP_HEADER, raw_file=None)
        with patch.object(runner, "run_http_request", return_value=mock_result):
            result = await tool.run(["https://example.com"])
        assert result["total"] >= 3
        subs = await db.get_subdomains("test-corp")
        assert len(subs) >= 3

    async def test_run_handles_failure(self, runner, db):
        tool = CspExtractorTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_http_request", return_value=mock_result):
            result = await tool.run(["https://example.com"])
        assert result["total"] == 0
