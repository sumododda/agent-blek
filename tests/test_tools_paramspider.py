import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.paramspider import ParamspiderTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

PARAMSPIDER_OUTPUT = "https://example.com/search?q=FUZZ\nhttps://example.com/api?id=FUZZ\n"

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

class TestParamspiderTool:
    def test_builds_command(self, runner, db):
        tool = ParamspiderTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("example.com")
        assert "paramspider" in cmd
        assert "-d" in cmd
        assert "example.com" in cmd

    def test_parses_output(self, runner, db):
        tool = ParamspiderTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(PARAMSPIDER_OUTPUT)
        assert len(results) == 2
        assert "https://example.com/search?q=FUZZ" in results
        assert "https://example.com/api?id=FUZZ" in results

    def test_parses_empty_output(self, runner, db):
        tool = ParamspiderTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_filters_non_http_lines(self, runner, db):
        tool = ParamspiderTool(runner=runner, db=db, program="test-corp")
        output = "https://example.com/search?q=FUZZ\nsome debug line\n[INFO] processing\n"
        results = tool.parse_output(output)
        assert len(results) == 1

    async def test_run_stores_in_db(self, runner, db):
        tool = ParamspiderTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=PARAMSPIDER_OUTPUT, raw_file=Path("/tmp/test.txt"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")
        urls = await db.get_urls("test-corp")
        assert len(urls) == 2
        assert summary["total"] == 2

    async def test_run_handles_failure(self, runner, db):
        tool = ParamspiderTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="not found")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")
        assert summary["total"] == 0
        assert summary["error"] == "not found"
