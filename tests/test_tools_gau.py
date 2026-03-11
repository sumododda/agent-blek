import pytest
from unittest.mock import patch
from bba.tools.gau import GauTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {"program": "test-corp", "in_scope": {"domains": ["*.example.com", "example.com"]}}
GAU_OUTPUT = "https://example.com/login\nhttps://example.com/api/users\nhttps://example.com/search?q=test\n"

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

class TestGauTool:
    def test_builds_command(self, runner, db):
        tool = GauTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("example.com")
        assert "gau" in cmd
        assert "example.com" in cmd

    def test_parses_plain_output(self, runner, db):
        tool = GauTool(runner=runner, db=db, program="test-corp")
        urls = tool.parse_output(GAU_OUTPUT)
        assert len(urls) == 3
        assert "https://example.com/login" in urls

    def test_parses_empty_output(self, runner, db):
        tool = GauTool(runner=runner, db=db, program="test-corp")
        urls = tool.parse_output("")
        assert urls == []

    async def test_run_returns_summary(self, runner, db):
        tool = GauTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=GAU_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")
        assert summary["total"] == 3
        assert len(summary["urls"]) == 3

    async def test_run_handles_failure(self, runner, db):
        tool = GauTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="err")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")
        assert summary["total"] == 0
