import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.waymore import WaymoreTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

WAYMORE_OUTPUT = "https://example.com/api/v1\nhttps://example.com/login\nhttps://example.com/admin\n"

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

class TestWaymoreTool:
    def test_builds_command(self, runner, db):
        tool = WaymoreTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("example.com")
        assert "waymore" in cmd
        assert "-i" in cmd
        assert "example.com" in cmd
        assert "-mode" in cmd
        assert "U" in cmd

    def test_parses_plain_output(self, runner, db):
        tool = WaymoreTool(runner=runner, db=db, program="test-corp")
        urls = tool.parse_output(WAYMORE_OUTPUT)
        assert len(urls) == 3
        assert "https://example.com/api/v1" in urls
        assert "https://example.com/login" in urls
        assert "https://example.com/admin" in urls

    def test_parses_empty_output(self, runner, db):
        tool = WaymoreTool(runner=runner, db=db, program="test-corp")
        urls = tool.parse_output("")
        assert urls == []

    def test_filters_non_http_lines(self, runner, db):
        tool = WaymoreTool(runner=runner, db=db, program="test-corp")
        output = "https://example.com/api\n[INFO] Processing...\nhttps://example.com/login\n"
        urls = tool.parse_output(output)
        assert len(urls) == 2

    async def test_run_stores_in_db(self, runner, db):
        tool = WaymoreTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=WAYMORE_OUTPUT, raw_file=Path("/tmp/test.txt"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")
        assert summary["total"] == 3
        assert len(summary["urls"]) == 3

    async def test_run_handles_failure(self, runner, db):
        tool = WaymoreTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")
        assert summary["total"] == 0
        assert summary["error"] == "timeout"
