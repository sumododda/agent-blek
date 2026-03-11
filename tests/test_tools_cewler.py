import pytest
from unittest.mock import patch
from pathlib import Path
from bba.tools.cewler import CewlerTool
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {"program": "test", "in_scope": {"domains": ["*.example.com"], "cidrs": []}, "out_of_scope": {}}

@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))

@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(), sanitizer=Sanitizer(), output_dir=tmp_path / "output")

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestCewlerTool:
    def test_build_command(self, runner, db):
        tool = CewlerTool(runner=runner, db=db, program="test")
        cmd = tool.build_command("https://example.com")
        assert "cewler" in cmd[0]
        assert "-u" in cmd
        assert "-d" in cmd

    def test_build_command_with_output(self, runner, db):
        tool = CewlerTool(runner=runner, db=db, program="test")
        cmd = tool.build_command("https://example.com", output_file="/tmp/words.txt")
        assert "-o" in cmd
        assert "/tmp/words.txt" in cmd

    def test_build_command_custom_depth(self, runner, db):
        tool = CewlerTool(runner=runner, db=db, program="test")
        cmd = tool.build_command("https://example.com", depth=5)
        idx = cmd.index("-d")
        assert cmd[idx + 1] == "5"

    def test_parse_output(self, runner, db):
        tool = CewlerTool(runner=runner, db=db, program="test")
        output = "admin\npassword\nlogin\nab\n"  # "ab" too short (<=2)
        result = tool.parse_output(output)
        assert len(result) == 3
        assert "ab" not in result

    def test_parse_output_empty(self, runner, db):
        tool = CewlerTool(runner=runner, db=db, program="test")
        assert tool.parse_output("") == []

    @pytest.mark.asyncio
    async def test_run_success(self, runner, db, tmp_path):
        tool = CewlerTool(runner=runner, db=db, program="test")
        mock = ToolResult(success=True, output="admin\nlogin\npassword\ndashboard\n", raw_file=None, error=None, duration=5.0)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run("https://example.com", tmp_path)
        assert result["total"] == 4
        assert result["url"] == "https://example.com"

    @pytest.mark.asyncio
    async def test_run_failure(self, runner, db, tmp_path):
        tool = CewlerTool(runner=runner, db=db, program="test")
        mock = ToolResult(success=False, output="", raw_file=None, error="not found", duration=0.5)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run("https://example.com", tmp_path)
        assert result["total"] == 0
        assert "error" in result
