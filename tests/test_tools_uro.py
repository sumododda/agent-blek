from __future__ import annotations
import pytest
from unittest.mock import patch
from bba.tools.uro import UroTool
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}


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


class TestUroTool:
    def test_build_command(self, runner, db, tmp_path):
        tool = UroTool(runner=runner, db=db, program="test-corp")
        urls = ["https://example.com/a?id=1", "https://example.com/a?id=2"]
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        cmd = tool.build_command(urls, work_dir)
        assert cmd[0] == "uro"
        assert "-i" in cmd

    def test_build_command_writes_input_file(self, runner, db, tmp_path):
        tool = UroTool(runner=runner, db=db, program="test-corp")
        urls = ["https://example.com/a?id=1", "https://example.com/b?name=test"]
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        cmd = tool.build_command(urls, work_dir)
        input_file = work_dir / "uro_input.txt"
        assert input_file.exists()
        content = input_file.read_text()
        assert "https://example.com/a?id=1" in content
        assert "https://example.com/b?name=test" in content

    def test_parse_output(self, runner, db):
        tool = UroTool(runner=runner, db=db, program="test-corp")
        output = "https://example.com/a?id=1\nhttps://example.com/b?name=test\n"
        result = tool.parse_output(output)
        assert len(result) == 2
        assert "https://example.com/a?id=1" in result

    def test_parse_empty_output(self, runner, db):
        tool = UroTool(runner=runner, db=db, program="test-corp")
        assert tool.parse_output("") == []
        assert tool.parse_output("\n\n") == []

    def test_parse_output_strips_whitespace(self, runner, db):
        tool = UroTool(runner=runner, db=db, program="test-corp")
        output = "  https://example.com/a  \nhttps://example.com/b\n"
        result = tool.parse_output(output)
        assert "https://example.com/a" in result
        assert "https://example.com/b" in result

    @pytest.mark.asyncio
    async def test_run_returns_deduped_urls(self, runner, db, tmp_path):
        tool = UroTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output="https://example.com/a?id=1\nhttps://example.com/b\n", raw_file=None, error=None, duration=1.0)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run(["https://example.com/a?id=1", "https://example.com/a?id=2", "https://example.com/b"], tmp_path)
        assert result["total"] == 2
        assert "https://example.com/a?id=1" in result["urls"]

    @pytest.mark.asyncio
    async def test_run_includes_reduced_by(self, runner, db, tmp_path):
        tool = UroTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output="https://example.com/a?id=1\n", raw_file=None, error=None, duration=1.0)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run(["https://example.com/a?id=1", "https://example.com/a?id=2"], tmp_path)
        assert result["original_count"] == 2
        assert result["reduced_by"] == 1

    @pytest.mark.asyncio
    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = UroTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", raw_file=None, error="crash", duration=0.1)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run(["https://example.com/a"], tmp_path)
        assert result["total"] == 0
        assert "error" in result

    @pytest.mark.asyncio
    async def test_run_empty_input(self, runner, db, tmp_path):
        tool = UroTool(runner=runner, db=db, program="test-corp")
        result = await tool.run([], tmp_path)
        assert result["total"] == 0
        assert result["original_count"] == 0
