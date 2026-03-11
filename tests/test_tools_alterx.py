import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.alterx import AlterxTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

ALTERX_OUTPUT = "dev-api.example.com\nstaging-api.example.com\napi-dev.example.com\n"

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

class TestAlterxTool:
    def test_builds_command(self, runner, db, tmp_path):
        tool = AlterxTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        cmd = tool.build_command(["api.example.com"], work_dir)
        assert "alterx" in cmd
        assert "-l" in cmd
        assert "-silent" in cmd

    def test_parses_output(self, runner, db):
        tool = AlterxTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(ALTERX_OUTPUT)
        assert len(results) == 3
        assert "dev-api.example.com" in results
        assert "staging-api.example.com" in results
        assert "api-dev.example.com" in results

    def test_parses_empty_output(self, runner, db):
        tool = AlterxTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    async def test_run_does_not_store_in_db(self, runner, db, tmp_path):
        tool = AlterxTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        mock_result = ToolResult(success=True, output=ALTERX_OUTPUT, raw_file=Path("/tmp/test.txt"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["api.example.com"], work_dir)
        assert summary["total"] == 3
        assert len(summary["permutations"]) == 3
        # AlterxTool does NOT store in DB
        subs = await db.get_subdomains("test-corp")
        assert len(subs) == 0

    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = AlterxTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        mock_result = ToolResult(success=False, output="", error="not found")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["api.example.com"], work_dir)
        assert summary["total"] == 0
        assert summary["error"] == "not found"
