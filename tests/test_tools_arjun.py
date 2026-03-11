import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.arjun import ArjunTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

ARJUN_OUTPUT = json.dumps({"https://example.com/api": ["id", "name", "page"]})

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

class TestArjunTool:
    def test_builds_command(self, runner, db):
        tool = ArjunTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com/api")
        assert "arjun" in cmd
        assert "-u" in cmd
        assert "https://example.com/api" in cmd
        assert "--json" in cmd

    def test_parses_json_output(self, runner, db):
        tool = ArjunTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(ARJUN_OUTPUT)
        assert len(results) == 1
        assert results[0]["url"] == "https://example.com/api"
        assert results[0]["params"] == ["id", "name", "page"]

    def test_parses_empty_output(self, runner, db):
        tool = ArjunTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_invalid_json(self, runner, db):
        tool = ArjunTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("not json")
        assert results == []

    async def test_run_stores_in_db(self, runner, db):
        tool = ArjunTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=ARJUN_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com/api")
        assert summary["total"] == 3
        assert "id" in summary["params"]
        assert "name" in summary["params"]
        assert "page" in summary["params"]

    async def test_run_handles_failure(self, runner, db):
        tool = ArjunTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="connection refused")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com/api")
        assert summary["total"] == 0
        assert summary["error"] == "connection refused"
