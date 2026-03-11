import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.nikto import NiktoTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

NIKTO_OUTPUT = json.dumps({
    "vulnerabilities": [
        {"id": "999990", "OSVDB": "0", "msg": "Retrieved x-powered-by header: Express", "method": "GET", "url": "/"},
        {"id": "999986", "OSVDB": "3092", "msg": "/admin/: Directory indexing found", "method": "GET", "url": "/admin/"},
    ]
})

NIKTO_LIST_OUTPUT = json.dumps([
    {"id": "111", "msg": "Server leaks inodes via ETags", "method": "GET", "url": "/"},
])

NIKTO_EMPTY = json.dumps({"vulnerabilities": []})


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


class TestNiktoTool:
    def test_builds_command(self, runner, db):
        tool = NiktoTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com")
        assert "nikto" in cmd
        assert "-h" in cmd
        assert "https://example.com" in cmd
        assert "-Format" in cmd
        assert "json" in cmd

    def test_parses_dict_output(self, runner, db):
        tool = NiktoTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(NIKTO_OUTPUT)
        assert len(results) == 2
        assert results[0]["id"] == "999990"
        assert "Express" in results[0]["msg"]
        assert results[1]["url"] == "/admin/"

    def test_parses_list_output(self, runner, db):
        tool = NiktoTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(NIKTO_LIST_OUTPUT)
        assert len(results) == 1
        assert "ETags" in results[0]["msg"]

    def test_parses_empty_output(self, runner, db):
        tool = NiktoTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(NIKTO_EMPTY)
        assert results == []

    def test_parses_invalid_json(self, runner, db):
        tool = NiktoTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("not json at all")
        assert results == []

    async def test_run_success(self, runner, db):
        tool = NiktoTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=NIKTO_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com")
        assert summary["total"] == 2
        assert len(summary["findings"]) == 2

    async def test_run_failure(self, runner, db):
        tool = NiktoTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="connection refused")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com")
        assert summary["total"] == 0
        assert summary["error"] == "connection refused"
