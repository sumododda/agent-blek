import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.feroxbuster import FeroxbusterTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

FEROXBUSTER_OUTPUT = "\n".join([
    json.dumps({"type": "response", "url": "https://example.com/admin", "status": 200}),
    json.dumps({"type": "response", "url": "https://example.com/.env", "status": 200}),
]) + "\n"

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

class TestFeroxbusterTool:
    def test_builds_command(self, runner, db):
        tool = FeroxbusterTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com")
        assert "feroxbuster" in cmd
        assert "-u" in cmd
        assert "https://example.com" in cmd
        assert "--json" in cmd
        assert "--silent" in cmd

    def test_parses_json_output(self, runner, db):
        tool = FeroxbusterTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(FEROXBUSTER_OUTPUT)
        assert len(results) == 2
        assert results[0]["url"] == "https://example.com/admin"
        assert results[0]["status"] == 200

    def test_parses_empty_output(self, runner, db):
        tool = FeroxbusterTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_output_with_invalid_lines(self, runner, db):
        tool = FeroxbusterTool(runner=runner, db=db, program="test-corp")
        output = json.dumps({"type": "response", "url": "https://example.com/admin", "status": 200}) + "\nbad line\n"
        results = tool.parse_output(output)
        assert len(results) == 1

    def test_detects_interesting_paths(self, runner, db):
        tool = FeroxbusterTool(runner=runner, db=db, program="test-corp")
        assert tool._is_interesting("https://example.com/admin") is True
        assert tool._is_interesting("https://example.com/.env") is True
        assert tool._is_interesting("https://example.com/about") is False

    async def test_run_stores_in_db(self, runner, db):
        tool = FeroxbusterTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=FEROXBUSTER_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com")
        assert summary["total"] == 2
        assert len(summary["interesting"]) == 2
        findings = await db.get_findings("test-corp")
        assert len(findings) >= 2

    async def test_run_handles_failure(self, runner, db):
        tool = FeroxbusterTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com")
        assert summary["total"] == 0
        assert summary["error"] == "timeout"
