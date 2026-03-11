import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.uncover import UncoverTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

UNCOVER_OUTPUT = "\n".join([
    json.dumps({"host": "example.com", "ip": "1.2.3.4", "port": 443}),
    json.dumps({"host": "api.example.com", "ip": "5.6.7.8", "port": 8080}),
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

class TestUncoverTool:
    def test_builds_command(self, runner, db):
        tool = UncoverTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("example.com")
        assert "uncover" in cmd
        assert "-q" in cmd
        assert "example.com" in cmd
        assert "-json" in cmd
        assert "-silent" in cmd
        assert "-e" in cmd

    def test_builds_command_custom_engines(self, runner, db):
        tool = UncoverTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("example.com", engines="shodan")
        assert "shodan" in cmd

    def test_parses_json_output(self, runner, db):
        tool = UncoverTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(UNCOVER_OUTPUT)
        assert len(results) == 2
        assert results[0]["host"] == "example.com"
        assert results[0]["ip"] == "1.2.3.4"
        assert results[0]["port"] == 443

    def test_parses_empty_output(self, runner, db):
        tool = UncoverTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_output_with_invalid_lines(self, runner, db):
        tool = UncoverTool(runner=runner, db=db, program="test-corp")
        output = json.dumps({"host": "example.com", "ip": "1.2.3.4", "port": 443}) + "\nbad line\n"
        results = tool.parse_output(output)
        assert len(results) == 1

    async def test_run_stores_in_db(self, runner, db):
        tool = UncoverTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=UNCOVER_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")
        ports = await db.get_ports("test-corp")
        assert len(ports) == 2
        assert summary["total"] == 2
        assert summary["results"][0]["host"] == "example.com"
        assert summary["results"][0]["port"] == 443

    async def test_run_handles_failure(self, runner, db):
        tool = UncoverTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")
        assert summary["total"] == 0
        assert summary["error"] == "timeout"
