import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.subfinder import SubfinderTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

SUBFINDER_OUTPUT = "\n".join([
    json.dumps({"host": "api.example.com", "source": "crtsh"}),
    json.dumps({"host": "shop.example.com", "source": "virustotal"}),
    json.dumps({"host": "mail.example.com", "source": "hackertarget"}),
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

class TestSubfinderTool:
    def test_builds_command(self, runner, db):
        tool = SubfinderTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("example.com")
        assert "subfinder" in cmd
        assert "-d" in cmd
        assert "example.com" in cmd
        assert "-silent" in cmd
        assert "-json" in cmd

    def test_parses_json_output(self, runner, db):
        tool = SubfinderTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(SUBFINDER_OUTPUT)
        assert len(results) == 3
        assert results[0]["host"] == "api.example.com"
        assert results[1]["source"] == "virustotal"

    def test_parses_empty_output(self, runner, db):
        tool = SubfinderTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_output_with_invalid_lines(self, runner, db):
        tool = SubfinderTool(runner=runner, db=db, program="test-corp")
        output = json.dumps({"host": "a.example.com", "source": "x"}) + "\nbad line\n"
        results = tool.parse_output(output)
        assert len(results) == 1

    async def test_run_stores_in_db(self, runner, db):
        tool = SubfinderTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=SUBFINDER_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")
        subs = await db.get_subdomains("test-corp")
        assert len(subs) == 3
        assert summary["total"] == 3
        assert summary["sources"]["crtsh"] == 1

    async def test_run_returns_summary(self, runner, db):
        tool = SubfinderTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=SUBFINDER_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")
        assert "total" in summary
        assert "domains" in summary
        assert "sources" in summary

    async def test_run_handles_failure(self, runner, db):
        tool = SubfinderTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="not found")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")
        assert summary["total"] == 0
        assert summary["error"] == "not found"
