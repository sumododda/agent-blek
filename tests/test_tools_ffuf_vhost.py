import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.ffuf import FfufVhostTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

VHOST_OUTPUT = "\n".join([
    json.dumps({"input": {"FUZZ": "dev"}, "url": "https://example.com", "status": 200}),
    json.dumps({"input": {"FUZZ": "staging"}, "url": "https://example.com", "status": 200}),
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


class TestFfufVhostTool:
    def test_builds_command(self, runner, db):
        tool = FfufVhostTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com", "/tmp/wordlist.txt", "example.com")
        assert "ffuf" in cmd
        assert "-H" in cmd
        assert "Host: FUZZ.example.com" in cmd

    def test_parses_output(self, runner, db):
        tool = FfufVhostTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(VHOST_OUTPUT)
        assert len(results) == 2

    def test_parses_empty_output(self, runner, db):
        tool = FfufVhostTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    async def test_run_stores_in_db(self, runner, db):
        tool = FfufVhostTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=VHOST_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com", "/tmp/wordlist.txt", "example.com")
        assert summary["total"] == 2
        assert "dev.example.com" in summary["vhosts"]
        assert "staging.example.com" in summary["vhosts"]
        subs = await db.get_subdomains("test-corp")
        assert len(subs) == 2

    async def test_run_handles_failure(self, runner, db):
        tool = FfufVhostTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com", "/tmp/wordlist.txt", "example.com")
        assert summary["total"] == 0
        assert summary["error"] == "timeout"
