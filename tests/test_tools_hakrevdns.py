import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.hakrevdns import HakrevdnsTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

HAKREVDNS_OUTPUT = "1.2.3.4\tapi.example.com\n5.6.7.8\tmail.example.com\n"

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

class TestHakrevdnsTool:
    def test_builds_command(self, runner, db, tmp_path):
        tool = HakrevdnsTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        cmd = tool.build_command(["1.2.3.4", "5.6.7.8"], work_dir)
        assert "hakrevdns" in cmd
        assert "-l" in cmd
        assert "-t" in cmd

    def test_parses_output(self, runner, db):
        tool = HakrevdnsTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(HAKREVDNS_OUTPUT)
        assert len(results) == 2
        assert results[0]["ip"] == "1.2.3.4"
        assert results[0]["hostname"] == "api.example.com"
        assert results[1]["ip"] == "5.6.7.8"
        assert results[1]["hostname"] == "mail.example.com"

    def test_parses_empty_output(self, runner, db):
        tool = HakrevdnsTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_output_with_trailing_dot(self, runner, db):
        tool = HakrevdnsTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("1.2.3.4\tapi.example.com.\n")
        assert len(results) == 1
        assert results[0]["hostname"] == "api.example.com"

    async def test_run_stores_in_db(self, runner, db, tmp_path):
        tool = HakrevdnsTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        mock_result = ToolResult(success=True, output=HAKREVDNS_OUTPUT, raw_file=Path("/tmp/test.txt"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["1.2.3.4", "5.6.7.8"], work_dir)
        subs = await db.get_subdomains("test-corp")
        assert len(subs) == 2
        assert summary["total"] == 2
        assert summary["unique_hostnames"] == 2

    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = HakrevdnsTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["1.2.3.4"], work_dir)
        assert summary["total"] == 0
        assert summary["error"] == "timeout"
