import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.wafw00f import Wafw00fTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

WAFW00F_DETECTED = json.dumps([
    {"url": "https://example.com", "detected": True, "firewall": "Cloudflare"},
])

WAFW00F_NOT_DETECTED = json.dumps([
    {"url": "https://example.com", "detected": False, "firewall": ""},
])

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

class TestWafw00fTool:
    def test_builds_command(self, runner, db):
        tool = Wafw00fTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com")
        assert "wafw00f" in cmd
        assert "https://example.com" in cmd

    def test_parses_detected_output(self, runner, db):
        tool = Wafw00fTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(WAFW00F_DETECTED)
        assert len(results) == 1
        assert results[0]["detected"] is True
        assert results[0]["firewall"] == "Cloudflare"

    def test_parses_not_detected_output(self, runner, db):
        tool = Wafw00fTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(WAFW00F_NOT_DETECTED)
        assert len(results) == 1
        assert results[0]["detected"] is False

    def test_parses_empty_output(self, runner, db):
        tool = Wafw00fTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    async def test_run_detected(self, runner, db):
        tool = Wafw00fTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=WAFW00F_DETECTED, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com")
        assert summary["detected"] is True
        assert summary["waf"] == "Cloudflare"

    async def test_run_not_detected(self, runner, db):
        tool = Wafw00fTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=WAFW00F_NOT_DETECTED, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com")
        assert summary["detected"] is False
        assert summary["waf"] is None

    async def test_run_handles_failure(self, runner, db):
        tool = Wafw00fTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="connection refused")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com")
        assert summary["detected"] is False
        assert summary["error"] == "connection refused"
