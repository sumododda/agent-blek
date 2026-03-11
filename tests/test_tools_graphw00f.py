import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.graphw00f import Graphw00fTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

GRAPHW00F_DETECTED = json.dumps({"detected": True, "engine": "GraphQL Yoga"})
GRAPHW00F_NOT_DETECTED = json.dumps({"detected": False, "engine": None})

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

class TestGraphw00fTool:
    def test_builds_command(self, runner, db):
        tool = Graphw00fTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com/graphql")
        assert "graphw00f" in cmd
        assert "-t" in cmd
        assert "https://example.com/graphql" in cmd
        assert "--json" in cmd

    def test_parses_detected_output(self, runner, db):
        tool = Graphw00fTool(runner=runner, db=db, program="test-corp")
        result = tool.parse_output(GRAPHW00F_DETECTED)
        assert result["detected"] is True
        assert result["engine"] == "GraphQL Yoga"

    def test_parses_not_detected_output(self, runner, db):
        tool = Graphw00fTool(runner=runner, db=db, program="test-corp")
        result = tool.parse_output(GRAPHW00F_NOT_DETECTED)
        assert result["detected"] is False

    def test_parses_empty_output(self, runner, db):
        tool = Graphw00fTool(runner=runner, db=db, program="test-corp")
        result = tool.parse_output("")
        assert result == {}

    def test_parses_invalid_json(self, runner, db):
        tool = Graphw00fTool(runner=runner, db=db, program="test-corp")
        result = tool.parse_output("not valid json")
        assert result == {}

    async def test_run_detected_stores_finding(self, runner, db):
        tool = Graphw00fTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=GRAPHW00F_DETECTED, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com/graphql")
        assert summary["detected"] is True
        assert summary["engine"] == "GraphQL Yoga"
        findings = await db.get_findings("test-corp")
        assert len(findings) >= 1

    async def test_run_not_detected_no_finding(self, runner, db):
        tool = Graphw00fTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=GRAPHW00F_NOT_DETECTED, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com/graphql")
        assert summary["detected"] is False
        findings = await db.get_findings("test-corp")
        assert len(findings) == 0

    async def test_run_handles_failure(self, runner, db):
        tool = Graphw00fTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="connection refused")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com/graphql")
        assert summary["detected"] is False
        assert summary["error"] == "connection refused"
