import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.gitleaks import GitleaksTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

GITLEAKS_OUTPUT = json.dumps([
    {"RuleID": "aws-access-key", "Match": "AKIA1234", "File": "secrets.py"},
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

class TestGitleaksTool:
    def test_builds_command(self, runner, db):
        tool = GitleaksTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("/tmp/source")
        assert "gitleaks" in cmd
        assert "detect" in cmd
        assert "--source" in cmd
        assert "/tmp/source" in cmd
        assert "--report-format" in cmd
        assert "json" in cmd

    def test_parses_json_output(self, runner, db):
        tool = GitleaksTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(GITLEAKS_OUTPUT)
        assert len(results) == 1
        assert results[0]["RuleID"] == "aws-access-key"
        assert results[0]["Match"] == "AKIA1234"
        assert results[0]["File"] == "secrets.py"

    def test_parses_empty_output(self, runner, db):
        tool = GitleaksTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_invalid_json(self, runner, db):
        tool = GitleaksTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("not json")
        assert results == []

    async def test_run_stores_in_db_on_success(self, runner, db):
        tool = GitleaksTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=GITLEAKS_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("/tmp/source")
        secrets = await db.get_secrets("test-corp")
        assert len(secrets) == 1
        assert summary["total"] == 1
        assert summary["secrets"][0]["type"] == "aws-access-key"
        assert summary["secrets"][0]["file"] == "secrets.py"

    async def test_run_stores_in_db_on_failure_with_output(self, runner, db):
        """gitleaks exits code 1 when leaks found, so output is parsed even on failure."""
        tool = GitleaksTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output=GITLEAKS_OUTPUT, error="exit code 1")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("/tmp/source")
        secrets = await db.get_secrets("test-corp")
        assert len(secrets) == 1
        assert summary["total"] == 1

    async def test_run_handles_failure(self, runner, db):
        tool = GitleaksTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="not found")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("/tmp/source")
        assert summary["total"] == 0
