import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.trufflehog import TrufflehogTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

TRUFFLEHOG_OUTPUT = json.dumps({
    "DetectorType": "AWS",
    "Redacted": "AKIA****",
    "Verified": True,
    "SourceMetadata": {"Data": {"Git": {"file": "config.py"}}},
}) + "\n"

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

class TestTrufflehogTool:
    def test_builds_command(self, runner, db):
        tool = TrufflehogTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://github.com/example/repo")
        assert "trufflehog" in cmd
        assert "git" in cmd
        assert "https://github.com/example/repo" in cmd
        assert "--json" in cmd
        assert "--no-update" in cmd

    def test_builds_command_custom_scan_type(self, runner, db):
        tool = TrufflehogTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("/tmp/source", scan_type="filesystem")
        assert "filesystem" in cmd

    def test_parses_json_output(self, runner, db):
        tool = TrufflehogTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(TRUFFLEHOG_OUTPUT)
        assert len(results) == 1
        assert results[0]["DetectorType"] == "AWS"
        assert results[0]["Verified"] is True

    def test_parses_empty_output(self, runner, db):
        tool = TrufflehogTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_output_with_invalid_lines(self, runner, db):
        tool = TrufflehogTool(runner=runner, db=db, program="test-corp")
        output = json.dumps({"DetectorType": "AWS", "Redacted": "AKIA****", "Verified": True}) + "\nbad line\n"
        results = tool.parse_output(output)
        assert len(results) == 1

    async def test_run_stores_in_db(self, runner, db):
        tool = TrufflehogTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=TRUFFLEHOG_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://github.com/example/repo")
        secrets = await db.get_secrets("test-corp")
        assert len(secrets) == 1
        assert summary["total"] == 1
        assert summary["secrets"][0]["verified"] is True
        assert summary["secrets"][0]["source_file"] == "config.py"

    async def test_run_handles_failure(self, runner, db):
        tool = TrufflehogTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="repo not found")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://github.com/example/repo")
        assert summary["total"] == 0
        assert summary["error"] == "repo not found"
