import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.gowitness import GowitnessTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

GOWITNESS_OUTPUT = "\n".join([
    json.dumps({"url": "https://example.com", "filename": "screenshot_1.png", "status_code": 200, "title": "Example"}),
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

class TestGowitnessTool:
    def test_builds_command(self, runner, db, tmp_path):
        tool = GowitnessTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        cmd = tool.build_command(["https://example.com"], work_dir)
        assert "gowitness" in cmd
        assert "scan" in cmd
        assert "file" in cmd
        assert "-f" in cmd
        assert "--write-json" in cmd

    def test_parses_json_output(self, runner, db):
        tool = GowitnessTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(GOWITNESS_OUTPUT)
        assert len(results) == 1
        assert results[0]["url"] == "https://example.com"
        assert results[0]["filename"] == "screenshot_1.png"
        assert results[0]["status_code"] == 200
        assert results[0]["title"] == "Example"

    def test_parses_empty_output(self, runner, db):
        tool = GowitnessTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_output_with_invalid_lines(self, runner, db):
        tool = GowitnessTool(runner=runner, db=db, program="test-corp")
        output = json.dumps({"url": "https://example.com", "filename": "ss.png", "status_code": 200}) + "\nbad line\n"
        results = tool.parse_output(output)
        assert len(results) == 1

    async def test_run_stores_in_db(self, runner, db, tmp_path):
        tool = GowitnessTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        mock_result = ToolResult(success=True, output=GOWITNESS_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["https://example.com"], work_dir)
        screenshots = await db.get_screenshots("test-corp")
        assert len(screenshots) == 1
        assert screenshots[0]["url"] == "https://example.com"
        assert screenshots[0]["title"] == "Example"
        assert summary["total"] == 1

    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = GowitnessTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        mock_result = ToolResult(success=False, output="", error="chrome not found")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["https://example.com"], work_dir)
        assert summary["total"] == 0
        assert summary["error"] == "chrome not found"
