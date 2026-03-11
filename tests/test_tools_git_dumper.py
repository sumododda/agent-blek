import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.git_dumper import GitDumperTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

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

class TestGitDumperTool:
    def test_builds_command(self, runner, db):
        tool = GitDumperTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com", "/tmp/out")
        assert "git-dumper" in cmd
        assert "https://example.com/.git" in cmd
        assert "/tmp/out" in cmd

    def test_builds_command_with_git_suffix(self, runner, db):
        tool = GitDumperTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com/.git", "/tmp/out")
        assert "https://example.com/.git" in cmd

    async def test_run_stores_finding_in_db(self, runner, db):
        tool = GitDumperTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output="dumped successfully", raw_file=Path("/tmp/test.txt"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com")
        assert summary["success"] is True
        findings = await db.get_findings("test-corp")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "exposed-git-directory"
        assert findings[0]["severity"] == "high"

    async def test_run_handles_failure(self, runner, db):
        tool = GitDumperTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="404 not found")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com")
        assert summary["success"] is False
        assert summary["error"] == "404 not found"
        findings = await db.get_findings("test-corp")
        assert len(findings) == 0
