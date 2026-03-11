"""Tests for ghauri advanced SQLi detection tool."""
from __future__ import annotations
import pytest
from unittest.mock import patch
from bba.tools.ghauri import GhauriTool
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {"program": "test-corp", "in_scope": {"domains": ["*.example.com", "example.com"]}}

GHAURI_VULN_OUTPUT = """
[*] Testing: https://example.com/users?id=1
[+] Parameter: 'id' is vulnerable to SQL injection
[+] Type: Boolean-based blind
[+] Parameter: 'id' injectable!
"""

GHAURI_CLEAN_OUTPUT = """
[*] Testing: https://example.com/users?id=1
[-] No vulnerabilities detected in parameters
[*] Finished
"""


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


class TestGhauriTool:
    def test_build_command_default(self, runner, db):
        tool = GhauriTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com/users?id=1")
        assert cmd[0] == "ghauri"
        assert "-u" in cmd
        assert "https://example.com/users?id=1" in cmd
        assert "--batch" in cmd
        assert "--level" in cmd
        assert "2" in cmd
        assert "--technique" not in cmd

    def test_build_command_with_technique(self, runner, db):
        tool = GhauriTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com/users?id=1", level=3, technique="BT")
        assert "--technique" in cmd
        assert "BT" in cmd
        assert "--level" in cmd
        assert "3" in cmd

    def test_is_vulnerable_true(self, runner, db):
        tool = GhauriTool(runner=runner, db=db, program="test-corp")
        assert tool.is_vulnerable(GHAURI_VULN_OUTPUT) is True

    def test_is_vulnerable_false(self, runner, db):
        tool = GhauriTool(runner=runner, db=db, program="test-corp")
        assert tool.is_vulnerable(GHAURI_CLEAN_OUTPUT) is False

    @pytest.mark.asyncio
    async def test_run_stores_finding(self, runner, db):
        tool = GhauriTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=GHAURI_VULN_OUTPUT, raw_file=None, error=None, duration=5.0)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com/users?id=1")
        assert result["vulnerable"] is True
        findings = await db.get_findings("test-corp")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "sql-injection"
        assert findings[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_run_no_finding_when_clean(self, runner, db):
        tool = GhauriTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=GHAURI_CLEAN_OUTPUT, raw_file=None, error=None, duration=2.0)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com/users?id=1")
        assert result["vulnerable"] is False
        findings = await db.get_findings("test-corp")
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_run_handles_failure(self, runner, db):
        tool = GhauriTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", raw_file=None, error="ghauri not installed", duration=0.1)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com/users?id=1")
        assert result["vulnerable"] is False
        assert "error" in result
        assert result["url"] == "https://example.com/users?id=1"
