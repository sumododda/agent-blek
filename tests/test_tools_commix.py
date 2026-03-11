"""Tests for commix command injection tool."""
from __future__ import annotations
import pytest
from unittest.mock import patch
from bba.tools.commix import CommixTool
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {"program": "test-corp", "in_scope": {"domains": ["*.example.com", "example.com"]}}

COMMIX_VULN_OUTPUT = """
[*] Testing: https://example.com/ping?host=localhost
[+] Parameter 'host' is vulnerable to OS command injection!
[+] Technique: results-based classic injection
[*] via: time-based blind command injection
"""

COMMIX_CLEAN_OUTPUT = """
[*] Testing: https://example.com/ping?host=localhost
[-] All parameters appear safe
[*] Testing finished
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


class TestCommixTool:
    def test_build_command_includes_batch(self, runner, db):
        tool = CommixTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com/ping?host=localhost")
        assert cmd[0] == "commix"
        assert "--url" in cmd
        assert "https://example.com/ping?host=localhost" in cmd
        assert "--batch" in cmd
        assert any("output-dir" in arg for arg in cmd)

    def test_is_vulnerable_true(self, runner, db):
        tool = CommixTool(runner=runner, db=db, program="test-corp")
        assert tool.is_vulnerable(COMMIX_VULN_OUTPUT) is True

    def test_is_vulnerable_false(self, runner, db):
        tool = CommixTool(runner=runner, db=db, program="test-corp")
        assert tool.is_vulnerable(COMMIX_CLEAN_OUTPUT) is False

    def test_extract_technique(self, runner, db):
        tool = CommixTool(runner=runner, db=db, program="test-corp")
        technique = tool.extract_technique(COMMIX_VULN_OUTPUT)
        assert technique != "unknown"
        # Should extract something from "Technique: results-based..."
        assert len(technique) > 0

    def test_extract_technique_unknown_when_not_found(self, runner, db):
        tool = CommixTool(runner=runner, db=db, program="test-corp")
        assert tool.extract_technique("No technique info here") == "unknown"

    @pytest.mark.asyncio
    async def test_run_stores_finding(self, runner, db):
        tool = CommixTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=COMMIX_VULN_OUTPUT, raw_file=None, error=None, duration=5.0)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com/ping?host=localhost")
        assert result["vulnerable"] is True
        assert result["technique"] is not None
        findings = await db.get_findings("test-corp")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "command-injection"
        assert findings[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_run_no_finding_when_clean(self, runner, db):
        tool = CommixTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=COMMIX_CLEAN_OUTPUT, raw_file=None, error=None, duration=2.0)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com/ping?host=localhost")
        assert result["vulnerable"] is False
        assert result["technique"] is None
        findings = await db.get_findings("test-corp")
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_run_handles_failure(self, runner, db):
        tool = CommixTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", raw_file=None, error="commix not found", duration=0.1)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com/ping?host=localhost")
        assert result["vulnerable"] is False
        assert "error" in result
        assert result["url"] == "https://example.com/ping?host=localhost"
