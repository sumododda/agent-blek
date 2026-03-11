"""Tests for nosqli NoSQL injection detection tool."""
from __future__ import annotations
import pytest
from unittest.mock import patch
from bba.tools.nosqli import NosqliTool
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {"program": "test-corp", "in_scope": {"domains": ["*.example.com", "example.com"]}}

NOSQLI_VULN_OUTPUT = """
[*] Scanning: https://example.com/api/users?username=admin
[+] Found vulnerable parameter: username
[+] NoSQL injection confirmed with payload: {"$gt": ""}
[+] MongoDB injection technique successful
"""

NOSQLI_CLEAN_OUTPUT = """
[*] Scanning: https://example.com/api/users?username=admin
[-] No vulnerabilities detected
[*] Scan complete
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


class TestNosqliTool:
    def test_build_command(self, runner, db):
        tool = NosqliTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com/api/users?username=admin")
        assert cmd[0] == "nosqli"
        assert "scan" in cmd
        assert "-t" in cmd
        assert "https://example.com/api/users?username=admin" in cmd

    def test_parse_output_with_vulnerable_lines(self, runner, db):
        tool = NosqliTool(runner=runner, db=db, program="test-corp")
        findings = tool.parse_output(NOSQLI_VULN_OUTPUT)
        assert len(findings) > 0
        assert all("detail" in f for f in findings)
        # Should capture lines with "vulnerable" or "injection"
        details = [f["detail"].lower() for f in findings]
        assert any("vulnerable" in d or "injection" in d for d in details)

    def test_parse_output_clean(self, runner, db):
        tool = NosqliTool(runner=runner, db=db, program="test-corp")
        findings = tool.parse_output(NOSQLI_CLEAN_OUTPUT)
        assert findings == []

    def test_parse_output_empty(self, runner, db):
        tool = NosqliTool(runner=runner, db=db, program="test-corp")
        assert tool.parse_output("") == []
        assert tool.parse_output("\n\n") == []

    @pytest.mark.asyncio
    async def test_run_stores_finding(self, runner, db):
        tool = NosqliTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=NOSQLI_VULN_OUTPUT, raw_file=None, error=None, duration=2.0)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com/api/users?username=admin")
        assert result["vulnerable"] is True
        assert len(result["findings"]) > 0
        findings = await db.get_findings("test-corp")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "nosql-injection"
        assert findings[0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_run_no_finding_when_clean(self, runner, db):
        tool = NosqliTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=NOSQLI_CLEAN_OUTPUT, raw_file=None, error=None, duration=1.0)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com/api/users?username=admin")
        assert result["vulnerable"] is False
        assert result["findings"] == []
        findings = await db.get_findings("test-corp")
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_run_handles_failure(self, runner, db):
        tool = NosqliTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", raw_file=None, error="nosqli not found", duration=0.1)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com/api/users?username=admin")
        assert result["vulnerable"] is False
        assert "error" in result
        assert result["url"] == "https://example.com/api/users?username=admin"
