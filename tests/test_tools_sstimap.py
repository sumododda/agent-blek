"""Tests for sstimap SSTI detection tool."""
from __future__ import annotations
import pytest
from unittest.mock import patch
from bba.tools.sstimap import SstimapTool
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {"program": "test-corp", "in_scope": {"domains": ["*.example.com", "example.com"]}}

SSTI_VULN_OUTPUT = """
[*] Testing URL: https://example.com/render?template=test
[+] Identified injection engine: Jinja2
[+] Confirmed exploitable SSTI vulnerability
[*] Template engine: Jinja2
"""

SSTI_CLEAN_OUTPUT = """
[*] Testing URL: https://example.com/render?template=test
[-] No vulnerabilities found
[*] Finished testing
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


class TestSstimapTool:
    def test_build_command(self, runner, db):
        tool = SstimapTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com/render?template=test")
        assert cmd[0] == "sstimap"
        assert "-u" in cmd
        assert "https://example.com/render?template=test" in cmd
        assert "--no-color" in cmd

    def test_parse_output_vulnerable(self, runner, db):
        tool = SstimapTool(runner=runner, db=db, program="test-corp")
        result = tool.parse_output(SSTI_VULN_OUTPUT)
        assert result["vulnerable"] is True
        assert "Jinja2" in result["engines"]
        assert "raw" in result

    def test_parse_output_not_vulnerable(self, runner, db):
        tool = SstimapTool(runner=runner, db=db, program="test-corp")
        result = tool.parse_output(SSTI_CLEAN_OUTPUT)
        assert result["vulnerable"] is False
        assert result["engines"] == []

    @pytest.mark.asyncio
    async def test_run_stores_critical_finding(self, runner, db):
        tool = SstimapTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=SSTI_VULN_OUTPUT, raw_file=None, error=None, duration=2.0)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com/render?template=test")
        assert result["vulnerable"] is True
        assert "Jinja2" in result["engines"]
        findings = await db.get_findings("test-corp")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "ssti"
        assert findings[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_run_no_finding_when_clean(self, runner, db):
        tool = SstimapTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=SSTI_CLEAN_OUTPUT, raw_file=None, error=None, duration=2.0)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com/render?template=test")
        assert result["vulnerable"] is False
        findings = await db.get_findings("test-corp")
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_run_handles_failure(self, runner, db):
        tool = SstimapTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", raw_file=None, error="sstimap not installed", duration=0.1)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com/render?template=test")
        assert result["vulnerable"] is False
        assert "error" in result
        assert result["url"] == "https://example.com/render?template=test"
