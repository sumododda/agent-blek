import pytest
from unittest.mock import patch
from bba.tools.cache_scanner import CacheScannerTool
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {"program": "test", "in_scope": {"domains": ["*.example.com"], "cidrs": []}, "out_of_scope": {}}

@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))

@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(), sanitizer=Sanitizer(), output_dir=tmp_path / "output")

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestCacheScannerTool:
    def test_build_command(self, runner, db):
        tool = CacheScannerTool(runner=runner, db=db, program="test")
        cmd = tool.build_command("https://example.com")
        assert "Web-Cache-Vulnerability-Scanner" in cmd[0]
        assert "-u" in cmd

    def test_parse_output_vulnerable(self, runner, db):
        tool = CacheScannerTool(runner=runner, db=db, program="test")
        output = "VULNERABLE: cache poisoning via X-Forwarded-Host header\ntechnique: header injection\n"
        result = tool.parse_output(output)
        assert len(result) >= 1

    def test_parse_output_not_vulnerable(self, runner, db):
        tool = CacheScannerTool(runner=runner, db=db, program="test")
        output = "Testing https://example.com...\nNo vulnerabilities found.\n"
        result = tool.parse_output(output)
        assert len(result) == 0

    def test_parse_output_empty(self, runner, db):
        tool = CacheScannerTool(runner=runner, db=db, program="test")
        assert tool.parse_output("") == []

    @pytest.mark.asyncio
    async def test_run_vulnerable(self, runner, db):
        tool = CacheScannerTool(runner=runner, db=db, program="test")
        mock = ToolResult(success=True, output="VULNERABLE: cache poisoning detected\n", raw_file=None, error=None, duration=10.0)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run("https://example.com")
        assert result["vulnerable"] is True
        findings = await db.get_findings("test")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "cache-poisoning"

    @pytest.mark.asyncio
    async def test_run_not_vulnerable(self, runner, db):
        tool = CacheScannerTool(runner=runner, db=db, program="test")
        mock = ToolResult(success=True, output="No vulnerabilities found.\n", raw_file=None, error=None, duration=5.0)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run("https://example.com")
        assert result["vulnerable"] is False

    @pytest.mark.asyncio
    async def test_run_failure(self, runner, db):
        tool = CacheScannerTool(runner=runner, db=db, program="test")
        mock = ToolResult(success=False, output="", raw_file=None, error="timeout", duration=180.0)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run("https://example.com")
        assert result["vulnerable"] is False
        assert "error" in result
