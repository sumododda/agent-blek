import pytest
from unittest.mock import patch
from bba.tools.nomore403 import Nomore403Tool
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


class TestNomore403Tool:
    def test_build_command(self, runner, db):
        tool = Nomore403Tool(runner=runner, db=db, program="test")
        cmd = tool.build_command("https://example.com/admin")
        assert "nomore403" in cmd[0]
        assert "https://example.com/admin" in cmd
        assert "-u" in cmd

    def test_parse_output_finds_bypass(self, runner, db):
        tool = Nomore403Tool(runner=runner, db=db, program="test")
        output = "200 https://example.com/%2e/admin (Header: X-Original-URL)\n403 https://example.com/admin\n"
        result = tool.parse_output(output)
        assert len(result) == 1
        assert result[0]["status"] == 200
        assert result[0]["technique"] == "Header: X-Original-URL"

    def test_parse_output_finds_redirect_bypass(self, runner, db):
        tool = Nomore403Tool(runner=runner, db=db, program="test")
        output = "301 https://example.com/admin/ (Path: trailing slash)\n"
        result = tool.parse_output(output)
        assert len(result) == 1
        assert result[0]["status"] == 301

    def test_parse_output_no_bypass(self, runner, db):
        tool = Nomore403Tool(runner=runner, db=db, program="test")
        output = "403 https://example.com/admin\n403 https://example.com/%2e/admin\n"
        result = tool.parse_output(output)
        assert len(result) == 0

    def test_parse_output_multiple_bypasses(self, runner, db):
        tool = Nomore403Tool(runner=runner, db=db, program="test")
        output = "200 https://example.com/%2e/admin (Header: X-Original-URL)\n200 https://example.com/admin/ (Path: trailing slash)\n403 https://example.com/admin\n"
        result = tool.parse_output(output)
        assert len(result) == 2

    def test_parse_output_no_technique(self, runner, db):
        tool = Nomore403Tool(runner=runner, db=db, program="test")
        output = "200 https://example.com/%2e/admin\n"
        result = tool.parse_output(output)
        assert len(result) == 1
        assert result[0]["technique"] == "unknown"

    @pytest.mark.asyncio
    async def test_run_stores_finding(self, runner, db):
        tool = Nomore403Tool(runner=runner, db=db, program="test")
        mock = ToolResult(success=True, output="200 https://example.com/%2e/admin (Method: POST)\n", raw_file=None, error=None, duration=2.0)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run("https://example.com/admin")
        assert result["total"] == 1
        findings = await db.get_findings("test")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "403-bypass"
        assert findings[0]["tool"] == "nomore403"

    @pytest.mark.asyncio
    async def test_run_failure(self, runner, db):
        tool = Nomore403Tool(runner=runner, db=db, program="test")
        mock = ToolResult(success=False, output="", raw_file=None, error="not found", duration=0.5)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run("https://example.com/admin")
        assert result["total"] == 0
        assert "error" in result

    @pytest.mark.asyncio
    async def test_run_no_bypass_found(self, runner, db):
        tool = Nomore403Tool(runner=runner, db=db, program="test")
        mock = ToolResult(success=True, output="403 https://example.com/admin\n", raw_file=None, error=None, duration=3.0)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run("https://example.com/admin")
        assert result["total"] == 0
        assert result["bypasses"] == []
