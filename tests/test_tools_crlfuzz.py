"""Tests for crlfuzz CRLF injection scanner."""
from __future__ import annotations
import pytest
from unittest.mock import patch
from bba.tools.crlfuzz import CrlfuzzTool
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {"program": "test-corp", "in_scope": {"domains": ["*.example.com", "example.com"]}}


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


class TestCrlfuzzTool:
    def test_build_command_single(self, runner, db):
        tool = CrlfuzzTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com/path?q=test")
        assert cmd[0] == "crlfuzz"
        assert "-u" in cmd
        assert "https://example.com/path?q=test" in cmd
        assert "-s" in cmd

    def test_build_command_list(self, runner, db, tmp_path):
        tool = CrlfuzzTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        urls = ["https://example.com/a?x=1", "https://sub.example.com/b?y=2"]
        cmd = tool.build_command_list(urls, work_dir)
        assert cmd[0] == "crlfuzz"
        assert "-l" in cmd
        assert "-s" in cmd
        # Verify input file was created with correct content
        input_file = work_dir / "crlfuzz_input.txt"
        assert input_file.exists()
        content = input_file.read_text()
        assert "https://example.com/a?x=1" in content
        assert "https://sub.example.com/b?y=2" in content

    def test_parse_output_normal(self, runner, db):
        tool = CrlfuzzTool(runner=runner, db=db, program="test-corp")
        output = "https://example.com/vuln%0d%0aHeader:injected\nhttps://sub.example.com/also-vuln%0d%0a\n"
        result = tool.parse_output(output)
        assert len(result) == 2
        assert "https://example.com/vuln%0d%0aHeader:injected" in result

    def test_parse_output_empty(self, runner, db):
        tool = CrlfuzzTool(runner=runner, db=db, program="test-corp")
        assert tool.parse_output("") == []
        assert tool.parse_output("\n\n") == []

    @pytest.mark.asyncio
    async def test_run_stores_findings(self, runner, db):
        tool = CrlfuzzTool(runner=runner, db=db, program="test-corp")
        vuln_output = "https://example.com/page%0d%0aX-Injected:yes\n"
        mock_result = ToolResult(success=True, output=vuln_output, raw_file=None, error=None, duration=1.0)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com/page?q=test")
        assert result["total"] == 1
        assert len(result["vulnerable"]) == 1
        findings = await db.get_findings("test-corp")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "crlf-injection"
        assert findings[0]["severity"] == "medium"

    @pytest.mark.asyncio
    async def test_run_handles_failure(self, runner, db):
        tool = CrlfuzzTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", raw_file=None, error="tool not found", duration=0.1)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com/page?q=test")
        assert result["total"] == 0
        assert result["vulnerable"] == []
        assert "error" in result

    @pytest.mark.asyncio
    async def test_run_list_stores_findings(self, runner, db, tmp_path):
        tool = CrlfuzzTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        vuln_output = "https://example.com/a%0d%0aX-Test:injected\nhttps://sub.example.com/b%0d%0a\n"
        mock_result = ToolResult(success=True, output=vuln_output, raw_file=None, error=None, duration=2.0)
        urls = ["https://example.com/a?x=1", "https://sub.example.com/b?y=2"]
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run_list(urls, work_dir)
        assert result["total"] == 2
        assert result["scanned"] == 2
        findings = await db.get_findings("test-corp")
        assert len(findings) == 2
        assert all(f["vuln_type"] == "crlf-injection" for f in findings)
