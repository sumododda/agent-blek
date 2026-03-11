import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.xsstrike import XSStrikeTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

VULN_OUTPUT = """\
Vulnerable
Payload: <script>alert(1)</script>
"""

WAF_OUTPUT = """\
WAF detected: Cloudflare
Vulnerable
Payload: <img src=x onerror=alert(1)>
"""

CLEAN_OUTPUT = "No XSS vulnerabilities found."


@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))


@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(
        scope=scope,
        rate_limiter=MultiTargetRateLimiter(default_rps=100),
        sanitizer=Sanitizer(),
        output_dir=tmp_path / "output",
    )


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestXSStrikeTool:
    def test_build_command_default(self, runner, db):
        tool = XSStrikeTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com")
        assert "xsstrike" in cmd
        assert "-u" in cmd
        assert "https://example.com" in cmd
        assert "--skip" in cmd
        assert "--blind" not in cmd
        assert "--crawl" not in cmd

    def test_build_command_blind(self, runner, db):
        tool = XSStrikeTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com", blind=True)
        assert "--blind" in cmd

    def test_build_command_crawl(self, runner, db):
        tool = XSStrikeTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com", crawl=True)
        assert "--crawl" in cmd
        assert "-l" in cmd
        assert "2" in cmd

    def test_parse_output_finds_payload(self, runner, db):
        tool = XSStrikeTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(VULN_OUTPUT)
        assert len(results) >= 1
        assert any("<script>" in r["payload"] for r in results)

    def test_parse_output_clean(self, runner, db):
        tool = XSStrikeTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(CLEAN_OUTPUT)
        assert results == []

    def test_detect_waf(self, runner, db):
        tool = XSStrikeTool(runner=runner, db=db, program="test-corp")
        waf = tool.detect_waf(WAF_OUTPUT)
        assert waf == "Cloudflare"

    def test_detect_waf_none(self, runner, db):
        tool = XSStrikeTool(runner=runner, db=db, program="test-corp")
        waf = tool.detect_waf(CLEAN_OUTPUT)
        assert waf is None

    async def test_run_stores_finding(self, runner, db):
        tool = XSStrikeTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=VULN_OUTPUT, raw_file=Path("/tmp/test.txt"))
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com")
        assert result["vulnerable"] is True
        assert len(result["findings"]) >= 1
        findings = await db.get_findings(program="test-corp")
        assert len(findings) >= 1
        assert findings[0]["vuln_type"] == "xss"

    async def test_run_handles_failure(self, runner, db):
        tool = XSStrikeTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="xsstrike not found")
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com")
        assert result["vulnerable"] is False
        assert "error" in result
