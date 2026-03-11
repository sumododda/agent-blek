import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.smuggler import SmugglerTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

DESYNC_OUTPUT = """\
Sending CL.TE probe...
[+] DESYNC CL.TE - Potential request smuggling vulnerability detected
Sending TE.CL probe...
Nothing found for TE.CL
"""

VULN_OUTPUT = """\
[!] VULNERABLE to HTTP request smuggling via H2.CL technique
"""

CLEAN_OUTPUT = """\
Testing endpoints...
No issues found on this host.
"""


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


class TestSmugglerTool:
    def test_build_command(self, runner, db):
        tool = SmugglerTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com")
        assert "python3" in cmd
        assert "-u" in cmd
        assert "https://example.com" in cmd
        assert "-q" in cmd

    def test_parse_output_desync_cl_te(self, runner, db):
        tool = SmugglerTool(runner=runner, db=db, program="test-corp")
        findings = tool.parse_output(DESYNC_OUTPUT)
        assert len(findings) >= 1
        assert findings[0]["technique"] == "CL.TE"
        assert "DESYNC" in findings[0]["detail"]

    def test_parse_output_vulnerable_h2(self, runner, db):
        tool = SmugglerTool(runner=runner, db=db, program="test-corp")
        findings = tool.parse_output(VULN_OUTPUT)
        assert len(findings) == 1
        assert findings[0]["technique"] == "H2.CL"

    def test_parse_output_clean(self, runner, db):
        tool = SmugglerTool(runner=runner, db=db, program="test-corp")
        findings = tool.parse_output(CLEAN_OUTPUT)
        assert findings == []

    async def test_run_stores_critical_finding(self, runner, db):
        tool = SmugglerTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=VULN_OUTPUT, raw_file=Path("/tmp/test.txt"))
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com")
        assert result["vulnerable"] is True
        assert len(result["findings"]) == 1
        findings = await db.get_findings(program="test-corp")
        assert len(findings) >= 1
        assert findings[0]["severity"] == "critical"
        assert findings[0]["vuln_type"] == "http-smuggling"

    async def test_run_handles_failure(self, runner, db):
        tool = SmugglerTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="smuggler not installed")
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com")
        assert result["vulnerable"] is False
        assert "error" in result
