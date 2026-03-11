import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.jwt_tool import JwtToolTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

SAMPLE_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

ALG_NONE_OUTPUT = """\
Running algorithm tests...
[+] alg none accepted - Server accepted unsigned token
VULNERABLE: Algorithm 'none' bypass successful
"""

WEAK_SECRET_OUTPUT = """\
Running dictionary attack...
[+] secret found: password123
Weak secret cracked: mysecret
"""

CLEAN_OUTPUT = """\
Running tests...
No vulnerabilities found.
"""

VULN_OUTPUT = """\
VULNERABLE endpoint detected
EXPLOITABLE parameter found
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


class TestJwtToolTool:
    def test_build_command_scan(self, runner, db):
        tool = JwtToolTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command_scan(SAMPLE_TOKEN)
        assert "jwt_tool" in cmd
        assert SAMPLE_TOKEN in cmd
        assert "-M" in cmd
        assert "at" in cmd
        assert "-np" in cmd

    def test_build_command_crack(self, runner, db):
        tool = JwtToolTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command_crack(SAMPLE_TOKEN, "/path/to/wordlist.txt")
        assert "jwt_tool" in cmd
        assert SAMPLE_TOKEN in cmd
        assert "-C" in cmd
        assert "-d" in cmd
        assert "/path/to/wordlist.txt" in cmd

    def test_parse_output_alg_none(self, runner, db):
        tool = JwtToolTool(runner=runner, db=db, program="test-corp")
        result = tool.parse_output(ALG_NONE_OUTPUT)
        assert result["vulnerable"] is True
        assert any(v["type"] == "alg-none" for v in result["vulns"])

    def test_parse_output_weak_secret(self, runner, db):
        tool = JwtToolTool(runner=runner, db=db, program="test-corp")
        result = tool.parse_output(WEAK_SECRET_OUTPUT)
        assert result["vulnerable"] is True
        assert any(v["type"] == "weak-secret" for v in result["vulns"])

    def test_parse_output_clean(self, runner, db):
        tool = JwtToolTool(runner=runner, db=db, program="test-corp")
        result = tool.parse_output(CLEAN_OUTPUT)
        assert result["vulnerable"] is False
        assert result["vulns"] == []

    async def test_run_stores_finding(self, runner, db):
        tool = JwtToolTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=ALG_NONE_OUTPUT, raw_file=Path("/tmp/test.txt"))
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run(SAMPLE_TOKEN, "example.com")
        assert result["vulnerable"] is True
        findings = await db.get_findings(program="test-corp")
        assert len(findings) >= 1
        assert findings[0]["severity"] == "critical"

    async def test_run_handles_failure(self, runner, db):
        tool = JwtToolTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="jwt_tool not found")
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run(SAMPLE_TOKEN, "example.com")
        assert result["vulnerable"] is False
        assert "error" in result
