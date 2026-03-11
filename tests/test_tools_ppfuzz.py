import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.ppfuzz import PpfuzzTool
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
https://example.com/?__proto__[x]=y - vulnerable to prototype pollution
https://api.example.com - pollution gadget found
"""

CLEAN_OUTPUT = """\
Scanning complete. No issues found.
"""

PROTO_OUTPUT = """\
https://example.com - proto chain manipulation possible
"""

SAMPLE_URLS = [
    "https://example.com/?q=1",
    "https://api.example.com/search?q=test",
]


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


class TestPpfuzzTool:
    def test_build_command(self, runner, db, tmp_path):
        tool = PpfuzzTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(SAMPLE_URLS, tmp_path)
        assert "ppfuzz" in cmd
        assert "-l" in cmd
        input_idx = cmd.index("-l")
        input_file = Path(cmd[input_idx + 1])
        assert input_file.exists()
        content = input_file.read_text()
        for url in SAMPLE_URLS:
            assert url in content

    def test_parse_output_vulnerable(self, runner, db):
        tool = PpfuzzTool(runner=runner, db=db, program="test-corp")
        findings = tool.parse_output(VULN_OUTPUT)
        assert len(findings) == 2
        assert any("prototype pollution" in f["url"] or "pollut" in f["url"].lower() for f in findings)

    def test_parse_output_pollution_keyword(self, runner, db):
        tool = PpfuzzTool(runner=runner, db=db, program="test-corp")
        findings = tool.parse_output(PROTO_OUTPUT)
        assert len(findings) == 1

    def test_parse_output_clean(self, runner, db):
        tool = PpfuzzTool(runner=runner, db=db, program="test-corp")
        findings = tool.parse_output(CLEAN_OUTPUT)
        assert findings == []

    async def test_run_stores_finding(self, runner, db, tmp_path):
        tool = PpfuzzTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=VULN_OUTPUT, raw_file=Path("/tmp/test.txt"))
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run(SAMPLE_URLS, tmp_path)
        assert result["total"] == 2
        assert result["scanned"] == len(SAMPLE_URLS)
        findings = await db.get_findings(program="test-corp")
        assert len(findings) >= 1
        assert findings[0]["vuln_type"] == "prototype-pollution"
        assert findings[0]["severity"] == "high"

    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = PpfuzzTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="ppfuzz not found")
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run(SAMPLE_URLS, tmp_path)
        assert result["total"] == 0
        assert "error" in result
