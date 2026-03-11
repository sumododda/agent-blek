import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.corscanner import CORScannerTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

VULN_JSON_OUTPUT = json.dumps({"url": "https://example.com", "vulnerable": True, "type": "reflect_origin"})
VULN_TEXT_OUTPUT = "https://example.com is vulnerable - misconfigured CORS"
CLEAN_OUTPUT = json.dumps({"url": "https://example.com", "vulnerable": False})
CREDS_OUTPUT = json.dumps({"url": "https://example.com", "vulnerable": True, "credentials": True, "type": "reflect_origin"})


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


class TestCORScannerTool:
    def test_build_command(self, runner, db):
        tool = CORScannerTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com")
        assert "python3" in cmd
        assert "-u" in cmd
        assert "https://example.com" in cmd
        assert "-q" in cmd

    def test_build_command_list(self, runner, db, tmp_path):
        tool = CORScannerTool(runner=runner, db=db, program="test-corp")
        urls = ["https://example.com", "https://api.example.com"]
        cmd = tool.build_command_list(urls, tmp_path)
        assert "-i" in cmd
        input_idx = cmd.index("-i")
        input_file = Path(cmd[input_idx + 1])
        assert input_file.exists()
        content = input_file.read_text()
        assert "https://example.com" in content
        assert "https://api.example.com" in content

    def test_parse_output_json_vulnerable(self, runner, db):
        tool = CORScannerTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(VULN_JSON_OUTPUT)
        assert len(results) == 1
        assert results[0]["vulnerable"] is True

    def test_parse_output_text_vulnerable(self, runner, db):
        tool = CORScannerTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(VULN_TEXT_OUTPUT)
        assert len(results) == 1
        assert "cors-misconfiguration" in results[0]["type"]

    def test_parse_output_clean(self, runner, db):
        tool = CORScannerTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(CLEAN_OUTPUT)
        assert results == []

    def test_parse_output_empty(self, runner, db):
        tool = CORScannerTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    async def test_run_stores_finding(self, runner, db):
        tool = CORScannerTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=VULN_JSON_OUTPUT, raw_file=Path("/tmp/test.txt"))
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com")
        assert result["total"] == 1
        findings = await db.get_findings(program="test-corp")
        assert len(findings) >= 1
        assert findings[0]["vuln_type"] == "cors-misconfiguration"

    async def test_run_critical_with_credentials(self, runner, db):
        tool = CORScannerTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=CREDS_OUTPUT, raw_file=Path("/tmp/test.txt"))
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com")
        assert result["total"] == 1
        findings = await db.get_findings(program="test-corp")
        assert findings[0]["severity"] == "critical"

    async def test_run_handles_failure(self, runner, db):
        tool = CORScannerTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="module not found")
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com")
        assert result["total"] == 0
        assert "error" in result
