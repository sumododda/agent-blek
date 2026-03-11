import json
import pytest
from unittest.mock import patch
from bba.tools.dalfox import DalfoxTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {"program": "test-corp", "in_scope": {"domains": ["*.example.com", "example.com"]}}
DALFOX_OUTPUT = "\n".join([json.dumps({"type": "G", "inject_type": "inHTML-URL", "poc_type": "plain", "method": "GET", "data": "https://shop.example.com/search?q=%3Csvg%20onload%3Dalert(1)%3E", "param": "q", "payload": "<svg onload=alert(1)>", "evidence": "reflected"})]) + "\n"

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

class TestDalfoxTool:
    def test_builds_command(self, runner, db):
        tool = DalfoxTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://shop.example.com/search?q=test")
        assert "dalfox" in cmd and "url" in cmd and "--silence" in cmd and "--format" in cmd and "json" in cmd

    def test_parses_json_output(self, runner, db):
        tool = DalfoxTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(DALFOX_OUTPUT)
        assert len(results) == 1 and results[0]["param"] == "q" and "alert(1)" in results[0]["payload"]

    async def test_run_stores_findings(self, runner, db):
        tool = DalfoxTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=DALFOX_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://shop.example.com/search?q=test")
        assert summary["total"] == 1
        findings = await db.get_findings("test-corp")
        assert len(findings) == 1 and findings[0]["vuln_type"] == "xss"

    async def test_run_handles_no_findings(self, runner, db):
        tool = DalfoxTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output="", raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://shop.example.com/search?q=test")
        assert summary["total"] == 0

    async def test_run_handles_failure(self, runner, db):
        tool = DalfoxTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="crash")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://shop.example.com/search?q=test")
        assert summary["total"] == 0 and summary["error"] == "crash"
