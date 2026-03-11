import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.retirejs import RetirejsTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

RETIREJS_OUTPUT = json.dumps([
    {
        "file": "/tmp/js/jquery.min.js",
        "results": [
            {
                "component": "jquery",
                "version": "1.6.1",
                "vulnerabilities": [
                    {
                        "severity": "medium",
                        "info": ["https://cve.example.com"],
                        "identifiers": {"CVE": ["CVE-2021-1234"]},
                    },
                ],
            },
        ],
    },
])

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

class TestRetirejsTool:
    def test_builds_command(self, runner, db):
        tool = RetirejsTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("/tmp/js")
        assert "retire" in cmd
        assert "--path" in cmd
        assert "/tmp/js" in cmd
        assert "--outputformat" in cmd
        assert "json" in cmd

    def test_parses_json_output(self, runner, db):
        tool = RetirejsTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(RETIREJS_OUTPUT)
        assert len(results) == 1
        assert results[0]["file"] == "/tmp/js/jquery.min.js"
        assert results[0]["results"][0]["component"] == "jquery"
        assert results[0]["results"][0]["version"] == "1.6.1"

    def test_parses_empty_output(self, runner, db):
        tool = RetirejsTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_invalid_json(self, runner, db):
        tool = RetirejsTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("not valid json")
        assert results == []

    def test_parses_empty_array(self, runner, db):
        tool = RetirejsTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("[]")
        assert results == []

    async def test_run_stores_finding(self, runner, db):
        tool = RetirejsTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=RETIREJS_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("/tmp/js", domain="example.com")
        findings = await db.get_findings("test-corp")
        assert len(findings) == 1
        assert summary["total"] == 1
        assert summary["vulnerabilities"][0]["component"] == "jquery"
        assert summary["vulnerabilities"][0]["version"] == "1.6.1"
        assert summary["vulnerabilities"][0]["severity"] == "medium"
        assert "CVE-2021-1234" in summary["vulnerabilities"][0]["cve"]

    async def test_run_handles_failure(self, runner, db):
        tool = RetirejsTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="not found")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("/tmp/js", domain="example.com")
        assert summary["total"] == 0
        assert summary["error"] == "not found"
