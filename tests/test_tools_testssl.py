import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.testssl import TestsslTool, SEVERITY_MAP
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

TESTSSL_OUTPUT = json.dumps([
    {"id": "BEAST", "severity": "WARN", "finding": "BEAST: vulnerable", "cve": "CVE-2011-3389", "cwe": ""},
    {"id": "POODLE_SSL", "severity": "CRITICAL", "finding": "POODLE: vulnerable", "cve": "CVE-2014-3566", "cwe": "CWE-310"},
    {"id": "cert_expirationStatus", "severity": "OK", "finding": "Certificate valid", "cve": "", "cwe": ""},
    {"id": "protocol_support", "severity": "INFO", "finding": "TLS 1.2 offered", "cve": "", "cwe": ""},
])

TESTSSL_EMPTY = json.dumps([])


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


class TestTestsslTool:
    def test_builds_command(self, runner, db):
        tool = TestsslTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com")
        assert "testssl" in cmd
        assert "--jsonfile" in cmd
        assert "https://example.com" in cmd

    def test_parses_output_filters_ok_info(self, runner, db):
        tool = TestsslTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(TESTSSL_OUTPUT)
        assert len(results) == 2
        assert results[0]["id"] == "BEAST"
        assert results[0]["severity"] == "medium"  # WARN maps to medium
        assert results[1]["id"] == "POODLE_SSL"
        assert results[1]["severity"] == "critical"

    def test_parses_empty_output(self, runner, db):
        tool = TestsslTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(TESTSSL_EMPTY)
        assert results == []

    def test_parses_invalid_json(self, runner, db):
        tool = TestsslTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("not json")
        assert results == []

    def test_severity_map(self):
        assert SEVERITY_MAP["CRITICAL"] == "critical"
        assert SEVERITY_MAP["HIGH"] == "high"
        assert SEVERITY_MAP["WARN"] == "medium"
        assert SEVERITY_MAP["OK"] == "info"

    async def test_run_success(self, runner, db):
        tool = TestsslTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=TESTSSL_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com")
        assert summary["total"] == 2
        assert len(summary["findings"]) == 2

    async def test_run_failure(self, runner, db):
        tool = TestsslTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://example.com")
        assert summary["total"] == 0
        assert summary["error"] == "timeout"
