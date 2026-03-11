import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.s3scanner import S3ScannerTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

S3SCANNER_ACCESSIBLE = json.dumps({"bucket_exists": True, "permissions": {"read": True, "write": False}}) + "\n"
S3SCANNER_NOT_ACCESSIBLE = json.dumps({"bucket_exists": False, "permissions": {}}) + "\n"

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

class TestS3ScannerTool:
    def test_builds_command(self, runner, db):
        tool = S3ScannerTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("example-corp-assets")
        assert "s3scanner" in cmd
        assert "scan" in cmd
        assert "--bucket" in cmd
        assert "example-corp-assets" in cmd
        assert "--json" in cmd

    def test_parses_json_output(self, runner, db):
        tool = S3ScannerTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(S3SCANNER_ACCESSIBLE)
        assert len(results) == 1
        assert results[0]["bucket_exists"] is True
        assert results[0]["permissions"]["read"] is True

    def test_parses_empty_output(self, runner, db):
        tool = S3ScannerTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_output_with_invalid_lines(self, runner, db):
        tool = S3ScannerTool(runner=runner, db=db, program="test-corp")
        output = json.dumps({"bucket_exists": True, "permissions": {"read": True}}) + "\nbad line\n"
        results = tool.parse_output(output)
        assert len(results) == 1

    async def test_run_accessible_stores_finding(self, runner, db):
        tool = S3ScannerTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=S3SCANNER_ACCESSIBLE, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example-corp-assets")
        assert summary["accessible"] is True
        assert summary["bucket"] == "example-corp-assets"
        assert len(summary["permissions"]) >= 1
        findings = await db.get_findings("test-corp")
        assert len(findings) == 1

    async def test_run_inaccessible_no_finding(self, runner, db):
        tool = S3ScannerTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=S3SCANNER_NOT_ACCESSIBLE, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example-corp-private")
        assert summary["accessible"] is False
        findings = await db.get_findings("test-corp")
        assert len(findings) == 0

    async def test_run_handles_failure(self, runner, db):
        tool = S3ScannerTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example-corp-assets")
        assert summary["accessible"] is False
        assert summary["error"] == "timeout"
