import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.brutespray import BrutesprayTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

BRUTESPRAY_OUTPUT = "[SUCCESS] host: 1.2.3.4 login: admin password: admin123 service: ssh\n[SUCCESS] host: 5.6.7.8 login: root password: toor service: ftp\n"
BRUTESPRAY_NO_SUCCESS = "[INFO] Attempting brute force on 1.2.3.4:22\n[FAILED] host: 1.2.3.4 login: admin service: ssh\n"

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

class TestBrutesprayTool:
    def test_builds_command(self, runner, db):
        tool = BrutesprayTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("/tmp/nmap_output.xml")
        assert "brutespray" in cmd
        assert "-f" in cmd
        assert "/tmp/nmap_output.xml" in cmd
        assert "--threads" in cmd
        assert "-q" in cmd

    def test_builds_command_custom_threads(self, runner, db):
        tool = BrutesprayTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("/tmp/nmap_output.xml", threads=10)
        assert "10" in cmd

    def test_parses_output(self, runner, db):
        tool = BrutesprayTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(BRUTESPRAY_OUTPUT)
        assert len(results) == 2
        assert results[0]["success"] is True
        assert "admin" in results[0]["line"]
        assert "ssh" in results[0]["line"]

    def test_parses_empty_output(self, runner, db):
        tool = BrutesprayTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_output_no_success(self, runner, db):
        tool = BrutesprayTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(BRUTESPRAY_NO_SUCCESS)
        assert results == []

    async def test_run_stores_finding_as_critical(self, runner, db):
        tool = BrutesprayTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=BRUTESPRAY_OUTPUT, raw_file=Path("/tmp/test.txt"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("/tmp/nmap_output.xml", domain="example.com")
        findings = await db.get_findings("test-corp")
        assert len(findings) == 2
        assert summary["total"] == 2

    async def test_run_handles_failure(self, runner, db):
        tool = BrutesprayTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="file not found")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("/tmp/nmap_output.xml", domain="example.com")
        assert summary["total"] == 0
        assert summary["error"] == "file not found"
