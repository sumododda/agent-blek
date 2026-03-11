import json
import pytest
from unittest.mock import patch
from bba.tools.sqlmap_runner import SqlmapTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {"program": "test-corp", "in_scope": {"domains": ["*.example.com", "example.com"]}}
SQLMAP_OUTPUT = """[INFO] testing 'AND boolean-based blind'
[INFO] GET parameter 'id' is vulnerable
[INFO] the back-end DBMS is MySQL
[CRITICAL] parameter 'id' is vulnerable to SQL injection
back-end DBMS: MySQL >= 5.0
"""

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

class TestSqlmapTool:
    def test_builds_command(self, runner, db):
        tool = SqlmapTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://shop.example.com/product?id=1")
        assert "sqlmap" in cmd and "-u" in cmd and "--batch" in cmd

    def test_detects_vulnerability_in_output(self, runner, db):
        tool = SqlmapTool(runner=runner, db=db, program="test-corp")
        assert tool.is_vulnerable(SQLMAP_OUTPUT) is True

    def test_clean_output_not_vulnerable(self, runner, db):
        tool = SqlmapTool(runner=runner, db=db, program="test-corp")
        assert tool.is_vulnerable("[INFO] testing connection\n[INFO] all tested parameters do not appear to be injectable") is False

    async def test_run_stores_finding_when_vulnerable(self, runner, db):
        tool = SqlmapTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=SQLMAP_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://shop.example.com/product?id=1")
        assert summary["vulnerable"] is True
        findings = await db.get_findings("test-corp")
        assert len(findings) == 1 and findings[0]["vuln_type"] == "sql-injection"

    async def test_run_no_finding_when_clean(self, runner, db):
        tool = SqlmapTool(runner=runner, db=db, program="test-corp")
        clean_output = "[INFO] all tested parameters do not appear to be injectable"
        mock_result = ToolResult(success=True, output=clean_output, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://shop.example.com/product?id=1")
        assert summary["vulnerable"] is False
        findings = await db.get_findings("test-corp")
        assert len(findings) == 0
