import json
import pytest
from unittest.mock import patch
from pathlib import Path
from bba.tools.nuclei import NucleiTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {"program": "test-corp", "in_scope": {"domains": ["*.example.com", "example.com"]}}

NUCLEI_OUTPUT = "\n".join([
    json.dumps({"template-id": "cve-2021-44228", "info": {"name": "Log4j RCE", "severity": "critical", "tags": ["cve", "rce"]}, "host": "https://api.example.com", "matched-at": "https://api.example.com/login", "matcher-name": "log4j", "extracted-results": ["${jndi:ldap://...}"]}),
    json.dumps({"template-id": "exposed-panels", "info": {"name": "Admin Panel Detected", "severity": "info", "tags": ["panel"]}, "host": "https://shop.example.com", "matched-at": "https://shop.example.com/admin"}),
    json.dumps({"template-id": "xss-reflected", "info": {"name": "Reflected XSS", "severity": "high", "tags": ["xss"]}, "host": "https://shop.example.com", "matched-at": "https://shop.example.com/search?q=test", "extracted-results": ["<script>alert(1)</script>"]}),
]) + "\n"

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

class TestNucleiTool:
    def test_builds_command_with_targets_file(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(["https://api.example.com", "https://shop.example.com"], work_dir=tmp_path, severity="high,critical", rate_limit=100)
        assert "nuclei" in cmd and "-l" in cmd and "-severity" in cmd and "high,critical" in cmd and "-rl" in cmd and "100" in cmd and "-json" in cmd

    def test_builds_command_with_tags(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(["https://api.example.com"], work_dir=tmp_path, tags="wordpress,wp-plugin")
        assert "-tags" in cmd and "wordpress,wp-plugin" in cmd

    def test_parses_json_output(self, runner, db):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(NUCLEI_OUTPUT)
        assert len(results) == 3 and results[0]["template-id"] == "cve-2021-44228" and results[0]["info"]["severity"] == "critical"

    def test_parses_empty_output(self, runner, db):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        assert tool.parse_output("") == []

    async def test_run_stores_findings_in_db(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=NUCLEI_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["https://api.example.com", "https://shop.example.com"], work_dir=tmp_path)
        findings = await db.get_findings("test-corp")
        assert len(findings) == 3 and summary["total"] == 3 and summary["by_severity"]["critical"] == 1 and summary["by_severity"]["high"] == 1

    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["https://api.example.com"], work_dir=tmp_path)
        assert summary["total"] == 0 and summary["error"] == "timeout"

    def test_select_templates_for_wordpress(self, runner, db):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        opts = tool.select_scan_options(technologies=["apache", "php", "wordpress"])
        assert "wordpress" in opts["tags"]

    def test_select_templates_for_api(self, runner, db):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        opts = tool.select_scan_options(technologies=["nginx", "python", "flask"])
        assert opts["severity"] == "high,critical"

    def test_select_templates_default(self, runner, db):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        opts = tool.select_scan_options(technologies=[])
        assert opts["severity"] == "high,critical"
