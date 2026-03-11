import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.nuclei import NucleiTool, TECH_TAG_MAP
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}


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


class TestNucleiEnhanced:
    def test_build_command_with_templates(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(
            ["https://example.com"], tmp_path,
            templates=["cves/", "vulnerabilities/"]
        )
        assert cmd.count("-t") == 2
        assert "cves/" in cmd
        assert "vulnerabilities/" in cmd

    def test_build_command_with_dast(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(["https://example.com"], tmp_path, dast=True)
        assert "-dast" in cmd

    def test_build_command_without_dast(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(["https://example.com"], tmp_path, dast=False)
        assert "-dast" not in cmd

    def test_build_command_with_concurrency(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(["https://example.com"], tmp_path, concurrency=50)
        idx = cmd.index("-c")
        assert cmd[idx + 1] == "50"

    def test_build_command_default(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(["https://example.com"], tmp_path)
        assert "-severity" in cmd
        assert "-rl" in cmd
        assert "-dast" not in cmd
        assert "-t" not in cmd

    def test_select_scan_options_known_tech(self, runner, db):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        opts = tool.select_scan_options(["WordPress", "Nginx"])
        assert opts["tags"] is not None
        assert "wordpress" in opts["tags"]
        assert "nginx" in opts["tags"]

    def test_select_scan_options_unknown_tech(self, runner, db):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        opts = tool.select_scan_options(["UnknownFramework"])
        assert opts["tags"] is None

    def test_select_scan_options_empty(self, runner, db):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        opts = tool.select_scan_options([])
        assert opts["tags"] is None

    def test_tech_tag_map_coverage(self):
        assert "wordpress" in TECH_TAG_MAP
        assert "jenkins" in TECH_TAG_MAP
        assert "apache" in TECH_TAG_MAP

    def test_build_command_with_tags(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(["https://example.com"], tmp_path, tags="cve,rce")
        idx = cmd.index("-tags")
        assert cmd[idx + 1] == "cve,rce"

    async def test_run_with_templates_and_dast(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        finding = json.dumps({
            "template-id": "CVE-2021-44228",
            "info": {"name": "Log4Shell", "severity": "critical"},
            "host": "https://example.com",
            "matched-at": "https://example.com/api",
            "extracted-results": ["payload-match"],
            "matcher-name": "log4j",
        })
        mock_result = ToolResult(success=True, output=finding, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(
                ["https://example.com"], tmp_path,
                templates=["cves/"], dast=True, concurrency=25,
            )
        assert summary["total"] == 1
        assert summary["by_severity"]["critical"] == 1

    def test_interactsh_url_flag(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(["https://example.com"], tmp_path, interactsh_url="https://abc.oast.live")
        assert "-iurl" in cmd
        assert "https://abc.oast.live" in cmd

    def test_interactsh_server_flag(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(["https://example.com"], tmp_path, interactsh_server="https://my-server.com")
        assert "-iserver" in cmd
        assert "https://my-server.com" in cmd

    def test_headless_flag(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(["https://example.com"], tmp_path, headless=True)
        assert "-headless" in cmd

    def test_no_interactsh_by_default(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(["https://example.com"], tmp_path)
        assert "-iurl" not in cmd
        assert "-iserver" not in cmd
        assert "-headless" not in cmd
