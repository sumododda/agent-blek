import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.cdncheck import CdncheckTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

CDNCHECK_OUTPUT = "\n".join([
    json.dumps({"input": "example.com", "cdn": True, "cdn_name": "Cloudflare", "waf": True, "waf_name": "Cloudflare"}),
    json.dumps({"input": "api.example.com", "cdn": False, "cdn_name": "", "waf": False, "waf_name": ""}),
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

class TestCdncheckTool:
    def test_builds_command(self, runner, db, tmp_path):
        tool = CdncheckTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        cmd = tool.build_command(["example.com", "api.example.com"], work_dir)
        assert "cdncheck" in cmd
        assert "-i" in cmd
        assert "-json" in cmd
        assert "-silent" in cmd

    def test_parses_json_output(self, runner, db):
        tool = CdncheckTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(CDNCHECK_OUTPUT)
        assert len(results) == 2
        assert results[0]["input"] == "example.com"
        assert results[0]["cdn"] is True
        assert results[0]["cdn_name"] == "Cloudflare"
        assert results[0]["waf"] is True
        assert results[0]["waf_name"] == "Cloudflare"

    def test_parses_empty_output(self, runner, db):
        tool = CdncheckTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_output_with_invalid_lines(self, runner, db):
        tool = CdncheckTool(runner=runner, db=db, program="test-corp")
        output = json.dumps({"input": "example.com", "cdn": True, "cdn_name": "Cloudflare"}) + "\nbad line\n"
        results = tool.parse_output(output)
        assert len(results) == 1

    async def test_run_stores_in_db(self, runner, db, tmp_path):
        tool = CdncheckTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        mock_result = ToolResult(success=True, output=CDNCHECK_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["example.com", "api.example.com"], work_dir)
        assert summary["total"] == 2
        assert len(summary["cdn_hosts"]) == 1
        assert summary["cdn_hosts"][0]["cdn"] == "Cloudflare"
        assert len(summary["waf_hosts"]) == 1
        assert summary["waf_hosts"][0]["waf"] == "Cloudflare"

    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = CdncheckTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["example.com"], work_dir)
        assert summary["total"] == 0
        assert summary["error"] == "timeout"
