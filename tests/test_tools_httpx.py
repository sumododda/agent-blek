import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.httpx_runner import HttpxTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

HTTPX_OUTPUT = "\n".join([
    json.dumps({"input": "api.example.com", "url": "https://api.example.com", "status_code": 200, "title": "API Docs", "host": "1.2.3.4", "port": "443", "tech": ["nginx", "python"]}),
    json.dumps({"input": "shop.example.com", "url": "https://shop.example.com", "status_code": 301, "title": "Shop", "host": "5.6.7.8", "port": "443", "tech": ["apache", "php", "wordpress"]}),
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

class TestHttpxTool:
    def test_builds_command_from_list(self, runner, db, tmp_path):
        tool = HttpxTool(runner=runner, db=db, program="test-corp")
        domains = ["api.example.com", "shop.example.com"]
        cmd = tool.build_command(domains, tmp_path)
        assert "httpx" in cmd
        assert "-silent" in cmd
        assert "-json" in cmd
        assert "-l" in cmd

    def test_parses_json_output(self, runner, db):
        tool = HttpxTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(HTTPX_OUTPUT)
        assert len(results) == 2
        assert results[0]["status_code"] == 200
        assert "nginx" in results[0]["tech"]

    async def test_run_stores_services_in_db(self, runner, db, tmp_path):
        tool = HttpxTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=HTTPX_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["api.example.com", "shop.example.com"], work_dir=tmp_path)
        services = await db.get_services("test-corp")
        assert len(services) == 2
        assert summary["live"] == 2
        assert "wordpress" in summary["technologies"]

    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = HttpxTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["api.example.com"], work_dir=tmp_path)
        assert summary["live"] == 0
        assert summary["error"] == "timeout"

    async def test_summary_includes_tech_counts(self, runner, db, tmp_path):
        tool = HttpxTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=HTTPX_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["a.example.com"], work_dir=tmp_path)
        assert summary["technologies"]["nginx"] == 1
        assert summary["technologies"]["wordpress"] == 1
