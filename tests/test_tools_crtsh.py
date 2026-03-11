import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.crtsh import CrtshTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

CRTSH_OUTPUT = json.dumps([
    {"name_value": "api.example.com\nwww.example.com"},
    {"name_value": "*.example.com"},
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

class TestCrtshTool:
    def test_build_url(self, runner, db):
        tool = CrtshTool(runner=runner, db=db, program="test-corp")
        url = tool.build_url("example.com")
        assert "crt.sh" in url
        assert "example.com" in url
        assert "output=json" in url

    def test_parses_json_output(self, runner, db):
        tool = CrtshTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(CRTSH_OUTPUT)
        assert "api.example.com" in results
        assert "www.example.com" in results

    def test_filters_wildcard_entries(self, runner, db):
        tool = CrtshTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(CRTSH_OUTPUT)
        for domain in results:
            assert not domain.startswith("*")

    def test_parses_empty_output(self, runner, db):
        tool = CrtshTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_invalid_json(self, runner, db):
        tool = CrtshTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("not valid json")
        assert results == []

    async def test_run_stores_in_db(self, runner, db):
        tool = CrtshTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=CRTSH_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_http_request", return_value=mock_result):
            summary = await tool.run("example.com")
        subs = await db.get_subdomains("test-corp")
        assert len(subs) == 2
        assert summary["total"] == 2

    async def test_run_handles_failure(self, runner, db):
        tool = CrtshTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="connection refused")
        with patch.object(runner, "run_http_request", return_value=mock_result):
            summary = await tool.run("example.com")
        assert summary["total"] == 0
        assert summary["error"] == "connection refused"
