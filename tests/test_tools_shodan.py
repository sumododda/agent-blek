import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.shodan_cli import ShodanTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

SHODAN_OUTPUT = json.dumps({
    "matches": [
        {
            "ip_str": "1.2.3.4",
            "port": 443,
            "transport": "tcp",
            "product": "nginx",
            "version": "1.24",
            "hostnames": ["example.com"],
        },
        {
            "ip_str": "5.6.7.8",
            "port": 8080,
            "transport": "tcp",
            "product": "Apache",
            "version": "2.4",
            "hostnames": ["api.example.com"],
        },
    ],
})

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

class TestShodanTool:
    def test_builds_url(self, runner, db, monkeypatch):
        monkeypatch.setenv("SHODAN_API_KEY", "test-key-123")
        tool = ShodanTool(runner=runner, db=db, program="test-corp")
        url = tool.build_url("hostname:example.com")
        assert "api.shodan.io" in url
        assert "test-key-123" in url
        assert "hostname%3Aexample.com" in url or "hostname:example.com" in url

    def test_parses_json_output(self, runner, db):
        tool = ShodanTool(runner=runner, db=db, program="test-corp")
        result = tool.parse_output(SHODAN_OUTPUT)
        assert "matches" in result
        assert len(result["matches"]) == 2
        assert result["matches"][0]["ip_str"] == "1.2.3.4"
        assert result["matches"][0]["port"] == 443

    def test_parses_empty_output(self, runner, db):
        tool = ShodanTool(runner=runner, db=db, program="test-corp")
        result = tool.parse_output("")
        assert result == {}

    def test_parses_invalid_json(self, runner, db):
        tool = ShodanTool(runner=runner, db=db, program="test-corp")
        result = tool.parse_output("not valid json")
        assert result == {}

    async def test_run_without_api_key(self, runner, db, monkeypatch):
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        tool = ShodanTool(runner=runner, db=db, program="test-corp")
        summary = await tool.run("hostname:example.com", domain="example.com")
        assert summary["total"] == 0
        assert summary["error"] == "SHODAN_API_KEY not set"

    async def test_run_stores_in_db(self, runner, db, monkeypatch):
        monkeypatch.setenv("SHODAN_API_KEY", "test-key-123")
        tool = ShodanTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=SHODAN_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_http_request", return_value=mock_result):
            summary = await tool.run("hostname:example.com", domain="example.com")
        ports = await db.get_ports("test-corp")
        assert len(ports) == 2
        assert summary["total"] == 2
        assert summary["results"][0]["ip"] == "1.2.3.4"
        assert summary["results"][0]["port"] == 443
        assert summary["results"][0]["product"] == "nginx"

    async def test_run_handles_failure(self, runner, db, monkeypatch):
        monkeypatch.setenv("SHODAN_API_KEY", "test-key-123")
        tool = ShodanTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="rate limited")
        with patch.object(runner, "run_http_request", return_value=mock_result):
            summary = await tool.run("hostname:example.com", domain="example.com")
        assert summary["total"] == 0
        assert summary["error"] == "rate limited"
