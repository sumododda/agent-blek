import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.asnmap import AsnmapTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

ASNMAP_OUTPUT = "\n".join([
    json.dumps({"as_number": "AS13335", "as_name": "Cloudflare", "as_country": "US", "as_range": "104.16.0.0/12"}),
    json.dumps({"as_number": "AS13335", "as_name": "Cloudflare", "as_country": "US", "as_range": "172.64.0.0/13"}),
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

class TestAsnmapTool:
    def test_builds_command(self, runner, db):
        tool = AsnmapTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("example.com")
        assert "asnmap" in cmd
        assert "-d" in cmd
        assert "example.com" in cmd
        assert "-json" in cmd
        assert "-silent" in cmd

    def test_parses_json_output(self, runner, db):
        tool = AsnmapTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(ASNMAP_OUTPUT)
        assert len(results) == 2
        assert results[0]["as_number"] == "AS13335"
        assert results[0]["as_name"] == "Cloudflare"
        assert results[0]["as_country"] == "US"
        assert results[0]["as_range"] == "104.16.0.0/12"

    def test_parses_empty_output(self, runner, db):
        tool = AsnmapTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_output_with_invalid_lines(self, runner, db):
        tool = AsnmapTool(runner=runner, db=db, program="test-corp")
        output = json.dumps({"as_number": "AS13335", "as_name": "Cloudflare", "as_country": "US", "as_range": "104.16.0.0/12"}) + "\nbad line\n"
        results = tool.parse_output(output)
        assert len(results) == 1

    async def test_run_stores_in_db(self, runner, db):
        tool = AsnmapTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=ASNMAP_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")
        assert summary["total"] == 2
        assert len(summary["ranges"]) == 2
        assert summary["ranges"][0]["as_number"] == "AS13335"
        assert summary["ranges"][0]["as_range"] == "104.16.0.0/12"

    async def test_run_handles_failure(self, runner, db):
        tool = AsnmapTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")
        assert summary["total"] == 0
        assert summary["error"] == "timeout"
