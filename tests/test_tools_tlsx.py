import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.tlsx import TlsxTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

TLSX_OUTPUT = "\n".join([
    json.dumps({
        "host": "example.com",
        "subject_cn": "example.com",
        "san": ["www.example.com", "api.example.com", "*.example.com"],
        "issuer_org": "Let's Encrypt",
    }),
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

class TestTlsxTool:
    def test_builds_command(self, runner, db, tmp_path):
        tool = TlsxTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        cmd = tool.build_command(["example.com"], work_dir)
        assert "tlsx" in cmd
        assert "-l" in cmd
        assert "-json" in cmd
        assert "-silent" in cmd
        assert "-san" in cmd
        assert "-cn" in cmd

    def test_parses_json_output(self, runner, db):
        tool = TlsxTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(TLSX_OUTPUT)
        assert len(results) == 1
        assert results[0]["host"] == "example.com"
        assert results[0]["subject_cn"] == "example.com"
        assert "www.example.com" in results[0]["san"]
        assert "*.example.com" in results[0]["san"]
        assert results[0]["issuer_org"] == "Let's Encrypt"

    def test_parses_empty_output(self, runner, db):
        tool = TlsxTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_output_with_invalid_lines(self, runner, db):
        tool = TlsxTool(runner=runner, db=db, program="test-corp")
        output = json.dumps({"host": "example.com", "san": ["www.example.com"]}) + "\nbad line\n"
        results = tool.parse_output(output)
        assert len(results) == 1

    async def test_run_stores_in_db(self, runner, db, tmp_path):
        tool = TlsxTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        mock_result = ToolResult(success=True, output=TLSX_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["example.com"], work_dir)
        subs = await db.get_subdomains("test-corp")
        # Wildcard *.example.com should be filtered; non-wildcard SANs + CN stored
        subdomain_names = [s["domain"] if isinstance(s, dict) else s for s in subs]
        assert "www.example.com" in subdomain_names or len(subs) >= 2
        assert summary["total"] == 1
        # new_domains should not contain wildcard entries
        for domain in summary["new_domains"]:
            assert not domain.startswith("*")

    async def test_run_filters_wildcard_sans(self, runner, db, tmp_path):
        tool = TlsxTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        mock_result = ToolResult(success=True, output=TLSX_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["example.com"], work_dir)
        for domain in summary["new_domains"]:
            assert not domain.startswith("*")
        # www.example.com and api.example.com and example.com (CN) should be present
        assert "www.example.com" in summary["new_domains"]
        assert "api.example.com" in summary["new_domains"]

    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = TlsxTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        mock_result = ToolResult(success=False, output="", error="connection refused")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["example.com"], work_dir)
        assert summary["total"] == 0
        assert summary["error"] == "connection refused"
