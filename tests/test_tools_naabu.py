import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.naabu import NaabuTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

NAABU_OUTPUT = "\n".join([
    json.dumps({"host": "example.com", "ip": "1.2.3.4", "port": 80}),
    json.dumps({"host": "example.com", "ip": "1.2.3.4", "port": 443}),
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

class TestNaabuTool:
    def test_builds_command(self, runner, db, tmp_path):
        tool = NaabuTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        cmd = tool.build_command(["example.com"], work_dir)
        assert "naabu" in cmd
        assert "-list" in cmd
        assert "-json" in cmd
        assert "-silent" in cmd

    def test_builds_command_all_ports(self, runner, db, tmp_path):
        tool = NaabuTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        cmd = tool.build_command(["example.com"], work_dir, ports="all")
        assert "-p" in cmd
        assert "-" in cmd

    def test_parses_json_output(self, runner, db):
        tool = NaabuTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(NAABU_OUTPUT)
        assert len(results) == 2
        assert results[0]["host"] == "example.com"
        assert results[0]["port"] == 80
        assert results[1]["port"] == 443

    def test_parses_empty_output(self, runner, db):
        tool = NaabuTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_output_with_invalid_lines(self, runner, db):
        tool = NaabuTool(runner=runner, db=db, program="test-corp")
        output = json.dumps({"host": "example.com", "ip": "1.2.3.4", "port": 80}) + "\nbad line\n"
        results = tool.parse_output(output)
        assert len(results) == 1

    async def test_run_stores_in_db(self, runner, db, tmp_path):
        tool = NaabuTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        mock_result = ToolResult(success=True, output=NAABU_OUTPUT, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["example.com"], work_dir)
        ports = await db.get_ports("test-corp")
        assert len(ports) == 2
        assert summary["total"] == 2

    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = NaabuTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["example.com"], work_dir)
        assert summary["total"] == 0
        assert summary["error"] == "timeout"
