import pytest
from unittest.mock import patch
from bba.tools.clairvoyance import ClairvoyanceTool
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {"program": "test", "in_scope": {"domains": ["*.example.com"], "cidrs": []}, "out_of_scope": {}}

@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))

@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(), sanitizer=Sanitizer(), output_dir=tmp_path / "output")

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestClairvoyanceTool:
    def test_build_command(self, runner, db):
        tool = ClairvoyanceTool(runner=runner, db=db, program="test")
        cmd = tool.build_command("https://example.com/graphql")
        assert "clairvoyance" in cmd[0]
        assert "-u" in cmd
        assert "-o" in cmd

    def test_build_command_with_wordlist(self, runner, db):
        tool = ClairvoyanceTool(runner=runner, db=db, program="test")
        cmd = tool.build_command("https://example.com/graphql", wordlist="/tmp/words.txt")
        assert "-w" in cmd
        assert "/tmp/words.txt" in cmd

    def test_parse_output_valid_schema(self, runner, db):
        tool = ClairvoyanceTool(runner=runner, db=db, program="test")
        schema = '{"data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}}'
        result = tool.parse_output(schema)
        assert result["type_count"] == 2
        assert result["schema"] is not None

    def test_parse_output_invalid_json(self, runner, db):
        tool = ClairvoyanceTool(runner=runner, db=db, program="test")
        result = tool.parse_output("not json")
        assert result["type_count"] == 0
        assert result["schema"] is None

    def test_parse_output_empty_schema(self, runner, db):
        tool = ClairvoyanceTool(runner=runner, db=db, program="test")
        result = tool.parse_output('{"data": {"__schema": {"types": []}}}')
        assert result["type_count"] == 0

    @pytest.mark.asyncio
    async def test_run_success(self, runner, db):
        tool = ClairvoyanceTool(runner=runner, db=db, program="test")
        schema = '{"data": {"__schema": {"types": [{"name": "Query"}, {"name": "Mutation"}]}}}'
        mock = ToolResult(success=True, output=schema, raw_file=None, error=None, duration=10.0)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run("https://example.com/graphql")
        assert result["success"] is True
        assert result["types_found"] == 2

    @pytest.mark.asyncio
    async def test_run_failure(self, runner, db):
        tool = ClairvoyanceTool(runner=runner, db=db, program="test")
        mock = ToolResult(success=False, output="", raw_file=None, error="timeout", duration=300.0)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run("https://example.com/graphql")
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_run_no_types_found(self, runner, db):
        tool = ClairvoyanceTool(runner=runner, db=db, program="test")
        mock = ToolResult(success=True, output='{"data": {"__schema": {"types": []}}}', raw_file=None, error=None, duration=5.0)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run("https://example.com/graphql")
        assert result["success"] is False
        assert result["types_found"] == 0
