import pytest
from unittest.mock import patch
from bba.tools.jsluice import JsluiceTool
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


class TestJsluiceTool:
    def test_build_command_urls(self, runner, db):
        tool = JsluiceTool(runner=runner, db=db, program="test")
        cmd = tool.build_command_urls("https://example.com/app.js")
        assert cmd[0] == "jsluice"
        assert "urls" in cmd
        assert "-R" in cmd

    def test_build_command_secrets(self, runner, db):
        tool = JsluiceTool(runner=runner, db=db, program="test")
        cmd = tool.build_command_secrets("https://example.com/app.js")
        assert cmd[0] == "jsluice"
        assert "secrets" in cmd

    def test_parse_output_json(self, runner, db):
        tool = JsluiceTool(runner=runner, db=db, program="test")
        output = '{"url": "https://api.example.com/v1/users"}\n{"url": "/api/config"}\n'
        result = tool.parse_output(output)
        assert len(result) == 2

    def test_parse_output_empty(self, runner, db):
        tool = JsluiceTool(runner=runner, db=db, program="test")
        assert tool.parse_output("") == []

    def test_parse_output_skips_invalid(self, runner, db):
        tool = JsluiceTool(runner=runner, db=db, program="test")
        output = 'not json\n{"url": "https://example.com/api"}\n'
        result = tool.parse_output(output)
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_run_urls(self, runner, db):
        tool = JsluiceTool(runner=runner, db=db, program="test")
        mock = ToolResult(success=True, output='{"url": "https://example.com/api/users"}\n{"url": "/config"}\n', raw_file=None, error=None, duration=1.0)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run_urls("https://example.com/app.js", "example.com")
        assert result["total"] == 2
        assert result["source"] == "https://example.com/app.js"

    @pytest.mark.asyncio
    async def test_run_urls_failure(self, runner, db):
        tool = JsluiceTool(runner=runner, db=db, program="test")
        mock = ToolResult(success=False, output="", raw_file=None, error="not found", duration=0.5)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run_urls("https://example.com/app.js", "example.com")
        assert result["total"] == 0
        assert "error" in result

    @pytest.mark.asyncio
    async def test_run_secrets_stores_in_db(self, runner, db):
        tool = JsluiceTool(runner=runner, db=db, program="test")
        mock = ToolResult(success=True, output='{"kind": "AWSAccessKey", "data": {"key": "AKIAIOSFODNN7EXAMPLE"}}\n', raw_file=None, error=None, duration=1.0)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run_secrets("https://example.com/app.js", "example.com")
        assert result["total"] == 1
        secrets = await db.get_secrets("test")
        assert len(secrets) == 1

    @pytest.mark.asyncio
    async def test_run_secrets_failure(self, runner, db):
        tool = JsluiceTool(runner=runner, db=db, program="test")
        mock = ToolResult(success=False, output="", raw_file=None, error="timeout", duration=60.0)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run_secrets("https://example.com/app.js", "example.com")
        assert result["total"] == 0
