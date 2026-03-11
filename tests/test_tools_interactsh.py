import pytest
from unittest.mock import patch
from bba.tools.interactsh import InteractshTool
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


class TestInteractshTool:
    def test_build_generate_command(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        cmd = tool.build_generate_command(count=5)
        assert "interactsh-client" in cmd[0]
        assert "-n" in cmd
        assert "5" in cmd

    def test_build_generate_command_with_server(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        cmd = tool.build_generate_command(count=3, server="https://my-server.com")
        assert "-server" in cmd
        assert "https://my-server.com" in cmd

    def test_build_poll_command(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        cmd = tool.build_poll_command(session_file="/tmp/session.yaml")
        assert "-sf" in cmd
        assert "/tmp/session.yaml" in cmd

    def test_parse_interactions(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        output = '{"protocol":"dns","unique-id":"abc123","full-id":"abc123.interact.sh","remote-address":"1.2.3.4","timestamp":"2026-01-01T00:00:00Z"}\n'
        result = tool.parse_interactions(output)
        assert len(result) == 1
        assert result[0]["protocol"] == "dns"
        assert result[0]["unique-id"] == "abc123"

    def test_parse_interactions_multiple(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        output = (
            '{"protocol":"dns","unique-id":"abc123","remote-address":"1.2.3.4"}\n'
            '{"protocol":"http","unique-id":"def456","remote-address":"5.6.7.8"}\n'
        )
        result = tool.parse_interactions(output)
        assert len(result) == 2
        assert result[0]["protocol"] == "dns"
        assert result[1]["protocol"] == "http"

    def test_parse_empty(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        assert tool.parse_interactions("") == []

    def test_parse_generated_urls(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        output = "abc123.oast.live\ndef456.oast.live\n"
        urls = tool.parse_generated_urls(output)
        assert len(urls) == 2
        assert "abc123.oast.live" in urls

    def test_parse_generated_urls_skips_json(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        output = '{"some":"json"}\nabc123.oast.live\n'
        urls = tool.parse_generated_urls(output)
        assert len(urls) == 1
        assert "abc123.oast.live" in urls

    @pytest.mark.asyncio
    async def test_generate_urls(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        mock_result = ToolResult(
            success=True,
            output="abc123.oast.live\ndef456.oast.live\n",
            raw_file=None, error=None, duration=1.0,
        )
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.generate_urls(count=2)
        assert result["total"] == 2
        assert "abc123.oast.live" in result["urls"]

    @pytest.mark.asyncio
    async def test_generate_urls_failure(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        mock_result = ToolResult(
            success=False, output="", raw_file=None, error="not found", duration=0.5,
        )
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.generate_urls(count=2)
        assert result["total"] == 0
        assert "error" in result

    @pytest.mark.asyncio
    async def test_poll_interactions_stores_findings(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        mock_result = ToolResult(
            success=True,
            output='{"protocol":"dns","unique-id":"abc123","remote-address":"1.2.3.4"}\n',
            raw_file=None, error=None, duration=2.0,
        )
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.poll_interactions("/tmp/session.yaml", domain="example.com")
        assert result["total"] == 1
        findings = await db.get_findings("test")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "oob-dns-interaction"
        assert findings[0]["tool"] == "interactsh"

    @pytest.mark.asyncio
    async def test_poll_interactions_failure(self, runner, db):
        tool = InteractshTool(runner=runner, db=db, program="test")
        mock_result = ToolResult(
            success=False, output="", raw_file=None, error="timeout", duration=30.0,
        )
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.poll_interactions("/tmp/session.yaml", domain="example.com")
        assert result["total"] == 0
        assert "error" in result
