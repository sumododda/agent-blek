import pytest
from unittest.mock import patch
from pathlib import Path
from bba.tools.subzy import SubzyTool
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


class TestSubzyTool:
    def test_build_command(self, runner, db, tmp_path):
        tool = SubzyTool(runner=runner, db=db, program="test")
        cmd = tool.build_command(["sub.example.com", "test.example.com"], tmp_path)
        assert "subzy" in cmd[0]
        assert "run" in cmd
        assert "--targets" in cmd

    def test_build_command_writes_targets(self, runner, db, tmp_path):
        tool = SubzyTool(runner=runner, db=db, program="test")
        tool.build_command(["sub.example.com"], tmp_path)
        targets_file = tmp_path / "subzy_targets.txt"
        assert targets_file.exists()
        assert "sub.example.com" in targets_file.read_text()

    def test_parse_output_vulnerable(self, runner, db):
        tool = SubzyTool(runner=runner, db=db, program="test")
        output = '{"subdomain": "old.example.com", "vulnerable": true, "service": "github", "cname": "old.github.io"}\n'
        result = tool.parse_output(output)
        assert len(result) == 1
        assert result[0]["service"] == "github"

    def test_parse_output_not_vulnerable(self, runner, db):
        tool = SubzyTool(runner=runner, db=db, program="test")
        output = '{"subdomain": "www.example.com", "vulnerable": false}\n'
        result = tool.parse_output(output)
        assert len(result) == 0

    def test_parse_output_empty(self, runner, db):
        tool = SubzyTool(runner=runner, db=db, program="test")
        assert tool.parse_output("") == []

    @pytest.mark.asyncio
    async def test_run_stores_finding(self, runner, db, tmp_path):
        tool = SubzyTool(runner=runner, db=db, program="test")
        mock = ToolResult(
            success=True,
            output='{"subdomain": "old.example.com", "vulnerable": true, "service": "github", "cname": "old.github.io"}\n',
            raw_file=None, error=None, duration=5.0,
        )
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run(["old.example.com", "www.example.com"], tmp_path)
        assert result["total"] == 1
        assert result["scanned"] == 2
        findings = await db.get_findings("test")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "subdomain-takeover"

    @pytest.mark.asyncio
    async def test_run_failure(self, runner, db, tmp_path):
        tool = SubzyTool(runner=runner, db=db, program="test")
        mock = ToolResult(success=False, output="", raw_file=None, error="timeout", duration=300.0)
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run(["old.example.com"], tmp_path)
        assert result["total"] == 0
        assert "error" in result

    @pytest.mark.asyncio
    async def test_run_no_vulnerabilities(self, runner, db, tmp_path):
        tool = SubzyTool(runner=runner, db=db, program="test")
        mock = ToolResult(
            success=True,
            output='{"subdomain": "www.example.com", "vulnerable": false}\n',
            raw_file=None, error=None, duration=3.0,
        )
        with patch.object(runner, "run_command", return_value=mock):
            result = await tool.run(["www.example.com"], tmp_path)
        assert result["total"] == 0
