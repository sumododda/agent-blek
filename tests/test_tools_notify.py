import pytest
from unittest.mock import patch
from bba.tools.notify import NotifyTool
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
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(),
                      sanitizer=Sanitizer(), output_dir=tmp_path / "output")


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestNotifyTool:
    def test_build_command_with_provider(self, runner, db):
        tool = NotifyTool(runner=runner, db=db, program="test")
        cmd = tool.build_command("New finding: XSS on example.com", provider_config="/etc/notify.yaml")
        assert "notify" in cmd[0]
        assert "-pc" in cmd
        assert "/etc/notify.yaml" in cmd

    def test_build_command_bulk(self, runner, db):
        tool = NotifyTool(runner=runner, db=db, program="test")
        cmd = tool.build_command_bulk("/tmp/messages.txt", provider_config="/etc/notify.yaml")
        assert "-data" in cmd

    def test_format_finding_message(self, runner, db):
        tool = NotifyTool(runner=runner, db=db, program="test")
        msg = tool.format_finding({
            "vuln_type": "xss", "severity": "high",
            "url": "https://example.com/search?q=test",
            "tool": "dalfox", "confidence": 0.9,
        })
        assert "xss" in msg.lower()
        assert "HIGH" in msg
        assert "example.com" in msg

    def test_format_diff_message(self, runner, db):
        tool = NotifyTool(runner=runner, db=db, program="test")
        msg = tool.format_diff({
            "added": ["new.example.com", "api.example.com"],
            "removed": ["old.example.com"],
            "unchanged": 5,
        }, category="subdomains", program="test-prog")
        assert "new.example.com" in msg
        assert "+2" in msg or "2 new" in msg.lower()

    @pytest.mark.asyncio
    async def test_send_message(self, runner, db):
        tool = NotifyTool(runner=runner, db=db, program="test")
        mock_result = ToolResult(success=True, output="sent", raw_file=None, error=None, duration=0.5)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.send("Test alert", provider_config="/etc/notify.yaml")
        assert result["sent"]
