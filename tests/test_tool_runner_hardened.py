import pytest
import asyncio
from bba.tool_runner import ToolRunner, ToolResult
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {"program": "test", "in_scope": {"domains": ["*.example.com"], "cidrs": []}, "out_of_scope": {}}

@pytest.fixture
def runner(tmp_path):
    scope = ScopeValidator(ScopeConfig.from_dict(SCOPE))
    return ToolRunner(
        scope=scope,
        rate_limiter=MultiTargetRateLimiter(),
        sanitizer=Sanitizer(),
        output_dir=tmp_path / "output",
    )

class TestToolRunnerTimeout:
    @pytest.mark.asyncio
    async def test_timeout_kills_process(self, runner):
        """On timeout, the child process must be killed and error reported."""
        result = await runner.run_command(
            tool="test",
            command=["sleep", "60"],
            targets=["test.example.com"],
            timeout=1,
        )
        assert not result.success
        assert "timed out" in result.error.lower()

class TestToolRunnerTimestamp:
    @pytest.mark.asyncio
    async def test_no_timestamp_collision(self, runner):
        """Two runs in same second must not overwrite each other's output."""
        result1 = await runner.run_command(
            tool="test", command=["echo", "first"], targets=["test.example.com"], timeout=5,
        )
        result2 = await runner.run_command(
            tool="test", command=["echo", "second"], targets=["test.example.com"], timeout=5,
        )
        assert result1.raw_file != result2.raw_file
        assert result1.raw_file.read_text().strip() == "first"
        assert result2.raw_file.read_text().strip() == "second"
