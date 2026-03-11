import pytest
from bba.tool_runner import ToolRunner, ToolResult
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {"program": "test", "in_scope": {"domains": ["example.com", "*.example.com"], "cidrs": []}, "out_of_scope": {}}


@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))


class TestDryRun:
    @pytest.mark.asyncio
    async def test_dry_run_no_execution(self, scope, tmp_path):
        runner = ToolRunner(
            scope=scope, rate_limiter=MultiTargetRateLimiter(),
            sanitizer=Sanitizer(), output_dir=tmp_path / "output",
            dry_run=True,
        )
        result = await runner.run_command(
            tool="nuclei", command=["nuclei", "-u", "https://example.com"],
            targets=["example.com"], timeout=60,
        )
        assert result.success
        assert "dry-run" in result.output.lower() or "dry_run" in result.output.lower()
        assert result.duration < 0.1

    @pytest.mark.asyncio
    async def test_dry_run_logs_command(self, scope, tmp_path):
        runner = ToolRunner(
            scope=scope, rate_limiter=MultiTargetRateLimiter(),
            sanitizer=Sanitizer(), output_dir=tmp_path / "output",
            dry_run=True,
        )
        result = await runner.run_command(
            tool="ffuf", command=["ffuf", "-u", "https://example.com/FUZZ"],
            targets=["example.com"], timeout=60,
        )
        assert "ffuf" in result.output
        assert "example.com" in result.output

    @pytest.mark.asyncio
    async def test_dry_run_still_validates_scope(self, scope, tmp_path):
        runner = ToolRunner(
            scope=scope, rate_limiter=MultiTargetRateLimiter(),
            sanitizer=Sanitizer(), output_dir=tmp_path / "output",
            dry_run=True,
        )
        # evil.com is not in scope - should raise ValueError
        with pytest.raises(ValueError, match="[Oo]ut of scope|not in scope|not allowed"):
            await runner.run_command(
                tool="nuclei", command=["nuclei", "-u", "https://evil.com"],
                targets=["evil.com"], timeout=60,
            )
