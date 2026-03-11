import pytest
from unittest.mock import AsyncMock, patch
from pathlib import Path

from bba.tool_runner import ToolRunner, ToolResult
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer


SCOPE = {
    "program": "test",
    "in_scope": {"domains": ["*.example.com"]},
    "out_of_scope": {"domains": ["admin.example.com"]},
}


@pytest.fixture
def runner(tmp_path):
    config = ScopeConfig.from_dict(SCOPE)
    validator = ScopeValidator(config)
    return ToolRunner(
        scope=validator,
        rate_limiter=MultiTargetRateLimiter(default_rps=100),
        sanitizer=Sanitizer(),
        output_dir=tmp_path / "output",
    )


class TestToolResult:
    def test_result_success(self):
        r = ToolResult(success=True, output="found 5 subdomains", raw_file=Path("/tmp/out.json"))
        assert r.success
        assert "5 subdomains" in r.output

    def test_result_failure(self):
        r = ToolResult(success=False, output="", error="timeout")
        assert not r.success
        assert r.error == "timeout"


class TestToolRunner:
    def test_rejects_out_of_scope_target(self, runner):
        with pytest.raises(ValueError, match="out of scope"):
            runner.validate_targets(["evil.com"])

    def test_accepts_in_scope_target(self, runner):
        runner.validate_targets(["shop.example.com"])

    def test_rejects_excluded_target(self, runner):
        with pytest.raises(ValueError, match="out of scope"):
            runner.validate_targets(["admin.example.com"])

    def test_rejects_mixed_targets(self, runner):
        with pytest.raises(ValueError, match="out of scope"):
            runner.validate_targets(["shop.example.com", "evil.com"])

    def test_output_dir_created(self, runner):
        runner._ensure_output_dir("nuclei")
        assert (runner.output_dir / "nuclei").is_dir()

    async def test_run_command(self, runner):
        result = await runner.run_command(
            tool="echo-test",
            command=["echo", '{"result": "ok"}'],
            targets=["test.example.com"],
        )
        assert result.success
        assert "ok" in result.output

    async def test_run_command_out_of_scope_blocked(self, runner):
        with pytest.raises(ValueError, match="out of scope"):
            await runner.run_command(
                tool="nmap",
                command=["nmap", "evil.com"],
                targets=["evil.com"],
            )

    async def test_run_command_stores_raw_output(self, runner):
        result = await runner.run_command(
            tool="test-tool",
            command=["echo", "raw data here"],
            targets=["a.example.com"],
        )
        assert result.raw_file is not None
        assert result.raw_file.exists()
        assert "raw data here" in result.raw_file.read_text()
