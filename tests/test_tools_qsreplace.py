from __future__ import annotations
import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from bba.tools.qsreplace import QsreplaceTool
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}


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


def _make_mock_process(stdout_data: str, returncode: int = 0, stderr_data: str = ""):
    """Create a mock process that returns given stdout/stderr."""
    mock_proc = AsyncMock()
    mock_proc.communicate = AsyncMock(return_value=(
        stdout_data.encode(),
        stderr_data.encode(),
    ))
    mock_proc.returncode = returncode
    return mock_proc


class TestQsreplaceTool:
    def test_build_command(self, runner, db, tmp_path):
        tool = QsreplaceTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        cmd = tool.build_command(["https://example.com/a?id=1"], "FUZZ", work_dir)
        assert cmd == ["qsreplace", "FUZZ"]

    def test_build_command_no_shell_injection(self, runner, db, tmp_path):
        tool = QsreplaceTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        malicious_payload = "'; cat /etc/passwd; echo '"
        cmd = tool.build_command(["https://example.com/a?id=1"], malicious_payload, work_dir)
        assert cmd[0] != "sh"
        assert cmd == ["qsreplace", malicious_payload]

    def test_build_command_writes_input_file(self, runner, db, tmp_path):
        tool = QsreplaceTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        urls = ["https://example.com/a?id=1", "https://example.com/b?name=foo"]
        tool.build_command(urls, "PAYLOAD", work_dir)
        input_file = work_dir / "qsreplace_input.txt"
        assert input_file.exists()
        content = input_file.read_text()
        assert "https://example.com/a?id=1" in content

    def test_parse_output(self, runner, db):
        tool = QsreplaceTool(runner=runner, db=db, program="test-corp")
        output = "https://example.com/a?id=FUZZ\nhttps://example.com/b?name=FUZZ\n"
        result = tool.parse_output(output)
        assert len(result) == 2

    def test_parse_empty(self, runner, db):
        tool = QsreplaceTool(runner=runner, db=db, program="test-corp")
        assert tool.parse_output("") == []

    def test_parse_output_strips_whitespace(self, runner, db):
        tool = QsreplaceTool(runner=runner, db=db, program="test-corp")
        output = "  https://example.com/a?id=FUZZ  \nhttps://example.com/b?x=FUZZ\n"
        result = tool.parse_output(output)
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_run_replaces_params(self, runner, db, tmp_path):
        tool = QsreplaceTool(runner=runner, db=db, program="test-corp")
        mock_proc = _make_mock_process("https://example.com/a?id=PAYLOAD\n")
        with patch("bba.tools.qsreplace.asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await tool.run(["https://example.com/a?id=1"], "PAYLOAD", tmp_path)
        assert result["total"] == 1
        assert "PAYLOAD" in result["urls"][0]
        assert result["payload"] == "PAYLOAD"

    @pytest.mark.asyncio
    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = QsreplaceTool(runner=runner, db=db, program="test-corp")
        mock_proc = _make_mock_process("", returncode=1, stderr_data="not found")
        with patch("bba.tools.qsreplace.asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await tool.run(["https://example.com/a?id=1"], "FUZZ", tmp_path)
        assert result["total"] == 0
        assert "error" in result

    @pytest.mark.asyncio
    async def test_run_empty_input(self, runner, db, tmp_path):
        tool = QsreplaceTool(runner=runner, db=db, program="test-corp")
        result = await tool.run([], "FUZZ", tmp_path)
        assert result["total"] == 0
        assert result["payload"] == "FUZZ"

    @pytest.mark.asyncio
    async def test_run_multiple_urls(self, runner, db, tmp_path):
        tool = QsreplaceTool(runner=runner, db=db, program="test-corp")
        mock_output = "https://example.com/a?id=XSS\nhttps://example.com/b?name=XSS\n"
        mock_proc = _make_mock_process(mock_output)
        with patch("bba.tools.qsreplace.asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await tool.run(
                ["https://example.com/a?id=1", "https://example.com/b?name=foo"],
                "XSS", tmp_path
            )
        assert result["total"] == 2
        assert result["payload"] == "XSS"
