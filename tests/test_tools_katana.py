import json
import pytest
from unittest.mock import patch
from pathlib import Path
from bba.tools.katana import KatanaTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {"program": "test-corp", "in_scope": {"domains": ["*.example.com", "example.com"]}}

KATANA_OUTPUT = "\n".join([
    json.dumps({"request": {"endpoint": "https://shop.example.com/products"}}),
    json.dumps({"request": {"endpoint": "https://shop.example.com/cart"}}),
    json.dumps({"request": {"endpoint": "https://shop.example.com/api/v1/items"}}),
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

class TestKatanaTool:
    def test_builds_command(self, runner, db, tmp_path):
        tool = KatanaTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(["https://shop.example.com"], tmp_path)
        assert "katana" in cmd
        assert "-silent" in cmd
        assert "-json" in cmd

    def test_parses_json_output(self, runner, db):
        tool = KatanaTool(runner=runner, db=db, program="test-corp")
        urls = tool.parse_output(KATANA_OUTPUT)
        assert len(urls) == 3
        assert "https://shop.example.com/products" in urls

    async def test_run_returns_url_count(self, runner, db, tmp_path):
        tool = KatanaTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=KATANA_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["https://shop.example.com"], work_dir=tmp_path)
        assert summary["total"] == 3
        assert len(summary["urls"]) == 3

    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = KatanaTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="crash")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["https://shop.example.com"], work_dir=tmp_path)
        assert summary["total"] == 0
