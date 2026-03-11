import json
import pytest
from unittest.mock import patch
from pathlib import Path
from bba.tools.ffuf import FfufTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {"program": "test-corp", "in_scope": {"domains": ["*.example.com", "example.com"]}}

FFUF_OUTPUT = json.dumps({
    "results": [
        {"input": {"FUZZ": "admin"}, "url": "https://shop.example.com/admin", "status": 200, "length": 4521, "words": 312},
        {"input": {"FUZZ": "backup"}, "url": "https://shop.example.com/backup", "status": 403, "length": 287, "words": 14},
        {"input": {"FUZZ": ".env"}, "url": "https://shop.example.com/.env", "status": 200, "length": 890, "words": 45},
    ]
})

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

class TestFfufTool:
    def test_builds_command(self, runner, db):
        tool = FfufTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(target_url="https://shop.example.com/FUZZ", wordlist="/usr/share/wordlists/common.txt")
        assert "ffuf" in cmd and "-u" in cmd and "https://shop.example.com/FUZZ" in cmd and "-w" in cmd and "-json" in cmd and "-fc" in cmd

    def test_parses_json_output(self, runner, db):
        tool = FfufTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(FFUF_OUTPUT)
        assert len(results) == 3 and results[0]["url"] == "https://shop.example.com/admin" and results[2]["input"]["FUZZ"] == ".env"

    def test_parses_empty_output(self, runner, db):
        tool = FfufTool(runner=runner, db=db, program="test-corp")
        assert tool.parse_output("") == []

    async def test_run_stores_interesting_findings(self, runner, db):
        tool = FfufTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=FFUF_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(target_url="https://shop.example.com/FUZZ", wordlist="/usr/share/wordlists/common.txt")
        assert summary["total"] == 3 and summary["interesting"] >= 1

    async def test_run_handles_failure(self, runner, db):
        tool = FfufTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="crash")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(target_url="https://shop.example.com/FUZZ", wordlist="/usr/share/wordlists/common.txt")
        assert summary["total"] == 0
