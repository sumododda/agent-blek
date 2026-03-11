import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.sourcemap_detector import SourcemapDetectorTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

SOURCEMAP_CONTENT = '{"version":3,"sources":["src/app.ts","src/utils.ts"],"mappings":"AAAA"}'


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


class TestSourcemapDetectorTool:
    async def test_detects_source_map(self, runner, db):
        tool = SourcemapDetectorTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=SOURCEMAP_CONTENT, raw_file=None)
        with patch.object(runner, "run_http_request", return_value=mock_result):
            result = await tool.run(["https://example.com/static/app.js"])
        assert result["found"] == 1
        assert result["checked"] == 1
        assert "https://example.com/static/app.js.map" in result["source_maps"]
        findings = await db.get_findings("test-corp")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "exposed-source-map"

    async def test_no_source_map(self, runner, db):
        tool = SourcemapDetectorTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output="<html>404</html>", raw_file=None)
        with patch.object(runner, "run_http_request", return_value=mock_result):
            result = await tool.run(["https://example.com/static/app.js"])
        assert result["found"] == 0
        assert result["checked"] == 1

    async def test_request_failure(self, runner, db):
        tool = SourcemapDetectorTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_http_request", return_value=mock_result):
            result = await tool.run(["https://example.com/static/app.js"])
        assert result["found"] == 0
        assert result["checked"] == 1

    async def test_empty_input(self, runner, db):
        tool = SourcemapDetectorTool(runner=runner, db=db, program="test-corp")
        result = await tool.run([])
        assert result["found"] == 0
        assert result["checked"] == 0
