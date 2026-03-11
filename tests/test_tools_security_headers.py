import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.security_headers import SecurityHeadersTool, REQUIRED_HEADERS, DANGEROUS_HEADERS
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

RESPONSE_MISSING_ALL = """HTTP/1.1 200 OK
Content-Type: text/html
Connection: keep-alive
"""

RESPONSE_ALL_PRESENT = """HTTP/1.1 200 OK
Content-Type: text/html
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin
Permissions-Policy: camera=()
X-XSS-Protection: 1; mode=block
"""

RESPONSE_DANGEROUS = """HTTP/1.1 200 OK
Server: Apache/2.4.51
X-Powered-By: PHP/7.4
X-AspNet-Version: 4.0.30319
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin
Permissions-Policy: camera=()
X-XSS-Protection: 1; mode=block
"""


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


class TestSecurityHeadersTool:
    def test_analyze_missing_headers(self, runner, db):
        tool = SecurityHeadersTool(runner=runner, db=db, program="test-corp")
        analysis = tool.analyze_headers(RESPONSE_MISSING_ALL)
        assert len(analysis["missing"]) == len(REQUIRED_HEADERS)
        assert analysis["dangerous"] == []

    def test_analyze_all_present(self, runner, db):
        tool = SecurityHeadersTool(runner=runner, db=db, program="test-corp")
        analysis = tool.analyze_headers(RESPONSE_ALL_PRESENT)
        assert analysis["missing"] == []
        assert analysis["dangerous"] == []

    def test_analyze_dangerous_headers(self, runner, db):
        tool = SecurityHeadersTool(runner=runner, db=db, program="test-corp")
        analysis = tool.analyze_headers(RESPONSE_DANGEROUS)
        assert analysis["missing"] == []
        assert len(analysis["dangerous"]) == 3
        header_names = [d["header"] for d in analysis["dangerous"]]
        assert "Server" in header_names
        assert "X-Powered-By" in header_names
        assert "X-AspNet-Version" in header_names

    def test_analyze_empty_response(self, runner, db):
        tool = SecurityHeadersTool(runner=runner, db=db, program="test-corp")
        analysis = tool.analyze_headers("")
        assert len(analysis["missing"]) == len(REQUIRED_HEADERS)

    async def test_run_success(self, runner, db):
        tool = SecurityHeadersTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=RESPONSE_MISSING_ALL, raw_file=Path("/tmp/test.txt"))
        with patch.object(runner, "run_http_request", return_value=mock_result):
            summary = await tool.run("https://example.com")
        assert summary["missing_count"] == len(REQUIRED_HEADERS)
        assert summary["dangerous_count"] == 0
        assert summary["url"] == "https://example.com"

    async def test_run_failure(self, runner, db):
        tool = SecurityHeadersTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_http_request", return_value=mock_result):
            summary = await tool.run("https://example.com")
        assert summary["missing"] == []
        assert summary["error"] == "timeout"
