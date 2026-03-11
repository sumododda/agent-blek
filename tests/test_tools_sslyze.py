import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.sslyze import SslyzeTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

SSLYZE_HEARTBLEED = json.dumps({
    "server_scan_results": [{
        "scan_result": {
            "heartbleed": {"is_vulnerable_to_heartbleed": True},
            "ssl_2_0_cipher_suites": {"accepted_cipher_suites": []},
            "ssl_3_0_cipher_suites": {"accepted_cipher_suites": []},
            "certificate_info": {"certificate_deployments": []},
        }
    }]
})

SSLYZE_DEPRECATED = json.dumps({
    "server_scan_results": [{
        "scan_result": {
            "heartbleed": {"is_vulnerable_to_heartbleed": False},
            "ssl_2_0_cipher_suites": {"accepted_cipher_suites": [{"name": "SSL_RSA_WITH_RC4_128_SHA"}]},
            "ssl_3_0_cipher_suites": {"accepted_cipher_suites": []},
            "certificate_info": {"certificate_deployments": []},
        }
    }]
})

SSLYZE_CERT_FAIL = json.dumps({
    "server_scan_results": [{
        "scan_result": {
            "heartbleed": {"is_vulnerable_to_heartbleed": False},
            "ssl_2_0_cipher_suites": {"accepted_cipher_suites": []},
            "ssl_3_0_cipher_suites": {"accepted_cipher_suites": []},
            "certificate_info": {
                "certificate_deployments": [{
                    "path_validation_results": [
                        {"was_validation_successful": False, "openssl_error_string": "self signed certificate"}
                    ]
                }]
            },
        }
    }]
})

SSLYZE_CLEAN = json.dumps({
    "server_scan_results": [{
        "scan_result": {
            "heartbleed": {"is_vulnerable_to_heartbleed": False},
            "ssl_2_0_cipher_suites": {"accepted_cipher_suites": []},
            "ssl_3_0_cipher_suites": {"accepted_cipher_suites": []},
            "certificate_info": {"certificate_deployments": []},
        }
    }]
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


class TestSslyzeTool:
    def test_builds_command(self, runner, db):
        tool = SslyzeTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("example.com:443")
        assert "sslyze" in cmd
        assert "--json_out=-" in cmd
        assert "example.com:443" in cmd

    def test_parses_heartbleed(self, runner, db):
        tool = SslyzeTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(SSLYZE_HEARTBLEED)
        assert len(results) == 1
        assert results[0]["type"] == "heartbleed"
        assert results[0]["severity"] == "critical"

    def test_parses_deprecated_protocol(self, runner, db):
        tool = SslyzeTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(SSLYZE_DEPRECATED)
        assert len(results) == 1
        assert "deprecated" in results[0]["type"]
        assert results[0]["severity"] == "high"

    def test_parses_cert_failure(self, runner, db):
        tool = SslyzeTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(SSLYZE_CERT_FAIL)
        assert len(results) == 1
        assert results[0]["type"] == "certificate-validation-failure"
        assert "self signed" in results[0]["detail"]

    def test_parses_clean_output(self, runner, db):
        tool = SslyzeTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(SSLYZE_CLEAN)
        assert results == []

    def test_parses_invalid_json(self, runner, db):
        tool = SslyzeTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("not json")
        assert results == []

    async def test_run_success(self, runner, db):
        tool = SslyzeTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=SSLYZE_HEARTBLEED, raw_file=Path("/tmp/test.json"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com:443")
        assert summary["total"] == 1
        assert summary["findings"][0]["type"] == "heartbleed"

    async def test_run_failure(self, runner, db):
        tool = SslyzeTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="connection refused")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com:443")
        assert summary["total"] == 0
        assert summary["error"] == "connection refused"
