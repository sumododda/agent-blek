import pytest
from unittest.mock import patch
from pathlib import Path
from bba.validator import FindingValidator, ValidationResult
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {"program": "test-corp", "in_scope": {"domains": ["*.example.com", "example.com"]}}

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

class TestValidationResult:
    def test_validated_result(self):
        r = ValidationResult(finding_id=1, status="validated", confidence=0.95, evidence="confirmed XSS")
        assert r.status == "validated" and r.confidence == 0.95

    def test_false_positive_result(self):
        r = ValidationResult(finding_id=2, status="false_positive", confidence=0.1, evidence="not reproducible")
        assert r.status == "false_positive"

class TestFindingValidator:
    async def test_validates_xss_finding(self, runner, db):
        fid = await db.add_finding("test-corp", "shop.example.com", "https://shop.example.com/search?q=<script>", "xss", "high", "dalfox", "reflected XSS", 0.85)
        validator = FindingValidator(runner=runner, db=db)
        curl_output = '<html><body>Results for: <script>alert(1)</script></body></html>'
        mock_result = ToolResult(success=True, output=curl_output, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            results = await validator.validate_findings("test-corp")
        assert len(results) == 1 and results[0].status == "validated" and results[0].confidence >= 0.8

    async def test_marks_false_positive(self, runner, db):
        await db.add_finding("test-corp", "api.example.com", "https://api.example.com/test", "xss", "high", "nuclei", "possible XSS", 0.7)
        validator = FindingValidator(runner=runner, db=db)
        curl_output = '<html><body>404 Not Found</body></html>'
        mock_result = ToolResult(success=True, output=curl_output, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            results = await validator.validate_findings("test-corp")
        assert len(results) == 1 and results[0].status == "false_positive"

    async def test_updates_db_status(self, runner, db):
        await db.add_finding("test-corp", "shop.example.com", "https://shop.example.com/vuln", "sql-injection", "critical", "sqlmap", "injectable", 0.9)
        validator = FindingValidator(runner=runner, db=db)
        mock_result = ToolResult(success=True, output="SQL error in response mysql syntax error", raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            await validator.validate_findings("test-corp")
        findings = await db.get_findings("test-corp", status="validated")
        assert len(findings) == 1

    async def test_handles_unreachable_target(self, runner, db):
        await db.add_finding("test-corp", "dead.example.com", "https://dead.example.com/page", "xss", "high", "nuclei", "xss", 0.8)
        validator = FindingValidator(runner=runner, db=db)
        mock_result = ToolResult(success=False, output="", error="connection refused")
        with patch.object(runner, "run_command", return_value=mock_result):
            results = await validator.validate_findings("test-corp")
        assert len(results) == 1 and results[0].status == "needs_review"

    async def test_skips_already_validated(self, runner, db):
        fid = await db.add_finding("test-corp", "a.example.com", "https://a.example.com", "xss", "high", "t", "", 0.9)
        await db.update_finding_status(fid, "validated")
        validator = FindingValidator(runner=runner, db=db)
        results = await validator.validate_findings("test-corp")
        assert len(results) == 0

    async def test_returns_summary(self, runner, db):
        await db.add_finding("test-corp", "a.example.com", "https://a.example.com/1", "xss", "high", "t", "", 0.8)
        await db.add_finding("test-corp", "b.example.com", "https://b.example.com/2", "sql-injection", "critical", "t", "", 0.9)
        validator = FindingValidator(runner=runner, db=db)
        mock_result = ToolResult(success=True, output="vulnerable content here", raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            results = await validator.validate_findings("test-corp")
        summary = validator.get_summary(results)
        assert summary["total"] == 2
        assert "validated" in summary["by_status"] or "false_positive" in summary["by_status"] or "needs_review" in summary["by_status"]
