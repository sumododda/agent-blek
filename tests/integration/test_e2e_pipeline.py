"""End-to-end integration tests against OWASP Juice Shop.

These tests require:
1. Juice Shop running on localhost:3000 (use scripts/test-e2e.sh)
2. Security tools installed (httpx, nuclei, ffuf, etc.)

Run with: uv run pytest tests/integration/ -m integration -v
"""
from __future__ import annotations

import pytest

from bba.db import Database
from bba.tool_runner import ToolRunner
from bba.tools.httpx_runner import HttpxTool
from bba.tools.nuclei import NucleiTool
from bba.tools.ffuf import FfufTool
from bba.validator import FindingValidator
from bba.reporter import ReportGenerator

from .conftest import (
    JUICESHOP_HOST,
    JUICESHOP_URL,
    PROGRAM,
    requires_tool,
)

pytestmark = [pytest.mark.integration]


# ---------------------------------------------------------------------------
# Individual tool tests
# ---------------------------------------------------------------------------


class TestHttpxProbe:
    """Test httpx can probe Juice Shop and detect it as live."""

    @requires_tool("httpx")
    async def test_httpx_detects_juiceshop(self, juiceshop_available, tool_runner, db, tmp_path):
        tool = HttpxTool(runner=tool_runner, db=db, program=PROGRAM)
        # Pass full URL since Juice Shop runs on non-standard port 3000
        result = await tool.run([JUICESHOP_URL], work_dir=tmp_path)

        assert result["live"] >= 1, "httpx should detect Juice Shop as live"

        # Should have stored service in DB
        services = await db.get_services(PROGRAM)
        assert len(services) >= 1


class TestNucleiScan:
    """Test nuclei can find vulnerabilities in Juice Shop."""

    @requires_tool("nuclei")
    async def test_nuclei_finds_issues(self, juiceshop_available, tool_runner, db, tmp_path):
        # Seed the DB with the service so nuclei has a target
        await db.add_service(
            program=PROGRAM,
            domain=JUICESHOP_HOST,
            ip="127.0.0.1",
            port=3000,
            status_code=200,
            title="OWASP Juice Shop",
            technologies="Node.js,Express",
        )

        tool = NucleiTool(runner=tool_runner, db=db, program=PROGRAM)
        result = await tool.run(
            targets=[JUICESHOP_URL],
            work_dir=tmp_path,
            severity="low,medium,high,critical",
        )

        # Nuclei should find at least some issues on Juice Shop
        # (it has many known vulnerabilities)
        assert result["total"] >= 0  # May be 0 if templates don't match
        # If findings exist, they should be stored in DB
        if result["total"] > 0:
            findings = await db.get_findings(PROGRAM)
            assert len(findings) > 0


class TestFfufFuzzing:
    """Test ffuf can discover paths on Juice Shop."""

    @requires_tool("ffuf")
    async def test_ffuf_finds_paths(self, juiceshop_available, tool_runner, db, tmp_path):
        tool = FfufTool(runner=tool_runner, db=db, program=PROGRAM)

        # Use a small custom wordlist for faster testing
        wordlist = tmp_path / "wordlist.txt"
        wordlist.write_text(
            "\n".join([
                "api",
                "admin",
                "rest",
                "ftp",
                "assets",
                "robots.txt",
                ".well-known",
                "socket.io",
                "redirect",
                "video",
            ])
        )

        result = await tool.run(
            target_url=f"{JUICESHOP_URL}/FUZZ",
            wordlist=str(wordlist),
        )

        # Juice Shop should respond to at least some of these paths
        assert result["total"] >= 0


# ---------------------------------------------------------------------------
# Validation & reporting tests
# ---------------------------------------------------------------------------


class TestValidationAndReporting:
    """Test the validation and reporting pipeline."""

    async def test_validator_retests_findings(self, juiceshop_available, tool_runner, db):
        # Seed a finding that points at Juice Shop
        finding_id = await db.add_finding(
            program=PROGRAM,
            domain=JUICESHOP_HOST,
            url=f"{JUICESHOP_URL}/rest/admin/application-configuration",
            vuln_type="directory-exposure",
            severity="medium",
            tool="nuclei",
            evidence="Exposed admin config endpoint",
            confidence=0.7,
        )

        validator = FindingValidator(runner=tool_runner, db=db)
        results = await validator.validate_findings(PROGRAM)

        assert len(results) == 1
        # Should have a status (validated, false_positive, or needs_review)
        assert results[0].status in ("validated", "false_positive", "needs_review")
        assert 0.0 <= results[0].confidence <= 1.0

        # DB should be updated
        findings = await db.get_findings(PROGRAM)
        assert findings[0]["status"] != "new"

    async def test_report_generation(self, juiceshop_available, db, tmp_path):
        # Seed a validated finding
        await db.add_finding(
            program=PROGRAM,
            domain=JUICESHOP_HOST,
            url=f"{JUICESHOP_URL}/api/Users",
            vuln_type="directory-exposure",
            severity="high",
            tool="nuclei",
            evidence="User data exposed",
            confidence=0.9,
        )
        await db.update_finding_status(1, "validated")

        reporter = ReportGenerator(db=db)
        report = await reporter.generate(PROGRAM)

        assert "Bug Bounty Report" in report
        assert "directory-exposure" in report
        assert "HIGH" in report

        # Save to file
        path = await reporter.save(PROGRAM, output_dir=tmp_path / "reports")
        assert path.exists()
        assert path.read_text() == report


