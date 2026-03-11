import pytest
from pathlib import Path
from bba.reporter import ReportGenerator
from bba.db import Database

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()

class TestReportGenerator:
    async def test_generates_markdown_report(self, db, tmp_path):
        await db.add_finding("test-corp", "shop.example.com", "https://shop.example.com/search?q=xss", "xss", "high", "dalfox", "reflected XSS via q param", 0.9)
        await db.update_finding_status(1, "validated")
        await db.add_finding("test-corp", "api.example.com", "https://api.example.com/login", "sql-injection", "critical", "sqlmap", "blind SQLi in login", 0.95)
        await db.update_finding_status(2, "validated")
        reporter = ReportGenerator(db=db)
        report = await reporter.generate("test-corp")
        assert "# Bug Bounty Report: test-corp" in report
        assert "critical" in report.lower()
        assert "shop.example.com" in report
        assert "sql-injection" in report

    async def test_report_includes_summary_stats(self, db):
        await db.add_finding("p", "a.com", "https://a.com", "xss", "high", "t", "", 0.9)
        await db.update_finding_status(1, "validated")
        await db.add_finding("p", "b.com", "https://b.com", "info", "low", "t", "", 0.3)
        await db.update_finding_status(2, "false_positive")
        reporter = ReportGenerator(db=db)
        report = await reporter.generate("p")
        assert "validated" in report.lower()
        assert "1" in report

    async def test_report_excludes_false_positives(self, db):
        await db.add_finding("p", "a.com", "https://a.com", "xss", "high", "t", "real", 0.9)
        await db.update_finding_status(1, "validated")
        await db.add_finding("p", "b.com", "https://b.com", "xss", "high", "t", "fake", 0.1)
        await db.update_finding_status(2, "false_positive")
        reporter = ReportGenerator(db=db)
        report = await reporter.generate("p")
        assert "real" in report
        assert "fake" not in report

    async def test_report_orders_by_severity(self, db):
        await db.add_finding("p", "a.com", "https://a.com", "info", "low", "t", "low-sev", 0.5)
        await db.update_finding_status(1, "validated")
        await db.add_finding("p", "b.com", "https://b.com", "rce", "critical", "t", "crit-sev", 0.95)
        await db.update_finding_status(2, "validated")
        reporter = ReportGenerator(db=db)
        report = await reporter.generate("p")
        crit_pos = report.find("crit-sev")
        low_pos = report.find("low-sev")
        assert crit_pos < low_pos

    async def test_saves_report_to_file(self, db, tmp_path):
        await db.add_finding("p", "a.com", "https://a.com", "xss", "high", "t", "", 0.9)
        await db.update_finding_status(1, "validated")
        reporter = ReportGenerator(db=db)
        path = await reporter.save("p", output_dir=tmp_path)
        assert path.exists() and path.suffix == ".md"
        content = path.read_text()
        assert "Bug Bounty Report" in content

    async def test_empty_report_when_no_findings(self, db):
        reporter = ReportGenerator(db=db)
        report = await reporter.generate("empty-program")
        assert "no validated findings" in report.lower()
