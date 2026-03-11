import pytest
from pathlib import Path
from bba.db import Database


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestDatabaseInit:
    async def test_creates_tables(self, db):
        tables = await db.list_tables()
        assert "subdomains" in tables
        assert "services" in tables
        assert "findings" in tables
        assert "audit_log" in tables

    async def test_initialize_idempotent(self, db):
        await db.initialize()
        tables = await db.list_tables()
        assert "subdomains" in tables


class TestSubdomains:
    async def test_add_subdomain(self, db):
        await db.add_subdomain("example-corp", "shop.example.com", "subfinder")
        subs = await db.get_subdomains("example-corp")
        assert len(subs) == 1
        assert subs[0]["domain"] == "shop.example.com"

    async def test_add_duplicate_subdomain_ignored(self, db):
        await db.add_subdomain("example-corp", "shop.example.com", "subfinder")
        await db.add_subdomain("example-corp", "shop.example.com", "amass")
        subs = await db.get_subdomains("example-corp")
        assert len(subs) == 1

    async def test_add_bulk_subdomains(self, db):
        domains = [f"sub{i}.example.com" for i in range(100)]
        count = await db.add_subdomains_bulk("example-corp", domains, "subfinder")
        assert count == 100
        subs = await db.get_subdomains("example-corp")
        assert len(subs) == 100


class TestServices:
    async def test_add_service(self, db):
        await db.add_service(
            program="example-corp",
            domain="shop.example.com",
            ip="1.2.3.4",
            port=443,
            status_code=200,
            title="Shop",
            technologies="nginx,php",
        )
        services = await db.get_services("example-corp")
        assert len(services) == 1
        assert services[0]["title"] == "Shop"

    async def test_service_upsert(self, db):
        await db.add_service("example-corp", "a.example.com", "1.2.3.4", 443, 200, "Old", "")
        await db.add_service("example-corp", "a.example.com", "1.2.3.4", 443, 200, "New", "")
        services = await db.get_services("example-corp")
        assert len(services) == 1
        assert services[0]["title"] == "New"


class TestFindings:
    async def test_add_finding(self, db):
        fid = await db.add_finding(
            program="example-corp",
            domain="shop.example.com",
            url="https://shop.example.com/search?q=test",
            vuln_type="xss",
            severity="high",
            tool="dalfox",
            evidence="reflected <script>alert(1)</script>",
            confidence=0.9,
        )
        assert fid is not None

    async def test_get_findings_by_severity(self, db):
        await db.add_finding("p", "a.com", "https://a.com", "xss", "high", "t", "", 0.9)
        await db.add_finding("p", "b.com", "https://b.com", "info", "low", "t", "", 0.5)
        highs = await db.get_findings("p", severity="high")
        assert len(highs) == 1

    async def test_get_findings_by_status(self, db):
        fid = await db.add_finding("p", "a.com", "https://a.com", "xss", "high", "t", "", 0.9)
        await db.update_finding_status(fid, "validated")
        validated = await db.get_findings("p", status="validated")
        assert len(validated) == 1


class TestAuditLog:
    async def test_log_action(self, db):
        await db.log_action("scan", "nuclei", "shop.example.com", '{"templates": 500}')
        logs = await db.get_audit_log(limit=10)
        assert len(logs) == 1
        assert logs[0]["action"] == "scan"

    async def test_audit_log_ordered_by_time(self, db):
        await db.log_action("recon", "subfinder", "example.com", "")
        await db.log_action("scan", "nuclei", "example.com", "")
        logs = await db.get_audit_log(limit=10)
        assert logs[0]["tool"] == "nuclei"


class TestSummary:
    async def test_get_program_summary(self, db):
        await db.add_subdomain("p", "a.example.com", "subfinder")
        await db.add_subdomain("p", "b.example.com", "subfinder")
        await db.add_service("p", "a.example.com", "1.2.3.4", 443, 200, "A", "")
        await db.add_finding("p", "a.example.com", "https://a.example.com", "xss", "high", "t", "", 0.9)
        summary = await db.get_program_summary("p")
        assert summary["subdomains"] == 2
        assert summary["services"] == 1
        assert summary["findings"] == 1
