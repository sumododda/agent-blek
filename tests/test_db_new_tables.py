import pytest

from bba.db import Database

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()

class TestPortsTable:
    async def test_add_port(self, db):
        await db.add_port("test-corp", "example.com", "1.2.3.4", 80, "tcp", "http", "nginx 1.24", "nmap")
        ports = await db.get_ports("test-corp")
        assert len(ports) == 1
        assert ports[0]["domain"] == "example.com"
        assert ports[0]["ip"] == "1.2.3.4"
        assert ports[0]["port"] == 80
        assert ports[0]["protocol"] == "tcp"
        assert ports[0]["service"] == "http"
        assert ports[0]["version"] == "nginx 1.24"
        assert ports[0]["source"] == "nmap"

    async def test_add_port_duplicate_ignored(self, db):
        await db.add_port("test-corp", "example.com", "1.2.3.4", 80, "tcp", "http", "", "nmap")
        await db.add_port("test-corp", "example.com", "1.2.3.4", 80, "tcp", "http", "", "nmap")
        ports = await db.get_ports("test-corp")
        assert len(ports) == 1

    async def test_add_ports_bulk(self, db):
        port_records = [
            {"domain": "example.com", "ip": "1.2.3.4", "port": 80, "protocol": "tcp", "service": "http", "version": ""},
            {"domain": "example.com", "ip": "1.2.3.4", "port": 443, "protocol": "tcp", "service": "https", "version": ""},
        ]
        count = await db.add_ports_bulk("test-corp", port_records, "naabu")
        assert count == 2
        ports = await db.get_ports("test-corp")
        assert len(ports) == 2

    async def test_get_ports_empty(self, db):
        ports = await db.get_ports("test-corp")
        assert ports == []

    async def test_get_ports_ordered_by_ip_and_port(self, db):
        await db.add_port("test-corp", "b.example.com", "2.2.2.2", 443, "tcp", "", "", "nmap")
        await db.add_port("test-corp", "a.example.com", "1.1.1.1", 80, "tcp", "", "", "nmap")
        await db.add_port("test-corp", "a.example.com", "1.1.1.1", 443, "tcp", "", "", "nmap")
        ports = await db.get_ports("test-corp")
        assert ports[0]["ip"] == "1.1.1.1"
        assert ports[0]["port"] == 80
        assert ports[1]["ip"] == "1.1.1.1"
        assert ports[1]["port"] == 443
        assert ports[2]["ip"] == "2.2.2.2"

class TestUrlsTable:
    async def test_add_url(self, db):
        await db.add_url("test-corp", "https://example.com/admin", "feroxbuster", status_code=200, content_type="text/html")
        urls = await db.get_urls("test-corp")
        assert len(urls) == 1
        assert urls[0]["url"] == "https://example.com/admin"
        assert urls[0]["source"] == "feroxbuster"
        assert urls[0]["status_code"] == 200
        assert urls[0]["content_type"] == "text/html"

    async def test_add_url_duplicate_ignored(self, db):
        await db.add_url("test-corp", "https://example.com/admin", "feroxbuster")
        await db.add_url("test-corp", "https://example.com/admin", "feroxbuster")
        urls = await db.get_urls("test-corp")
        assert len(urls) == 1

    async def test_add_urls_bulk(self, db):
        url_list = ["https://example.com/a", "https://example.com/b"]
        count = await db.add_urls_bulk("test-corp", url_list, "paramspider")
        assert count == 2
        urls = await db.get_urls("test-corp")
        assert len(urls) == 2

    async def test_get_urls_filter_by_source(self, db):
        await db.add_url("test-corp", "https://example.com/a", "feroxbuster")
        await db.add_url("test-corp", "https://example.com/b", "katana")
        urls = await db.get_urls("test-corp", source="feroxbuster")
        assert len(urls) == 1
        assert urls[0]["source"] == "feroxbuster"

    async def test_get_urls_empty(self, db):
        urls = await db.get_urls("test-corp")
        assert urls == []

class TestJsFilesTable:
    async def test_add_js_file(self, db):
        await db.add_js_file("test-corp", "https://example.com/app.js")
        js_files = await db.get_js_files("test-corp")
        assert len(js_files) == 1
        assert js_files[0]["url"] == "https://example.com/app.js"

    async def test_add_js_file_with_source_page(self, db):
        await db.add_js_file("test-corp", "https://example.com/app.js", source_page="https://example.com")
        js_files = await db.get_js_files("test-corp")
        assert js_files[0]["source_page"] == "https://example.com"

    async def test_add_js_file_duplicate_ignored(self, db):
        await db.add_js_file("test-corp", "https://example.com/app.js")
        await db.add_js_file("test-corp", "https://example.com/app.js")
        js_files = await db.get_js_files("test-corp")
        assert len(js_files) == 1

    async def test_update_js_file(self, db):
        await db.add_js_file("test-corp", "https://example.com/app.js")
        await db.update_js_file("test-corp", "https://example.com/app.js", 15, 3)
        js_files = await db.get_js_files("test-corp")
        assert js_files[0]["endpoints_extracted"] == 15
        assert js_files[0]["secrets_found"] == 3
        assert js_files[0]["analyzed_at"] is not None

    async def test_get_js_files_filter_analyzed(self, db):
        await db.add_js_file("test-corp", "https://example.com/app.js")
        await db.add_js_file("test-corp", "https://example.com/vendor.js")
        await db.update_js_file("test-corp", "https://example.com/app.js", 10, 0)
        analyzed = await db.get_js_files("test-corp", analyzed=True)
        assert len(analyzed) == 1
        assert analyzed[0]["url"] == "https://example.com/app.js"
        not_analyzed = await db.get_js_files("test-corp", analyzed=False)
        assert len(not_analyzed) == 1
        assert not_analyzed[0]["url"] == "https://example.com/vendor.js"

    async def test_get_js_files_empty(self, db):
        js_files = await db.get_js_files("test-corp")
        assert js_files == []

class TestSecretsTable:
    async def test_add_secret(self, db):
        await db.add_secret(
            "test-corp", "aws_key", "AKIA1234567890ABCDEF",
            source_url="https://example.com/app.js", source_file=None,
            tool="secretfinder", confidence=0.7,
        )
        secrets = await db.get_secrets("test-corp")
        assert len(secrets) == 1
        assert secrets[0]["secret_type"] == "aws_key"
        assert secrets[0]["value"] == "AKIA1234567890ABCDEF"
        assert secrets[0]["tool"] == "secretfinder"
        assert secrets[0]["confidence"] == 0.7

    async def test_add_secret_with_source_file(self, db):
        await db.add_secret(
            "test-corp", "aws_key", "AKIA****",
            source_url=None, source_file="config.py",
            tool="trufflehog", confidence=0.95,
        )
        secrets = await db.get_secrets("test-corp")
        assert secrets[0]["source_file"] == "config.py"

    async def test_get_secrets_filter_by_status(self, db):
        await db.add_secret(
            "test-corp", "aws_key", "AKIA1234",
            source_url="https://example.com", source_file=None,
            tool="secretfinder", confidence=0.7,
        )
        secrets = await db.get_secrets("test-corp", status="new")
        assert len(secrets) == 1
        secrets = await db.get_secrets("test-corp", status="verified")
        assert len(secrets) == 0

    async def test_get_secrets_empty(self, db):
        secrets = await db.get_secrets("test-corp")
        assert secrets == []

class TestScreenshotsTable:
    async def test_add_screenshot(self, db):
        await db.add_screenshot(
            "test-corp", "https://example.com", "screenshot_1.png",
            status_code=200, title="Example",
        )
        screenshots = await db.get_screenshots("test-corp")
        assert len(screenshots) == 1
        assert screenshots[0]["url"] == "https://example.com"
        assert screenshots[0]["file_path"] == "screenshot_1.png"
        assert screenshots[0]["status_code"] == 200
        assert screenshots[0]["title"] == "Example"

    async def test_add_screenshot_duplicate_ignored(self, db):
        await db.add_screenshot("test-corp", "https://example.com", "ss1.png", 200, "Example")
        await db.add_screenshot("test-corp", "https://example.com", "ss2.png", 200, "Example")
        screenshots = await db.get_screenshots("test-corp")
        assert len(screenshots) == 1

    async def test_get_screenshots_empty(self, db):
        screenshots = await db.get_screenshots("test-corp")
        assert screenshots == []

class TestProgramSummary:
    async def test_get_program_summary_includes_all_tables(self, db):
        await db.add_subdomain("test-corp", "api.example.com", "subfinder")
        await db.add_port("test-corp", "example.com", "1.2.3.4", 80, "tcp", "http", "", "nmap")
        await db.add_url("test-corp", "https://example.com/admin", "feroxbuster")
        await db.add_js_file("test-corp", "https://example.com/app.js")
        await db.add_secret(
            "test-corp", "aws_key", "AKIA1234",
            source_url="https://example.com", source_file=None,
            tool="secretfinder", confidence=0.7,
        )
        await db.add_screenshot("test-corp", "https://example.com", "ss.png", 200, "Example")

        summary = await db.get_program_summary("test-corp")
        assert summary["subdomains"] == 1
        assert summary["ports"] == 1
        assert summary["urls"] == 1
        assert summary["js_files"] == 1
        assert summary["secrets"] == 1
        assert summary["screenshots"] == 1
        assert "services" in summary
        assert "findings" in summary

    async def test_get_program_summary_empty(self, db):
        summary = await db.get_program_summary("test-corp")
        assert summary["subdomains"] == 0
        assert summary["ports"] == 0
        assert summary["urls"] == 0
        assert summary["js_files"] == 0
        assert summary["secrets"] == 0
        assert summary["screenshots"] == 0
