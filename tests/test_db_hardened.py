import json
import pytest
from bba.db import Database


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestFindingDedup:
    async def test_duplicate_finding_merges_evidence(self, db):
        await db.add_finding("prog", "example.com", "https://example.com/vuln",
                             "xss", "high", "dalfox", "payload1", 0.8)
        await db.add_finding("prog", "example.com", "https://example.com/vuln",
                             "xss", "high", "xsstrike", "payload2", 0.85)
        findings = await db.get_findings("prog")
        assert len(findings) == 1
        assert "payload1" in findings[0]["evidence"]
        assert "payload2" in findings[0]["evidence"]
        assert findings[0]["confidence"] == 0.85

    async def test_different_vuln_types_not_deduped(self, db):
        await db.add_finding("prog", "example.com", "https://example.com/vuln",
                             "xss", "high", "dalfox", "ev1", 0.8)
        await db.add_finding("prog", "example.com", "https://example.com/vuln",
                             "sqli", "critical", "sqlmap", "ev2", 0.9)
        findings = await db.get_findings("prog")
        assert len(findings) == 2

    async def test_same_tool_not_duplicated_in_tool_field(self, db):
        await db.add_finding("prog", "example.com", "https://example.com/x",
                             "xss", "high", "dalfox", "ev1", 0.8)
        await db.add_finding("prog", "example.com", "https://example.com/x",
                             "xss", "high", "dalfox", "ev2", 0.9)
        findings = await db.get_findings("prog")
        assert findings[0]["tool"] == "dalfox"  # Not "dalfox,dalfox"

    async def test_dedup_keeps_higher_confidence(self, db):
        await db.add_finding("prog", "example.com", "https://example.com/x",
                             "xss", "high", "dalfox", "ev1", 0.95)
        await db.add_finding("prog", "example.com", "https://example.com/x",
                             "xss", "high", "xsstrike", "ev2", 0.7)
        findings = await db.get_findings("prog")
        assert findings[0]["confidence"] == 0.95

    async def test_dedup_appends_different_tools(self, db):
        await db.add_finding("prog", "example.com", "https://example.com/x",
                             "xss", "high", "dalfox", "ev1", 0.8)
        await db.add_finding("prog", "example.com", "https://example.com/x",
                             "xss", "high", "nuclei", "ev2", 0.85)
        findings = await db.get_findings("prog")
        assert "dalfox" in findings[0]["tool"]
        assert "nuclei" in findings[0]["tool"]


class TestExport:
    async def test_export_findings_json(self, db):
        await db.add_finding("prog", "example.com", "https://example.com/x",
                             "xss", "high", "dalfox", "evidence", 0.9)
        data = await db.export_findings("prog", fmt="json")
        assert isinstance(data, str)
        parsed = json.loads(data)
        assert len(parsed) == 1
        assert parsed[0]["vuln_type"] == "xss"

    async def test_export_findings_csv(self, db):
        await db.add_finding("prog", "example.com", "https://example.com/x",
                             "xss", "high", "dalfox", "evidence", 0.9)
        data = await db.export_findings("prog", fmt="csv")
        assert "xss" in data
        assert "dalfox" in data

    async def test_export_empty_json(self, db):
        data = await db.export_findings("empty-prog", fmt="json")
        assert json.loads(data) == []

    async def test_export_empty_csv(self, db):
        data = await db.export_findings("empty-prog", fmt="csv")
        assert data == ""

    async def test_export_unsupported_format_raises(self, db):
        with pytest.raises(ValueError, match="Unsupported format"):
            await db.export_findings("prog", fmt="xml")


class TestFindingStats:
    async def test_severity_distribution(self, db):
        await db.add_finding("prog", "a.com", "https://a.com/1", "xss", "high", "t", "e", 0.9)
        await db.add_finding("prog", "b.com", "https://b.com/2", "sqli", "critical", "t", "e", 0.9)
        stats = await db.get_finding_stats("prog")
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_tool"]["t"] == 2
        assert stats["total"] == 2

    async def test_empty_stats(self, db):
        stats = await db.get_finding_stats("empty-prog")
        assert stats["total"] == 0
        assert stats["by_severity"] == {}
        assert stats["by_tool"] == {}

    async def test_multiple_tools_counted(self, db):
        await db.add_finding("prog", "a.com", "https://a.com/1", "xss", "high", "dalfox", "e", 0.9)
        await db.add_finding("prog", "b.com", "https://b.com/2", "sqli", "critical", "sqlmap", "e", 0.9)
        await db.add_finding("prog", "c.com", "https://c.com/3", "xss", "high", "nuclei", "e", 0.8)
        stats = await db.get_finding_stats("prog")
        assert stats["by_tool"]["dalfox"] == 1
        assert stats["by_tool"]["sqlmap"] == 1
        assert stats["by_tool"]["nuclei"] == 1
        assert stats["total"] == 3
