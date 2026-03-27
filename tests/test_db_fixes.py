import pytest
from bba.db import Database


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestSecretsDedup:
    async def test_duplicate_secret_ignored(self, db):
        await db.add_secret("prog", "api_key", "AKIA1234", "https://x.com", "", "trufflehog", 0.9)
        await db.add_secret("prog", "api_key", "AKIA1234", "https://x.com", "", "gitleaks", 0.8)
        secrets = await db.get_secrets("prog")
        assert len(secrets) == 1

    async def test_different_secrets_not_deduped(self, db):
        await db.add_secret("prog", "api_key", "AKIA1234", "", "", "trufflehog", 0.9)
        await db.add_secret("prog", "api_key", "AKIA5678", "", "", "trufflehog", 0.9)
        secrets = await db.get_secrets("prog")
        assert len(secrets) == 2


class TestAuditLogIndexes:
    async def test_audit_log_indexes_exist(self, db):
        cursor = await db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='audit_log'"
        )
        rows = await cursor.fetchall()
        index_names = [r[0] for r in rows]
        assert "idx_audit_log_tool" in index_names
        assert "idx_audit_log_timestamp" in index_names
        assert "idx_audit_log_target" in index_names


class TestToolSubstringCollision:
    async def test_sql_not_confused_with_sqlmap(self, db):
        await db.add_finding("prog", "a.com", "https://a.com/x", "sqli", "high", "sql", "ev1", 0.7)
        await db.add_finding("prog", "a.com", "https://a.com/x", "sqli", "high", "sqlmap", "ev2", 0.8)
        findings = await db.get_findings("prog")
        assert "sql" in findings[0]["tool"]
        assert "sqlmap" in findings[0]["tool"]

    async def test_exact_tool_not_duplicated(self, db):
        await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "dalfox", "ev1", 0.8)
        await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "dalfox", "ev2", 0.9)
        findings = await db.get_findings("prog")
        assert findings[0]["tool"] == "dalfox"


class TestEvidenceCap:
    async def test_evidence_capped_at_50k(self, db):
        large_evidence = "x" * 49000
        await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "t", large_evidence, 0.8)
        await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "t2", "new_evidence", 0.9)
        findings = await db.get_findings("prog")
        assert "new_evidence" in findings[0]["evidence"]

    async def test_evidence_stops_growing_past_cap(self, db):
        large_evidence = "x" * 51000
        await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "t", large_evidence, 0.8)
        await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "t2", "should_not_appear", 0.9)
        findings = await db.get_findings("prog")
        assert "should_not_appear" not in findings[0]["evidence"]
