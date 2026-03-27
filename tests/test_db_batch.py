import pytest
from bba.db import Database


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestBatchMode:
    async def test_batch_commits_at_end(self, db):
        async with db.batch():
            await db.add_subdomain("prog", "a.example.com", "subfinder")
            await db.add_subdomain("prog", "b.example.com", "subfinder")
        subs = await db.get_subdomains("prog")
        assert len(subs) == 2

    async def test_non_batch_commits_immediately(self, db):
        await db.add_subdomain("prog", "a.example.com", "subfinder")
        subs = await db.get_subdomains("prog")
        assert len(subs) == 1

    async def test_batch_mode_flag(self, db):
        assert db._batch_mode is False
        async with db.batch():
            assert db._batch_mode is True
        assert db._batch_mode is False

    async def test_batch_with_findings(self, db):
        async with db.batch():
            await db.add_finding("prog", "a.com", "https://a.com/1", "xss", "high", "t", "e1", 0.9)
            await db.add_finding("prog", "b.com", "https://b.com/2", "sqli", "critical", "t", "e2", 0.9)
        findings = await db.get_findings("prog")
        assert len(findings) == 2
