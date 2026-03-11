import pytest
from bba.scan_state import ScanState
from bba.db import Database


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestScanState:
    @pytest.mark.asyncio
    async def test_create_scan_run(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("test-prog", {"phases": "all"})
        assert run_id > 0

    @pytest.mark.asyncio
    async def test_update_phase(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("test-prog", {})
        await state.update_phase(run_id, "recon", "completed")
        phases = await state.get_completed_phases(run_id)
        assert "recon" in phases

    @pytest.mark.asyncio
    async def test_resume_skips_completed(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("test-prog", {})
        await state.update_phase(run_id, "recon", "completed")
        await state.update_phase(run_id, "infrastructure", "completed")
        remaining = await state.get_remaining_phases(run_id)
        assert "recon" not in remaining
        assert "infrastructure" not in remaining
        assert "scanning" in remaining

    @pytest.mark.asyncio
    async def test_mark_failed_allows_resume(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("test-prog", {})
        await state.update_phase(run_id, "scanning", "failed", error="timeout")
        status = await state.get_phase_status(run_id, "scanning")
        assert status["status"] == "failed"
        assert status["error"] == "timeout"

    @pytest.mark.asyncio
    async def test_get_latest_run(self, db):
        state = ScanState(db)
        await state.initialize()
        await state.create_run("test-prog", {"v": 1})
        run2 = await state.create_run("test-prog", {"v": 2})
        latest = await state.get_latest_run("test-prog")
        assert latest["id"] == run2

    @pytest.mark.asyncio
    async def test_diff_finds_new_subdomains(self, db):
        state = ScanState(db)
        await state.initialize()
        run1 = await state.create_run("test-prog", {})
        await state.record_snapshot(run1, "subdomains", ["a.example.com", "b.example.com"])
        await state.update_phase(run1, "recon", "completed")

        run2 = await state.create_run("test-prog", {})
        await state.record_snapshot(run2, "subdomains", ["a.example.com", "b.example.com", "c.example.com"])
        diff = await state.diff_snapshots(run1, run2, "subdomains")
        assert diff["added"] == ["c.example.com"]
        assert diff["removed"] == []

    @pytest.mark.asyncio
    async def test_diff_detects_removed(self, db):
        state = ScanState(db)
        await state.initialize()
        run1 = await state.create_run("test-prog", {})
        await state.record_snapshot(run1, "subdomains", ["a.example.com", "b.example.com"])
        run2 = await state.create_run("test-prog", {})
        await state.record_snapshot(run2, "subdomains", ["a.example.com"])
        diff = await state.diff_snapshots(run1, run2, "subdomains")
        assert diff["removed"] == ["b.example.com"]
