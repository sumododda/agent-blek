import pytest
from bba.db import Database
from bba.scan_state import ScanState, ALL_PHASES


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestValidationReason:
    async def test_update_finding_with_reason(self, db):
        fid = await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "t", "ev", 0.9)
        await db.update_finding_status(fid, "validated", reason="XSS confirmed in Chrome")
        findings = await db.get_findings("prog")
        assert findings[0]["validation_reason"] == "XSS confirmed in Chrome"
        assert findings[0]["status"] == "validated"

    async def test_update_finding_without_reason(self, db):
        fid = await db.add_finding("prog", "a.com", "https://a.com/x", "xss", "high", "t", "ev", 0.9)
        await db.update_finding_status(fid, "false_positive")
        findings = await db.get_findings("prog")
        assert findings[0]["validation_reason"] is None
        assert findings[0]["status"] == "false_positive"


class TestPhaseOutputs:
    async def test_set_and_get_phase_output(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("prog", {})
        await state.set_phase_output(run_id, "recon", "technology_profile", '{"frameworks":["Express.js"]}')
        value = await state.get_phase_output(run_id, "recon", "technology_profile")
        assert value == '{"frameworks":["Express.js"]}'

    async def test_get_missing_phase_output(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("prog", {})
        value = await state.get_phase_output(run_id, "recon", "nonexistent")
        assert value is None

    async def test_upsert_phase_output(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("prog", {})
        await state.set_phase_output(run_id, "recon", "live_count", "10")
        await state.set_phase_output(run_id, "recon", "live_count", "42")
        value = await state.get_phase_output(run_id, "recon", "live_count")
        assert value == "42"

    async def test_get_all_phase_outputs(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("prog", {})
        await state.set_phase_output(run_id, "recon", "key1", "val1")
        await state.set_phase_output(run_id, "recon", "key2", "val2")
        outputs = await state.get_all_phase_outputs(run_id, "recon")
        assert outputs == {"key1": "val1", "key2": "val2"}


class TestCoverage:
    async def test_add_and_get_coverage(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("prog", {})
        await db.add_coverage(run_id, "prog", "https://a.com/api", "scanning", "xss", True)
        await db.add_coverage(run_id, "prog", "https://a.com/login", "scanning", "sqli", False, "no query params")
        summary = await db.get_coverage_summary("prog")
        assert len(summary) > 0

    async def test_coverage_dedup(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("prog", {})
        await db.add_coverage(run_id, "prog", "https://a.com/x", "scanning", "xss", True)
        await db.add_coverage(run_id, "prog", "https://a.com/x", "scanning", "xss", True)
        # Should not raise — INSERT OR IGNORE


class TestExpandedPhases:
    def test_all_phases_includes_analysis_phases(self):
        assert "recon-analysis" in ALL_PHASES
        assert "scan-analysis" in ALL_PHASES
        assert "vuln-analysis" in ALL_PHASES
        assert "validation-analysis" in ALL_PHASES
        assert "diff-notify" in ALL_PHASES
        assert "precheck" in ALL_PHASES
        assert "initialize" in ALL_PHASES

    def test_all_phases_count(self):
        assert len(ALL_PHASES) == 16

    async def test_remaining_phases_with_new_list(self, db):
        state = ScanState(db)
        await state.initialize()
        run_id = await state.create_run("prog", {})
        await state.update_phase(run_id, "precheck", "completed")
        await state.update_phase(run_id, "initialize", "completed")
        await state.update_phase(run_id, "recon", "completed")
        remaining = await state.get_remaining_phases(run_id)
        assert "precheck" not in remaining
        assert "recon" not in remaining
        assert "recon-analysis" in remaining
