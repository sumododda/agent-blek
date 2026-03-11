import pytest
from unittest.mock import patch, AsyncMock
from bba.notifier import Notifier
from bba.db import Database


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestNotifier:
    @pytest.mark.asyncio
    async def test_notify_new_findings(self, db, tmp_path):
        notifier = Notifier(db=db, provider_config=str(tmp_path / "notify.yaml"))
        await db.add_finding("prog", "example.com", "https://example.com/x",
                             "xss", "high", "dalfox", "evidence", 0.9)
        with patch.object(notifier, "_send_message", new_callable=AsyncMock) as mock_send:
            await notifier.notify_findings("prog", severity_threshold="medium")
            mock_send.assert_called_once()
            call_msg = mock_send.call_args[0][0]
            assert "xss" in call_msg.lower()

    @pytest.mark.asyncio
    async def test_severity_threshold_filters(self, db, tmp_path):
        notifier = Notifier(db=db, provider_config=str(tmp_path / "notify.yaml"))
        await db.add_finding("prog", "example.com", "https://example.com/x",
                             "info-disclosure", "low", "nikto", "evidence", 0.5)
        with patch.object(notifier, "_send_message", new_callable=AsyncMock) as mock_send:
            await notifier.notify_findings("prog", severity_threshold="high")
            mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_notify_diff(self, db, tmp_path):
        notifier = Notifier(db=db, provider_config=str(tmp_path / "notify.yaml"))
        diff = {"added": ["new.example.com"], "removed": [], "unchanged": 5}
        with patch.object(notifier, "_send_message", new_callable=AsyncMock) as mock_send:
            await notifier.notify_diff("prog", "subdomains", diff)
            mock_send.assert_called_once()
            call_msg = mock_send.call_args[0][0]
            assert "new.example.com" in call_msg
