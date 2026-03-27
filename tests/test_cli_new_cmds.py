import pytest
from unittest.mock import patch, AsyncMock
import argparse


class TestUpdateFindingWithReason:
    async def test_passes_reason_to_db(self):
        from bba.cli.db_cmds import cmd_db_update_finding
        mock_db = AsyncMock()
        mock_db.update_finding_status = AsyncMock()
        mock_db.close = AsyncMock()
        args = argparse.Namespace(finding_id=1, status="validated", reason="confirmed XSS")
        with patch("bba.cli._get_db", return_value=mock_db):
            await cmd_db_update_finding(args)
        mock_db.update_finding_status.assert_called_once_with(1, "validated", reason="confirmed XSS")

    async def test_reason_defaults_to_none(self):
        from bba.cli.db_cmds import cmd_db_update_finding
        mock_db = AsyncMock()
        mock_db.update_finding_status = AsyncMock()
        mock_db.close = AsyncMock()
        args = argparse.Namespace(finding_id=1, status="false_positive", reason=None)
        with patch("bba.cli._get_db", return_value=mock_db):
            await cmd_db_update_finding(args)
        mock_db.update_finding_status.assert_called_once_with(1, "false_positive", reason=None)


class TestParserRegistration:
    def test_update_finding_has_reason_flag(self):
        from bba.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["db", "update-finding", "1", "--status", "validated", "--reason", "test reason"])
        assert args.reason == "test reason"

    def test_update_finding_reason_defaults_none(self):
        from bba.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["db", "update-finding", "1", "--status", "validated"])
        assert args.reason is None

    def test_set_phase_output_parser(self):
        from bba.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["db", "set-phase-output", "--program", "prog", "--phase", "recon", "--key", "tech", "--value", '{"a":1}'])
        assert args.phase == "recon"
        assert args.key == "tech"

    def test_get_phase_output_parser(self):
        from bba.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["db", "get-phase-output", "--program", "prog", "--phase", "recon", "--key", "tech"])
        assert args.key == "tech"

    def test_coverage_parser(self):
        from bba.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["db", "coverage", "--program", "prog"])
        assert args.program == "prog"
