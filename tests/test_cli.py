import json
import pytest
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock

from bba.cli import build_parser, main, _load_scope, _make_runner, _output


class TestBuildParser:
    def test_recon_subfinder(self):
        parser = build_parser()
        args = parser.parse_args(["recon", "subfinder", "example.com", "--program", "test"])
        assert args.command == "recon"
        assert args.tool == "subfinder"
        assert args.domain == "example.com"
        assert args.program == "test"

    def test_recon_httpx(self):
        parser = build_parser()
        args = parser.parse_args(["recon", "httpx", "targets.txt", "--program", "test"])
        assert args.tool == "httpx"
        assert args.targets == "targets.txt"

    def test_recon_katana(self):
        parser = build_parser()
        args = parser.parse_args(["recon", "katana", "urls.txt", "--program", "test"])
        assert args.tool == "katana"
        assert args.targets == "urls.txt"

    def test_recon_gau(self):
        parser = build_parser()
        args = parser.parse_args(["recon", "gau", "example.com", "--program", "test"])
        assert args.tool == "gau"
        assert args.domain == "example.com"

    def test_scan_nuclei(self):
        parser = build_parser()
        args = parser.parse_args([
            "scan", "nuclei", "targets.txt", "--program", "test",
            "--severity", "critical", "--tags", "cve", "--rate-limit", "50",
        ])
        assert args.tool == "nuclei"
        assert args.targets == "targets.txt"
        assert args.severity == "critical"
        assert args.tags == "cve"
        assert args.rate_limit == 50

    def test_scan_nuclei_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "nuclei", "targets.txt", "--program", "test"])
        assert args.severity is None
        assert args.tags is None
        assert args.rate_limit is None

    def test_scan_ffuf(self):
        parser = build_parser()
        args = parser.parse_args([
            "scan", "ffuf", "http://example.com/FUZZ", "--program", "test",
            "--wordlist", "/path/to/wordlist.txt",
        ])
        assert args.tool == "ffuf"
        assert args.url == "http://example.com/FUZZ"
        assert args.wordlist == "/path/to/wordlist.txt"

    def test_scan_sqlmap(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "sqlmap", "http://example.com/?id=1", "--program", "test"])
        assert args.tool == "sqlmap"
        assert args.url == "http://example.com/?id=1"

    def test_scan_dalfox(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "dalfox", "http://example.com/search", "--program", "test"])
        assert args.tool == "dalfox"
        assert args.url == "http://example.com/search"

    def test_db_subdomains(self):
        parser = build_parser()
        args = parser.parse_args(["db", "subdomains", "--program", "test"])
        assert args.command == "db"
        assert args.query == "subdomains"

    def test_db_services(self):
        parser = build_parser()
        args = parser.parse_args(["db", "services", "--program", "test"])
        assert args.query == "services"

    def test_db_findings_with_filters(self):
        parser = build_parser()
        args = parser.parse_args([
            "db", "findings", "--program", "test",
            "--severity", "high", "--status", "new",
        ])
        assert args.query == "findings"
        assert args.severity == "high"
        assert args.status == "new"

    def test_db_findings_no_filters(self):
        parser = build_parser()
        args = parser.parse_args(["db", "findings", "--program", "test"])
        assert args.severity is None
        assert args.status is None

    def test_db_summary(self):
        parser = build_parser()
        args = parser.parse_args(["db", "summary", "--program", "test"])
        assert args.query == "summary"

    def test_db_add_finding(self):
        parser = build_parser()
        args = parser.parse_args([
            "db", "add-finding", "--program", "test",
            "--domain", "example.com",
            "--url", "http://example.com/vuln",
            "--vuln-type", "xss",
            "--severity-level", "high",
            "--tool", "manual",
            "--evidence", "alert fires",
            "--confidence", "0.9",
        ])
        assert args.query == "add-finding"
        assert args.domain == "example.com"
        assert args.vuln_type == "xss"
        assert args.confidence == 0.9

    def test_db_add_finding_default_confidence(self):
        parser = build_parser()
        args = parser.parse_args([
            "db", "add-finding", "--program", "test",
            "--domain", "example.com", "--url", "http://example.com",
            "--vuln-type", "xss", "--severity-level", "high",
            "--tool", "manual", "--evidence", "test",
        ])
        assert args.confidence == 0.5

    def test_db_update_finding(self):
        parser = build_parser()
        args = parser.parse_args(["db", "update-finding", "42", "--status", "validated"])
        assert args.finding_id == 42
        assert args.status == "validated"

    def test_db_update_finding_status_choices(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["db", "update-finding", "1", "--status", "invalid"])

    def test_report(self):
        parser = build_parser()
        args = parser.parse_args(["report", "--program", "test"])
        assert args.command == "report"
        assert args.program == "test"

    def test_missing_program_fails(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["recon", "subfinder", "example.com"])

    def test_no_command_fails(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])


class TestLoadScope:
    def test_load_scope_missing_file(self, tmp_path):
        with patch("bba.cli.PROGRAMS_DIR", tmp_path):
            with pytest.raises(SystemExit):
                _load_scope("nonexistent")

    def test_load_scope_valid(self, tmp_path):
        scope_file = tmp_path / "test.yaml"
        scope_file.write_text(
            "program: test\nin_scope:\n  domains:\n    - '*.example.com'\n"
        )
        with patch("bba.cli.PROGRAMS_DIR", tmp_path):
            config = _load_scope("test")
        assert config.program == "test"
        assert "*.example.com" in config.in_scope_domains


class TestOutput:
    def test_output_dict(self, capsys):
        _output({"key": "value", "count": 42})
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["key"] == "value"
        assert data["count"] == 42

    def test_output_list(self, capsys):
        _output([{"a": 1}, {"b": 2}])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 2


class TestDbCommands:
    @pytest.fixture
    def mock_db(self):
        db = AsyncMock()
        db.initialize = AsyncMock()
        db.close = AsyncMock()
        return db

    async def test_db_summary(self, mock_db, capsys):
        mock_db.get_program_summary = AsyncMock(return_value={"subdomains": 5, "services": 3, "findings": 2})
        with patch("bba.cli._get_db", return_value=mock_db):
            from bba.cli import cmd_db_summary
            args = MagicMock()
            args.program = "test"
            await cmd_db_summary(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["subdomains"] == 5

    async def test_db_findings(self, mock_db, capsys):
        mock_db.get_findings = AsyncMock(return_value=[
            {"id": 1, "vuln_type": "xss", "severity": "high"},
        ])
        with patch("bba.cli._get_db", return_value=mock_db):
            from bba.cli import cmd_db_findings
            args = MagicMock()
            args.program = "test"
            args.severity = "high"
            args.status = None
            await cmd_db_findings(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["vuln_type"] == "xss"

    async def test_db_add_finding(self, mock_db, capsys):
        mock_db.add_finding = AsyncMock(return_value=7)
        with patch("bba.cli._get_db", return_value=mock_db):
            from bba.cli import cmd_db_add_finding
            args = MagicMock()
            args.program = "test"
            args.domain = "example.com"
            args.url = "http://example.com/vuln"
            args.vuln_type = "xss"
            args.severity_level = "high"
            args.tool = "manual"
            args.evidence = "test"
            args.confidence = 0.9
            await cmd_db_add_finding(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["id"] == 7
        assert data["status"] == "created"

    async def test_db_update_finding(self, mock_db, capsys):
        mock_db.update_finding_status = AsyncMock()
        with patch("bba.cli._get_db", return_value=mock_db):
            from bba.cli import cmd_db_update_finding
            args = MagicMock()
            args.finding_id = 1
            args.status = "validated"
            await cmd_db_update_finding(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["updated"] is True
        assert data["status"] == "validated"
