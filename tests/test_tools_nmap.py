import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.nmap_runner import NmapTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

NMAP_XML_OUTPUT = """<?xml version="1.0"?>
<nmaprun><host><address addr="1.2.3.4" addrtype="ipv4"/><hostnames><hostname name="example.com"/></hostnames><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24"/></port><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24"/></port></ports></host></nmaprun>"""

@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))

@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(default_rps=100), sanitizer=Sanitizer(), output_dir=tmp_path / "output")

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()

class TestNmapTool:
    def test_builds_command(self, runner, db):
        tool = NmapTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("example.com", "80,443")
        assert "nmap" in cmd
        assert "-sV" in cmd
        assert "-p" in cmd
        assert "80,443" in cmd
        assert "example.com" in cmd
        assert "-oX" in cmd

    def test_parses_xml_output(self, runner, db):
        tool = NmapTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(NMAP_XML_OUTPUT)
        assert len(results) == 2
        assert results[0]["ip"] == "1.2.3.4"
        assert results[0]["hostname"] == "example.com"
        assert results[0]["port"] == 80
        assert results[0]["service"] == "http"
        assert "nginx" in results[0]["version"]
        assert results[1]["port"] == 443

    def test_parses_empty_output(self, runner, db):
        tool = NmapTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_invalid_xml(self, runner, db):
        tool = NmapTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("not xml at all")
        assert results == []

    def test_skips_closed_ports(self, runner, db):
        tool = NmapTool(runner=runner, db=db, program="test-corp")
        xml = """<?xml version="1.0"?>
<nmaprun><host><address addr="1.2.3.4" addrtype="ipv4"/><hostnames><hostname name="example.com"/></hostnames><ports><port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port></ports></host></nmaprun>"""
        results = tool.parse_output(xml)
        assert len(results) == 0

    async def test_run_stores_in_db(self, runner, db):
        tool = NmapTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=NMAP_XML_OUTPUT, raw_file=Path("/tmp/test.xml"))
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com", "80,443")
        ports = await db.get_ports("test-corp")
        assert len(ports) == 2
        assert summary["total"] == 2

    async def test_run_handles_failure(self, runner, db):
        tool = NmapTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="permission denied")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com", "80,443")
        assert summary["total"] == 0
        assert summary["error"] == "permission denied"
