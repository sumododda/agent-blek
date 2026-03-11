"""BBA CLI — agents invoke security tools via this interface.

Usage:
    bba recon subfinder <domain> --program <prog>
    bba recon httpx <targets_file> --program <prog>
    bba recon katana <targets_file> --program <prog>
    bba recon gau <domain> --program <prog>
    bba recon crtsh <domain> --program <prog>
    bba recon amass <domain> --program <prog>
    bba recon dnsx <targets> --program <prog>
    bba recon wafw00f <url> --program <prog>
    bba recon naabu <targets> --program <prog> [--ports top-1000] [--scan-type connect]
    bba recon nmap <targets> --program <prog> [--ports 80,443]
    bba recon gowitness <targets> --program <prog>
    bba recon hakrevdns <targets> --program <prog>
    bba recon cdncheck <targets> --program <prog>
    bba recon asnmap <domain> --program <prog>
    bba recon tlsx <targets> --program <prog>
    bba recon waymore <domain> --program <prog>
    bba recon graphw00f <url> --program <prog>
    bba recon shodan <query> --program <prog> [--domain]
    bba scan nuclei <targets_file> --program <prog> [--severity] [--tags] [--rate-limit]
    bba scan ffuf <url-with-FUZZ> --program <prog> [--wordlist]
    bba scan sqlmap <url> --program <prog>
    bba scan dalfox <url> --program <prog>
    bba scan feroxbuster <url> --program <prog> [--wordlist] [--depth 3]
    bba scan arjun <url> --program <prog>
    bba scan paramspider <domain> --program <prog>
    bba scan uncover <query> --program <prog> [--engines]
    bba scan s3scanner <bucket> --program <prog>
    bba scan retirejs <path> --program <prog> [--domain]
    bba scan brutespray <nmap_xml> --program <prog> [--domain]
    bba scan nuclei-cve <targets> --program <prog> [--severity] [--rate-limit]
    bba scan nuclei-takeover <targets> --program <prog>
    bba scan nuclei-panels <targets> --program <prog>
    bba scan nuclei-dast <targets> --program <prog> [--rate-limit] [--concurrency]
    bba scan testssl <url> --program <prog>
    bba scan sslyze <target> --program <prog>
    bba scan nikto <url> --program <prog>
    bba scan security-headers <url> --program <prog>
    bba scan crlfuzz <target> --program <prog>
    bba scan sstimap <url> --program <prog>
    bba scan commix <url> --program <prog>
    bba scan ghauri <url> --program <prog> [--level N] [--technique T]
    bba scan nosqli <url> --program <prog>
    bba scan xsstrike <url> --program <prog> [--blind] [--crawl]
    bba scan jwt-tool <token> --program <prog> --domain <domain> [--mode scan|crack] [--wordlist path]
    bba scan ppfuzz <targets> --program <prog>
    bba scan interactsh-generate --program <prog> [--count 10] [--server url]
    bba scan interactsh-poll <session-file> --program <prog> --domain <d>
    bba scan nomore403 <url> --program <prog>
    bba recon uro <targets> --program <prog>
    bba recon qsreplace <targets> --program <prog> --payload <payload>
    bba db subdomains --program <prog>
    bba db services --program <prog>
    bba db findings --program <prog> [--severity] [--status]
    bba db summary --program <prog>
    bba db add-finding --program <prog> ...
    bba db update-finding <id> --status <status>
    bba db ports --program <prog>
    bba db urls --program <prog> [--source]
    bba db js-files --program <prog>
    bba db secrets --program <prog> [--status]
    bba db screenshots --program <prog>
    bba scan notify <message> --program <prog> [--provider-config path]
    bba scan notify-findings --program <prog> [--severity medium]
    bba db scan-history --program <prog>
    bba db scan-status <run_id> --program <prog>
    bba db scan-diff <old_id> <new_id> --category subdomains --program <prog>
    bba scope import-h1 <handle> [--name name] [--output path]
    bba scope import-bc <handle> [--name name] [--output path]
    bba report --program <prog>
    bba wordlist download [--name seclists|assetnote|onelistforall|resolvers|all]
    bba wordlist list
    bba --dry-run <any command>   # Log commands without execution
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from bba.db import Database
from bba.rate_limiter import MultiTargetRateLimiter
from bba.reporter import ReportGenerator
from bba.sanitizer import Sanitizer
from bba.scope import ScopeConfig, ScopeValidator
from bba.tool_runner import ToolRunner

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "db" / "findings.db"
OUTPUT_DIR = DATA_DIR / "output"
PROGRAMS_DIR = DATA_DIR / "programs"
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


def _load_scope(program: str) -> ScopeConfig:
    scope_file = PROGRAMS_DIR / f"{program}.yaml"
    if not scope_file.exists():
        print(json.dumps({"error": f"Scope file not found: {scope_file}"}))
        sys.exit(1)
    return ScopeConfig.from_yaml(scope_file)


def _make_runner(scope: ScopeConfig) -> ToolRunner:
    validator = ScopeValidator(scope)
    rate_limiter = MultiTargetRateLimiter()
    sanitizer = Sanitizer()
    return ToolRunner(
        scope=validator,
        rate_limiter=rate_limiter,
        sanitizer=sanitizer,
        output_dir=OUTPUT_DIR,
    )


async def _get_db() -> Database:
    db = Database(DB_PATH)
    await db.initialize()
    return db


def _output(data: dict | list) -> None:
    print(json.dumps(data, indent=2, default=str))


# --- Recon commands ---

async def cmd_recon_subfinder(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.subfinder import SubfinderTool
        tool = SubfinderTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.domain)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_httpx(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.httpx_runner import HttpxTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            domains = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            domains = [t.strip() for t in args.targets.split(",")]
        tool = HttpxTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(domains, work_dir=work_dir)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_katana(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.katana import KatanaTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = KatanaTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_gau(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.gau import GauTool
        tool = GauTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.domain)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_crtsh(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.crtsh import CrtshTool
        tool = CrtshTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.domain)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_amass(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.amass import AmassTool
        tool = AmassTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.domain)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_dnsx(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.dnsx import DnsxTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = DnsxTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_wafw00f(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.wafw00f import Wafw00fTool
        tool = Wafw00fTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_naabu(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.naabu import NaabuTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = NaabuTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir, ports=args.ports, scan_type=args.scan_type)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_nmap(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.nmap_runner import NmapTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = NmapTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir, ports=args.ports)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_gowitness(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.gowitness import GowitnessTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = GowitnessTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_hakrevdns(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.hakrevdns import HakrevdnsTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = HakrevdnsTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_cdncheck(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.cdncheck import CdncheckTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = CdncheckTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_asnmap(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.asnmap import AsnmapTool
        tool = AsnmapTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.domain)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_tlsx(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.tlsx import TlsxTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = TlsxTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_waymore(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.waymore import WaymoreTool
        tool = WaymoreTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.domain)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_graphw00f(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.graphw00f import Graphw00fTool
        tool = Graphw00fTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_shodan(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.shodan_cli import ShodanTool
        tool = ShodanTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.query, domain=args.domain or args.query)
        _output(result)
    finally:
        await db.close()


# --- Scan commands ---

async def cmd_scan_nuclei(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.nuclei import NucleiTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = NucleiTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "scan"
        work_dir.mkdir(parents=True, exist_ok=True)
        templates = args.templates.split(",") if args.templates else None
        result = await tool.run(
            targets=targets,
            work_dir=work_dir,
            severity=args.severity or "high,critical",
            rate_limit=args.rate_limit or 100,
            tags=args.tags,
            templates=templates,
            dast=args.dast,
            concurrency=args.concurrency,
        )
        _output(result)
    finally:
        await db.close()


async def cmd_scan_ffuf(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.ffuf import FfufTool
        tool = FfufTool(runner=runner, db=db, program=args.program)
        result = await tool.run(
            target_url=args.url,
            wordlist=args.wordlist or DEFAULT_WORDLIST,
        )
        _output(result)
    finally:
        await db.close()


async def cmd_scan_sqlmap(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.sqlmap_runner import SqlmapTool
        tool = SqlmapTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_dalfox(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.dalfox import DalfoxTool
        tool = DalfoxTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_feroxbuster(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.feroxbuster import FeroxbusterTool
        tool = FeroxbusterTool(runner=runner, db=db, program=args.program)
        result = await tool.run(
            target_url=args.url,
            wordlist=args.wordlist or DEFAULT_WORDLIST,
            depth=args.depth,
        )
        _output(result)
    finally:
        await db.close()


async def cmd_scan_arjun(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.arjun import ArjunTool
        tool = ArjunTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_paramspider(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.paramspider import ParamspiderTool
        tool = ParamspiderTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.domain)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_uncover(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.uncover import UncoverTool
        tool = UncoverTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.query, engines=args.engines or "shodan,censys,fofa")
        _output(result)
    finally:
        await db.close()


async def cmd_scan_s3scanner(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.s3scanner import S3ScannerTool
        tool = S3ScannerTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.bucket)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_retirejs(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.retirejs import RetirejsTool
        tool = RetirejsTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.path, domain=args.domain or "")
        _output(result)
    finally:
        await db.close()


async def cmd_scan_brutespray(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.brutespray import BrutesprayTool
        tool = BrutesprayTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.nmap_xml, domain=args.domain or "")
        _output(result)
    finally:
        await db.close()


async def cmd_scan_nuclei_cve(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.nuclei import NucleiTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = NucleiTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "scan"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(
            targets=targets, work_dir=work_dir,
            severity=args.severity or "critical,high",
            rate_limit=args.rate_limit or 100,
            templates=["cves/"],
        )
        _output(result)
    finally:
        await db.close()


async def cmd_scan_nuclei_takeover(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.nuclei import NucleiTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = NucleiTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "scan"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(
            targets=targets, work_dir=work_dir,
            templates=["takeovers/"],
        )
        _output(result)
    finally:
        await db.close()


async def cmd_scan_nuclei_panels(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.nuclei import NucleiTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = NucleiTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "scan"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(
            targets=targets, work_dir=work_dir,
            templates=["exposed-panels/", "misconfiguration/"],
        )
        _output(result)
    finally:
        await db.close()


async def cmd_scan_nuclei_dast(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.nuclei import NucleiTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = NucleiTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "scan"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(
            targets=targets, work_dir=work_dir,
            rate_limit=args.rate_limit or 10,
            dast=True,
            concurrency=args.concurrency or 3,
        )
        _output(result)
    finally:
        await db.close()


async def cmd_scan_testssl(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.testssl import TestsslTool
        tool = TestsslTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_sslyze(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.sslyze import SslyzeTool
        tool = SslyzeTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.target)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_nikto(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.nikto import NiktoTool
        tool = NiktoTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_security_headers(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.security_headers import SecurityHeadersTool
        tool = SecurityHeadersTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _output(result)
    finally:
        await db.close()


# --- Phase 4 scan command handlers ---

async def cmd_scan_crlfuzz(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.crlfuzz import CrlfuzzTool
        tool = CrlfuzzTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.target)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_sstimap(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.sstimap import SstimapTool
        tool = SstimapTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_commix(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.commix import CommixTool
        tool = CommixTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_ghauri(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.ghauri import GhauriTool
        tool = GhauriTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url, level=args.level, technique=args.technique)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_nosqli(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.nosqli import NosqliTool
        tool = NosqliTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_xsstrike(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.xsstrike import XSStrikeTool
        tool = XSStrikeTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url, blind=args.blind, crawl=args.crawl)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_jwt_tool(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.jwt_tool import JwtToolTool
        tool = JwtToolTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.token, domain=args.domain, mode=args.mode, wordlist=args.wordlist)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_ppfuzz(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.ppfuzz import PpfuzzTool
        if Path(args.targets).is_file():
            targets = Path(args.targets).read_text().strip().splitlines()
        else:
            targets = [t.strip() for t in args.targets.split(",") if t.strip()]
        tool = PpfuzzTool(runner=runner, db=db, program=args.program)
        work_dir = Path(f"data/output/ppfuzz")
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir)
        _output(result)
    finally:
        await db.close()


# --- Phase 5A scan command handlers ---

async def cmd_scan_interactsh_generate(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.interactsh import InteractshTool
        tool = InteractshTool(runner=runner, db=db, program=args.program)
        result = await tool.generate_urls(count=args.count, server=args.server)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_interactsh_poll(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.interactsh import InteractshTool
        tool = InteractshTool(runner=runner, db=db, program=args.program)
        result = await tool.poll_interactions(args.session_file, domain=args.domain)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_nomore403(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.nomore403 import Nomore403Tool
        tool = Nomore403Tool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_jsluice_urls(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.jsluice import JsluiceTool
        tool = JsluiceTool(runner=runner, db=db, program=args.program)
        result = await tool.run_urls(args.js_url, domain=args.domain)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_jsluice_secrets(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.jsluice import JsluiceTool
        tool = JsluiceTool(runner=runner, db=db, program=args.program)
        result = await tool.run_secrets(args.js_url, domain=args.domain)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_subzy(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.subzy import SubzyTool
        if Path(args.targets).is_file():
            targets = Path(args.targets).read_text().strip().splitlines()
        else:
            targets = [t.strip() for t in args.targets.split(",") if t.strip()]
        tool = SubzyTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "scan"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_clairvoyance(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.clairvoyance import ClairvoyanceTool
        tool = ClairvoyanceTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url, wordlist=args.wordlist)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_cache_scanner(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.cache_scanner import CacheScannerTool
        tool = CacheScannerTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_cewler(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.cewler import CewlerTool
        tool = CewlerTool(runner=runner, db=db, program=args.program)
        work_dir = OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(args.url, work_dir, depth=args.depth)
        _output(result)
    finally:
        await db.close()


# --- Phase 4 recon command handlers ---

async def cmd_recon_uro(args: argparse.Namespace) -> None:
    scope = _load_scope(args.program)
    runner = _make_runner(scope)
    db = await _get_db()
    try:
        from bba.tools.uro import UroTool
        if Path(args.targets).is_file():
            targets = Path(args.targets).read_text().strip().splitlines()
        else:
            targets = [t.strip() for t in args.targets.split(",") if t.strip()]
        tool = UroTool(runner=runner, db=db, program=args.program)
        work_dir = Path(f"data/output/uro")
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir)
        _output(result)
    finally:
        await db.close()


async def cmd_recon_qsreplace(args: argparse.Namespace) -> None:
    from bba.tools.qsreplace import QsreplaceTool
    tool = QsreplaceTool()
    if Path(args.targets).is_file():
        urls = Path(args.targets).read_text().strip().splitlines()
    else:
        urls = [t.strip() for t in args.targets.split(",") if t.strip()]
    results = tool.batch_replace(urls, args.payload)
    _output({"total": len(results), "urls": results, "payload": args.payload})


# --- Database commands ---

async def cmd_db_subdomains(args: argparse.Namespace) -> None:
    db = await _get_db()
    try:
        rows = await db.get_subdomains(args.program)
        _output(rows)
    finally:
        await db.close()


async def cmd_db_services(args: argparse.Namespace) -> None:
    db = await _get_db()
    try:
        rows = await db.get_services(args.program)
        _output(rows)
    finally:
        await db.close()


async def cmd_db_findings(args: argparse.Namespace) -> None:
    db = await _get_db()
    try:
        rows = await db.get_findings(
            args.program,
            severity=args.severity,
            status=args.status,
        )
        _output(rows)
    finally:
        await db.close()


async def cmd_db_summary(args: argparse.Namespace) -> None:
    db = await _get_db()
    try:
        summary = await db.get_program_summary(args.program)
        _output(summary)
    finally:
        await db.close()


async def cmd_db_add_finding(args: argparse.Namespace) -> None:
    db = await _get_db()
    try:
        finding_id = await db.add_finding(
            program=args.program,
            domain=args.domain,
            url=args.url,
            vuln_type=args.vuln_type,
            severity=args.severity_level,
            tool=args.tool,
            evidence=args.evidence,
            confidence=args.confidence,
        )
        _output({"id": finding_id, "status": "created"})
    finally:
        await db.close()


async def cmd_db_update_finding(args: argparse.Namespace) -> None:
    db = await _get_db()
    try:
        await db.update_finding_status(args.finding_id, args.status)
        _output({"id": args.finding_id, "status": args.status, "updated": True})
    finally:
        await db.close()


async def cmd_db_ports(args: argparse.Namespace) -> None:
    db = await _get_db()
    try:
        rows = await db.get_ports(args.program)
        _output(rows)
    finally:
        await db.close()


async def cmd_db_urls(args: argparse.Namespace) -> None:
    db = await _get_db()
    try:
        rows = await db.get_urls(args.program, source=args.source)
        _output(rows)
    finally:
        await db.close()


async def cmd_db_js_files(args: argparse.Namespace) -> None:
    db = await _get_db()
    try:
        rows = await db.get_js_files(args.program)
        _output(rows)
    finally:
        await db.close()


async def cmd_db_secrets(args: argparse.Namespace) -> None:
    db = await _get_db()
    try:
        rows = await db.get_secrets(args.program, status=args.status)
        _output(rows)
    finally:
        await db.close()


async def cmd_db_screenshots(args: argparse.Namespace) -> None:
    db = await _get_db()
    try:
        rows = await db.get_screenshots(args.program)
        _output(rows)
    finally:
        await db.close()


# --- Scan state commands ---

async def cmd_db_scan_history(args: argparse.Namespace) -> None:
    from bba.scan_state import ScanState
    db = await _get_db()
    try:
        state = ScanState(db)
        await state.initialize()
        cursor = await db._conn.execute(
            "SELECT id, status, started_at, finished_at FROM scan_runs WHERE program = ? ORDER BY id DESC LIMIT 20",
            (args.program,),
        )
        rows = await cursor.fetchall()
        runs = [{"id": r[0], "status": r[1], "started_at": r[2], "finished_at": r[3]} for r in rows]
        _output(runs)
    finally:
        await db.close()


async def cmd_db_scan_status(args: argparse.Namespace) -> None:
    from bba.scan_state import ScanState
    db = await _get_db()
    try:
        state = ScanState(db)
        await state.initialize()
        cursor = await db._conn.execute(
            "SELECT phase, status, error, started_at, finished_at FROM scan_phases WHERE run_id = ? ORDER BY id",
            (args.run_id,),
        )
        rows = await cursor.fetchall()
        phases = [{"phase": r[0], "status": r[1], "error": r[2], "started_at": r[3], "finished_at": r[4]} for r in rows]
        _output(phases)
    finally:
        await db.close()


async def cmd_db_scan_diff(args: argparse.Namespace) -> None:
    from bba.scan_state import ScanState
    db = await _get_db()
    try:
        state = ScanState(db)
        await state.initialize()
        diff = await state.diff_snapshots(args.old_run_id, args.new_run_id, args.category)
        _output(diff)
    finally:
        await db.close()


# --- Notify commands ---

async def cmd_scan_notify(args: argparse.Namespace) -> None:
    scope_cfg = _load_scope(args.program)
    scope = ScopeValidator(scope_cfg)
    runner = ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(),
                        sanitizer=Sanitizer(), output_dir=OUTPUT_DIR)
    db = await _get_db()
    try:
        from bba.tools.notify import NotifyTool
        tool = NotifyTool(runner=runner, db=db, program=args.program)
        result = await tool.send(args.message, provider_config=args.provider_config)
        _output(result)
    finally:
        await db.close()


async def cmd_scan_notify_findings(args: argparse.Namespace) -> None:
    db = await _get_db()
    try:
        from bba.notifier import Notifier
        notifier = Notifier(db=db, provider_config=args.provider_config)
        await notifier.notify_findings(args.program, severity_threshold=args.severity)
        _output({"sent": True, "program": args.program, "severity_threshold": args.severity})
    finally:
        await db.close()


# --- Scope import commands ---

async def cmd_scope_import_h1(args: argparse.Namespace) -> None:
    import urllib.request
    from bba.scope_importer import ScopeImporter

    handle = args.handle
    name = args.name or handle
    url = f"https://hackerone.com/programs/{handle}/policy_scopes.json"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read().decode())
    except Exception as e:
        _output({"error": f"Failed to fetch H1 scope: {e}"})
        return

    importer = ScopeImporter()
    scope = importer.parse_hackerone(data, name)
    output = Path(args.output) if args.output else PROGRAMS_DIR / f"{name}.yaml"
    importer.save_yaml(scope, output)
    _output({"saved": str(output), "in_scope_domains": len(scope["in_scope"]["domains"]),
             "in_scope_cidrs": len(scope["in_scope"]["cidrs"]),
             "out_of_scope": len(scope["out_of_scope"]["domains"])})


async def cmd_scope_import_bc(args: argparse.Namespace) -> None:
    import urllib.request
    from bba.scope_importer import ScopeImporter

    handle = args.handle
    name = args.name or handle
    url = f"https://bugcrowd.com/{handle}.json"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read().decode())
    except Exception as e:
        _output({"error": f"Failed to fetch Bugcrowd scope: {e}"})
        return

    importer = ScopeImporter()
    scope = importer.parse_bugcrowd(data, name)
    output = Path(args.output) if args.output else PROGRAMS_DIR / f"{name}.yaml"
    importer.save_yaml(scope, output)
    _output({"saved": str(output), "in_scope_domains": len(scope["in_scope"]["domains"]),
             "in_scope_cidrs": len(scope["in_scope"]["cidrs"]),
             "out_of_scope": len(scope["out_of_scope"]["domains"])})


# --- Wordlist commands ---

def cmd_wordlist_download(args: argparse.Namespace) -> None:
    from bba.wordlist_manager import WordlistManager
    manager = WordlistManager()
    result = manager.download(args.name)
    _output(result)


def cmd_wordlist_list(args: argparse.Namespace) -> None:
    from bba.wordlist_manager import WordlistManager
    manager = WordlistManager()
    result = manager.list()
    _output(result)


# --- Report command ---

async def cmd_report(args: argparse.Namespace) -> None:
    db = await _get_db()
    try:
        reporter = ReportGenerator(db=db)
        report = await reporter.generate(args.program)
        output_dir = OUTPUT_DIR / "reports"
        path = await reporter.save(args.program, output_dir)
        _output({"report_path": str(path), "report": report})
    finally:
        await db.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bba", description="Bug Bounty Agent CLI")
    parser.add_argument("--dry-run", action="store_true", help="Log commands without executing")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- recon ---
    recon = subparsers.add_parser("recon", help="Reconnaissance tools")
    recon_sub = recon.add_subparsers(dest="tool", required=True)

    sf = recon_sub.add_parser("subfinder", help="Subdomain enumeration")
    sf.add_argument("domain", help="Target domain")
    sf.add_argument("--program", required=True, help="Program name")
    sf.set_defaults(func=cmd_recon_subfinder)

    hx = recon_sub.add_parser("httpx", help="HTTP service probing")
    hx.add_argument("targets", help="Targets file or comma-separated domains")
    hx.add_argument("--program", required=True, help="Program name")
    hx.set_defaults(func=cmd_recon_httpx)

    kt = recon_sub.add_parser("katana", help="URL crawling")
    kt.add_argument("targets", help="Targets file or comma-separated URLs")
    kt.add_argument("--program", required=True, help="Program name")
    kt.set_defaults(func=cmd_recon_katana)

    ga = recon_sub.add_parser("gau", help="URL harvesting from archives")
    ga.add_argument("domain", help="Target domain")
    ga.add_argument("--program", required=True, help="Program name")
    ga.set_defaults(func=cmd_recon_gau)

    cr = recon_sub.add_parser("crtsh", help="Certificate transparency lookup")
    cr.add_argument("domain", help="Target domain")
    cr.add_argument("--program", required=True, help="Program name")
    cr.set_defaults(func=cmd_recon_crtsh)

    am = recon_sub.add_parser("amass", help="Subdomain enumeration with amass")
    am.add_argument("domain", help="Target domain")
    am.add_argument("--program", required=True, help="Program name")
    am.set_defaults(func=cmd_recon_amass)

    dn = recon_sub.add_parser("dnsx", help="DNS resolution and probing")
    dn.add_argument("targets", help="Targets file or comma-separated domains")
    dn.add_argument("--program", required=True, help="Program name")
    dn.set_defaults(func=cmd_recon_dnsx)

    wf = recon_sub.add_parser("wafw00f", help="WAF detection")
    wf.add_argument("url", help="Target URL")
    wf.add_argument("--program", required=True, help="Program name")
    wf.set_defaults(func=cmd_recon_wafw00f)

    nb = recon_sub.add_parser("naabu", help="Port scanning with naabu")
    nb.add_argument("targets", help="Targets file or comma-separated hosts")
    nb.add_argument("--program", required=True, help="Program name")
    nb.add_argument("--ports", default="top-1000", help="Ports to scan (default: top-1000)")
    nb.add_argument("--scan-type", default="connect", help="Scan type (default: connect)")
    nb.set_defaults(func=cmd_recon_naabu)

    nm = recon_sub.add_parser("nmap", help="Port scanning with nmap")
    nm.add_argument("targets", help="Targets file or comma-separated hosts")
    nm.add_argument("--program", required=True, help="Program name")
    nm.add_argument("--ports", default="80,443", help="Ports to scan (default: 80,443)")
    nm.set_defaults(func=cmd_recon_nmap)

    gw = recon_sub.add_parser("gowitness", help="Screenshot capture")
    gw.add_argument("targets", help="Targets file or comma-separated URLs")
    gw.add_argument("--program", required=True, help="Program name")
    gw.set_defaults(func=cmd_recon_gowitness)

    hrd = recon_sub.add_parser("hakrevdns", help="Reverse DNS lookup")
    hrd.add_argument("targets", help="Targets file or comma-separated IPs")
    hrd.add_argument("--program", required=True, help="Program name")
    hrd.set_defaults(func=cmd_recon_hakrevdns)

    cdc = recon_sub.add_parser("cdncheck", help="CDN/WAF detection")
    cdc.add_argument("targets", help="Targets file or comma-separated hosts")
    cdc.add_argument("--program", required=True, help="Program name")
    cdc.set_defaults(func=cmd_recon_cdncheck)

    asm = recon_sub.add_parser("asnmap", help="ASN mapping and enumeration")
    asm.add_argument("domain", help="Target domain")
    asm.add_argument("--program", required=True, help="Program name")
    asm.set_defaults(func=cmd_recon_asnmap)

    tl = recon_sub.add_parser("tlsx", help="TLS certificate probing")
    tl.add_argument("targets", help="Targets file or comma-separated hosts")
    tl.add_argument("--program", required=True, help="Program name")
    tl.set_defaults(func=cmd_recon_tlsx)

    wm = recon_sub.add_parser("waymore", help="Extended URL harvesting from archives")
    wm.add_argument("domain", help="Target domain")
    wm.add_argument("--program", required=True, help="Program name")
    wm.set_defaults(func=cmd_recon_waymore)

    gwf = recon_sub.add_parser("graphw00f", help="GraphQL fingerprinting")
    gwf.add_argument("url", help="Target URL")
    gwf.add_argument("--program", required=True, help="Program name")
    gwf.set_defaults(func=cmd_recon_graphw00f)

    sh = recon_sub.add_parser("shodan", help="Shodan search")
    sh.add_argument("query", help="Shodan search query")
    sh.add_argument("--domain", default=None, help="Associated domain")
    sh.add_argument("--program", required=True, help="Program name")
    sh.set_defaults(func=cmd_recon_shodan)

    uro = recon_sub.add_parser("uro", help="URL deduplication and filtering")
    uro.add_argument("targets", help="Targets file or comma-separated URLs")
    uro.add_argument("--program", required=True, help="Program name")
    uro.set_defaults(func=cmd_recon_uro)

    qsr = recon_sub.add_parser("qsreplace", help="Query string replacement for fuzzing")
    qsr.add_argument("targets", help="Targets file or comma-separated URLs")
    qsr.add_argument("--program", required=True, help="Program name")
    qsr.add_argument("--payload", required=True, help="Payload to replace query string values")
    qsr.set_defaults(func=cmd_recon_qsreplace)

    cew = recon_sub.add_parser("cewler", help="Custom wordlist generation from target content")
    cew.add_argument("url", help="Target URL to crawl")
    cew.add_argument("--depth", type=int, default=2, help="Crawl depth (default: 2)")
    cew.add_argument("--program", required=True, help="Program name")
    cew.set_defaults(func=cmd_recon_cewler)

    # --- scan ---
    scan = subparsers.add_parser("scan", help="Vulnerability scanning tools")
    scan_sub = scan.add_subparsers(dest="tool", required=True)

    nu = scan_sub.add_parser("nuclei", help="Template-based vulnerability scanning")
    nu.add_argument("targets", help="Targets file or comma-separated URLs")
    nu.add_argument("--program", required=True, help="Program name")
    nu.add_argument("--severity", default=None, help="Severity filter (e.g. high,critical)")
    nu.add_argument("--tags", default=None, help="Nuclei template tags")
    nu.add_argument("--rate-limit", type=int, default=None, help="Requests per second")
    nu.add_argument("--templates", default=None, help="Comma-separated template paths")
    nu.add_argument("--dast", action="store_true", help="Enable DAST scanning")
    nu.add_argument("--concurrency", type=int, default=None, help="Concurrency level")
    nu.set_defaults(func=cmd_scan_nuclei)

    ff = scan_sub.add_parser("ffuf", help="Directory fuzzing")
    ff.add_argument("url", help="Target URL with FUZZ keyword")
    ff.add_argument("--program", required=True, help="Program name")
    ff.add_argument("--wordlist", default=None, help="Wordlist path")
    ff.set_defaults(func=cmd_scan_ffuf)

    sq = scan_sub.add_parser("sqlmap", help="SQL injection testing")
    sq.add_argument("url", help="Target URL with parameters")
    sq.add_argument("--program", required=True, help="Program name")
    sq.set_defaults(func=cmd_scan_sqlmap)

    dx = scan_sub.add_parser("dalfox", help="XSS testing")
    dx.add_argument("url", help="Target URL")
    dx.add_argument("--program", required=True, help="Program name")
    dx.set_defaults(func=cmd_scan_dalfox)

    fb = scan_sub.add_parser("feroxbuster", help="Recursive directory fuzzing")
    fb.add_argument("url", help="Target URL")
    fb.add_argument("--program", required=True, help="Program name")
    fb.add_argument("--wordlist", default=None, help="Wordlist path")
    fb.add_argument("--depth", type=int, default=3, help="Recursion depth (default: 3)")
    fb.set_defaults(func=cmd_scan_feroxbuster)

    aj = scan_sub.add_parser("arjun", help="HTTP parameter discovery")
    aj.add_argument("url", help="Target URL")
    aj.add_argument("--program", required=True, help="Program name")
    aj.set_defaults(func=cmd_scan_arjun)

    ps = scan_sub.add_parser("paramspider", help="Parameter mining from web archives")
    ps.add_argument("domain", help="Target domain")
    ps.add_argument("--program", required=True, help="Program name")
    ps.set_defaults(func=cmd_scan_paramspider)

    uc = scan_sub.add_parser("uncover", help="Search engine discovery")
    uc.add_argument("query", help="Search query")
    uc.add_argument("--engines", default=None, help="Engines (default: shodan,censys,fofa)")
    uc.add_argument("--program", required=True, help="Program name")
    uc.set_defaults(func=cmd_scan_uncover)

    s3 = scan_sub.add_parser("s3scanner", help="S3 bucket scanning")
    s3.add_argument("bucket", help="Target bucket name")
    s3.add_argument("--program", required=True, help="Program name")
    s3.set_defaults(func=cmd_scan_s3scanner)

    rj = scan_sub.add_parser("retirejs", help="JavaScript vulnerability scanning")
    rj.add_argument("path", help="Path to scan")
    rj.add_argument("--domain", default=None, help="Associated domain")
    rj.add_argument("--program", required=True, help="Program name")
    rj.set_defaults(func=cmd_scan_retirejs)

    bs = scan_sub.add_parser("brutespray", help="Credential brute-forcing from nmap")
    bs.add_argument("nmap_xml", help="Path to nmap XML output")
    bs.add_argument("--domain", default=None, help="Associated domain")
    bs.add_argument("--program", required=True, help="Program name")
    bs.set_defaults(func=cmd_scan_brutespray)

    ncve = scan_sub.add_parser("nuclei-cve", help="Nuclei CVE scanning")
    ncve.add_argument("targets", help="Targets file or comma-separated URLs")
    ncve.add_argument("--program", required=True, help="Program name")
    ncve.add_argument("--severity", default=None, help="Severity filter (default: critical,high)")
    ncve.add_argument("--rate-limit", type=int, default=None, help="Requests per second")
    ncve.set_defaults(func=cmd_scan_nuclei_cve)

    nto = scan_sub.add_parser("nuclei-takeover", help="Nuclei subdomain takeover scanning")
    nto.add_argument("targets", help="Targets file or comma-separated URLs")
    nto.add_argument("--program", required=True, help="Program name")
    nto.set_defaults(func=cmd_scan_nuclei_takeover)

    npn = scan_sub.add_parser("nuclei-panels", help="Nuclei exposed panels and misconfigs")
    npn.add_argument("targets", help="Targets file or comma-separated URLs")
    npn.add_argument("--program", required=True, help="Program name")
    npn.set_defaults(func=cmd_scan_nuclei_panels)

    nda = scan_sub.add_parser("nuclei-dast", help="Nuclei DAST scanning")
    nda.add_argument("targets", help="Targets file or comma-separated URLs")
    nda.add_argument("--program", required=True, help="Program name")
    nda.add_argument("--rate-limit", type=int, default=None, help="Requests per second")
    nda.add_argument("--concurrency", type=int, default=None, help="Concurrency level")
    nda.set_defaults(func=cmd_scan_nuclei_dast)

    ts = scan_sub.add_parser("testssl", help="TLS/SSL audit with testssl")
    ts.add_argument("url", help="Target URL")
    ts.add_argument("--program", required=True, help="Program name")
    ts.set_defaults(func=cmd_scan_testssl)

    sl = scan_sub.add_parser("sslyze", help="SSL analysis with sslyze")
    sl.add_argument("target", help="Target in host:port format")
    sl.add_argument("--program", required=True, help="Program name")
    sl.set_defaults(func=cmd_scan_sslyze)

    nk = scan_sub.add_parser("nikto", help="Web server vulnerability scanning")
    nk.add_argument("url", help="Target URL")
    nk.add_argument("--program", required=True, help="Program name")
    nk.set_defaults(func=cmd_scan_nikto)

    sh_scan = scan_sub.add_parser("security-headers", help="HTTP security header analysis")
    sh_scan.add_argument("url", help="Target URL")
    sh_scan.add_argument("--program", required=True, help="Program name")
    sh_scan.set_defaults(func=cmd_scan_security_headers)

    crlf = scan_sub.add_parser("crlfuzz", help="CRLF injection scanning")
    crlf.add_argument("target", help="URL to test")
    crlf.add_argument("--program", required=True, help="Program name")
    crlf.set_defaults(func=cmd_scan_crlfuzz)

    ssti = scan_sub.add_parser("sstimap", help="Server-side template injection testing")
    ssti.add_argument("url", help="Target URL")
    ssti.add_argument("--program", required=True, help="Program name")
    ssti.set_defaults(func=cmd_scan_sstimap)

    cmx = scan_sub.add_parser("commix", help="Command injection testing")
    cmx.add_argument("url", help="Target URL")
    cmx.add_argument("--program", required=True, help="Program name")
    cmx.set_defaults(func=cmd_scan_commix)

    gh = scan_sub.add_parser("ghauri", help="SQL injection testing with ghauri")
    gh.add_argument("url", help="Target URL with parameters")
    gh.add_argument("--program", required=True, help="Program name")
    gh.add_argument("--level", type=int, default=2, help="Test level (default: 2)")
    gh.add_argument("--technique", default=None, help="Injection technique (e.g. BEUSTQ)")
    gh.set_defaults(func=cmd_scan_ghauri)

    nsql = scan_sub.add_parser("nosqli", help="NoSQL injection testing")
    nsql.add_argument("url", help="Target URL")
    nsql.add_argument("--program", required=True, help="Program name")
    nsql.set_defaults(func=cmd_scan_nosqli)

    xss = scan_sub.add_parser("xsstrike", help="XSS detection with XSStrike")
    xss.add_argument("url", help="Target URL")
    xss.add_argument("--program", required=True, help="Program name")
    xss.add_argument("--blind", action="store_true", help="Enable blind XSS mode")
    xss.add_argument("--crawl", action="store_true", help="Enable crawling mode")
    xss.set_defaults(func=cmd_scan_xsstrike)

    jwt = scan_sub.add_parser("jwt-tool", help="JWT token analysis and attack")
    jwt.add_argument("token", help="JWT token to test")
    jwt.add_argument("--program", required=True, help="Program name")
    jwt.add_argument("--domain", required=True, help="Associated domain")
    jwt.add_argument("--mode", default="scan", help="Mode: scan or crack (default: scan)")
    jwt.add_argument("--wordlist", default=None, help="Wordlist path for crack mode")
    jwt.set_defaults(func=cmd_scan_jwt_tool)

    ppf = scan_sub.add_parser("ppfuzz", help="Prototype pollution fuzzing")
    ppf.add_argument("targets", help="Targets file or comma-separated URLs")
    ppf.add_argument("--program", required=True, help="Program name")
    ppf.set_defaults(func=cmd_scan_ppfuzz)

    ig = scan_sub.add_parser("interactsh-generate", help="Generate OOB callback URLs")
    ig.add_argument("--count", type=int, default=10, help="Number of URLs to generate")
    ig.add_argument("--server", default=None, help="Custom interactsh server URL")
    ig.add_argument("--program", required=True, help="Program name")
    ig.set_defaults(func=cmd_scan_interactsh_generate)

    ip = scan_sub.add_parser("interactsh-poll", help="Poll for OOB interactions")
    ip.add_argument("session_file", help="Session file from generate")
    ip.add_argument("--domain", required=True, help="Domain being tested")
    ip.add_argument("--program", required=True, help="Program name")
    ip.set_defaults(func=cmd_scan_interactsh_poll)

    nm4 = scan_sub.add_parser("nomore403", help="403 bypass automation")
    nm4.add_argument("url", help="URL returning 403")
    nm4.add_argument("--program", required=True, help="Program name")
    nm4.set_defaults(func=cmd_scan_nomore403)

    jsu = scan_sub.add_parser("jsluice-urls", help="Extract URLs from JS files (AST-based)")
    jsu.add_argument("js_url", help="JavaScript file URL or path")
    jsu.add_argument("--domain", required=True, help="Associated domain")
    jsu.add_argument("--program", required=True, help="Program name")
    jsu.set_defaults(func=cmd_scan_jsluice_urls)

    jss = scan_sub.add_parser("jsluice-secrets", help="Extract secrets from JS files (AST-based)")
    jss.add_argument("js_url", help="JavaScript file URL or path")
    jss.add_argument("--domain", required=True, help="Associated domain")
    jss.add_argument("--program", required=True, help="Program name")
    jss.set_defaults(func=cmd_scan_jsluice_secrets)

    sz = scan_sub.add_parser("subzy", help="Subdomain takeover detection")
    sz.add_argument("targets", help="Targets file or comma-separated domains")
    sz.add_argument("--program", required=True, help="Program name")
    sz.set_defaults(func=cmd_scan_subzy)

    cv = scan_sub.add_parser("clairvoyance", help="GraphQL schema reconstruction")
    cv.add_argument("url", help="GraphQL endpoint URL")
    cv.add_argument("--wordlist", default=None, help="Custom wordlist for field brute-forcing")
    cv.add_argument("--program", required=True, help="Program name")
    cv.set_defaults(func=cmd_scan_clairvoyance)

    cs = scan_sub.add_parser("cache-scanner", help="Web cache poisoning/deception detection")
    cs.add_argument("url", help="Target URL")
    cs.add_argument("--program", required=True, help="Program name")
    cs.set_defaults(func=cmd_scan_cache_scanner)

    ntf = scan_sub.add_parser("notify", help="Send notification via notify")
    ntf.add_argument("message", help="Message to send")
    ntf.add_argument("--provider-config", default=None, help="Path to notify provider config")
    ntf.add_argument("--program", required=True, help="Program name")
    ntf.set_defaults(func=cmd_scan_notify)

    ntff = scan_sub.add_parser("notify-findings", help="Send notifications for new findings")
    ntff.add_argument("--program", required=True, help="Program name")
    ntff.add_argument("--severity", default="medium", choices=["critical", "high", "medium", "low", "info"])
    ntff.add_argument("--provider-config", default=None)
    ntff.set_defaults(func=cmd_scan_notify_findings)

    # --- db ---
    db = subparsers.add_parser("db", help="Database queries")
    db_sub = db.add_subparsers(dest="query", required=True)

    db_subs = db_sub.add_parser("subdomains", help="List discovered subdomains")
    db_subs.add_argument("--program", required=True, help="Program name")
    db_subs.set_defaults(func=cmd_db_subdomains)

    db_svcs = db_sub.add_parser("services", help="List discovered services")
    db_svcs.add_argument("--program", required=True, help="Program name")
    db_svcs.set_defaults(func=cmd_db_services)

    db_find = db_sub.add_parser("findings", help="List findings")
    db_find.add_argument("--program", required=True, help="Program name")
    db_find.add_argument("--severity", default=None, help="Filter by severity")
    db_find.add_argument("--status", default=None, help="Filter by status")
    db_find.set_defaults(func=cmd_db_findings)

    db_summ = db_sub.add_parser("summary", help="Program summary")
    db_summ.add_argument("--program", required=True, help="Program name")
    db_summ.set_defaults(func=cmd_db_summary)

    db_add = db_sub.add_parser("add-finding", help="Add a finding")
    db_add.add_argument("--program", required=True, help="Program name")
    db_add.add_argument("--domain", required=True, help="Affected domain")
    db_add.add_argument("--url", required=True, help="Affected URL")
    db_add.add_argument("--vuln-type", required=True, help="Vulnerability type")
    db_add.add_argument("--severity-level", required=True, help="Severity level")
    db_add.add_argument("--tool", required=True, help="Discovery tool")
    db_add.add_argument("--evidence", required=True, help="Evidence text")
    db_add.add_argument("--confidence", type=float, default=0.5, help="Confidence score 0.0-1.0")
    db_add.set_defaults(func=cmd_db_add_finding)

    db_upd = db_sub.add_parser("update-finding", help="Update finding status")
    db_upd.add_argument("finding_id", type=int, help="Finding ID")
    db_upd.add_argument("--status", required=True, choices=["validated", "false_positive", "needs_review"], help="New status")
    db_upd.set_defaults(func=cmd_db_update_finding)

    db_ports = db_sub.add_parser("ports", help="List discovered ports")
    db_ports.add_argument("--program", required=True, help="Program name")
    db_ports.set_defaults(func=cmd_db_ports)

    db_urls = db_sub.add_parser("urls", help="List discovered URLs")
    db_urls.add_argument("--program", required=True, help="Program name")
    db_urls.add_argument("--source", default=None, help="Filter by source tool")
    db_urls.set_defaults(func=cmd_db_urls)

    db_js = db_sub.add_parser("js-files", help="List discovered JS files")
    db_js.add_argument("--program", required=True, help="Program name")
    db_js.set_defaults(func=cmd_db_js_files)

    db_sec = db_sub.add_parser("secrets", help="List discovered secrets")
    db_sec.add_argument("--program", required=True, help="Program name")
    db_sec.add_argument("--status", default=None, help="Filter by status")
    db_sec.set_defaults(func=cmd_db_secrets)

    db_ss = db_sub.add_parser("screenshots", help="List captured screenshots")
    db_ss.add_argument("--program", required=True, help="Program name")
    db_ss.set_defaults(func=cmd_db_screenshots)

    db_sh = db_sub.add_parser("scan-history", help="List scan runs for a program")
    db_sh.add_argument("--program", required=True, help="Program name")
    db_sh.set_defaults(func=cmd_db_scan_history)

    db_ss2 = db_sub.add_parser("scan-status", help="Show status of a scan run")
    db_ss2.add_argument("run_id", type=int, help="Scan run ID")
    db_ss2.add_argument("--program", required=True, help="Program name")
    db_ss2.set_defaults(func=cmd_db_scan_status)

    db_sd = db_sub.add_parser("scan-diff", help="Diff two scan runs")
    db_sd.add_argument("old_run_id", type=int, help="Old scan run ID")
    db_sd.add_argument("new_run_id", type=int, help="New scan run ID")
    db_sd.add_argument("--category", default="subdomains", choices=["subdomains", "urls", "services", "findings"])
    db_sd.add_argument("--program", required=True, help="Program name")
    db_sd.set_defaults(func=cmd_db_scan_diff)

    # --- wordlist ---
    wl = subparsers.add_parser("wordlist", help="Wordlist management")
    wl_sub = wl.add_subparsers(dest="action", required=True)

    wl_dl = wl_sub.add_parser("download", help="Download wordlists")
    wl_dl.add_argument("--name", default="all", help="Wordlist name (default: all)")
    wl_dl.set_defaults(func=cmd_wordlist_download)

    wl_ls = wl_sub.add_parser("list", help="List available wordlists")
    wl_ls.set_defaults(func=cmd_wordlist_list)

    # --- report ---
    rpt = subparsers.add_parser("report", help="Generate report")
    rpt.add_argument("--program", required=True, help="Program name")
    rpt.set_defaults(func=cmd_report)

    # --- scope ---
    scope_p = subparsers.add_parser("scope", help="Scope management")
    scope_sub = scope_p.add_subparsers(dest="scope_cmd", required=True)

    si_h1 = scope_sub.add_parser("import-h1", help="Import scope from HackerOne")
    si_h1.add_argument("handle", help="HackerOne program handle")
    si_h1.add_argument("--name", help="Program name (defaults to handle)")
    si_h1.add_argument("--output", default=None, help="Output path")
    si_h1.set_defaults(func=cmd_scope_import_h1)

    si_bc = scope_sub.add_parser("import-bc", help="Import scope from Bugcrowd")
    si_bc.add_argument("handle", help="Bugcrowd program handle")
    si_bc.add_argument("--name", help="Program name (defaults to handle)")
    si_bc.add_argument("--output", default=None, help="Output path")
    si_bc.set_defaults(func=cmd_scope_import_bc)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    result = args.func(args)
    if asyncio.iscoroutine(result):
        asyncio.run(result)


if __name__ == "__main__":
    main()
