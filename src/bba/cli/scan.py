"""Scan command handlers and parser registration."""

from __future__ import annotations

import argparse
from pathlib import Path

import bba.cli as _bba_cli
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.scope import ScopeValidator
from bba.tool_runner import ToolRunner


# --- Scan commands ---


async def cmd_scan_nuclei(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.nuclei import NucleiTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = NucleiTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "scan"
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
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_ffuf(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.ffuf import FfufTool
        tool = FfufTool(runner=runner, db=db, program=args.program)
        result = await tool.run(
            target_url=args.url,
            wordlist=args.wordlist or _bba_cli.DEFAULT_WORDLIST,
        )
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_sqlmap(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.sqlmap_runner import SqlmapTool
        tool = SqlmapTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_dalfox(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.dalfox import DalfoxTool
        tool = DalfoxTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_feroxbuster(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.feroxbuster import FeroxbusterTool
        tool = FeroxbusterTool(runner=runner, db=db, program=args.program)
        result = await tool.run(
            url=args.url,
            wordlist=args.wordlist or _bba_cli.DEFAULT_WORDLIST,
            depth=args.depth,
        )
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_arjun(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.arjun import ArjunTool
        tool = ArjunTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_paramspider(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.paramspider import ParamspiderTool
        tool = ParamspiderTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.domain)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_uncover(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.uncover import UncoverTool
        tool = UncoverTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.query, engines=args.engines or "shodan,censys,fofa")
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_s3scanner(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.s3scanner import S3ScannerTool
        tool = S3ScannerTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.bucket)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_retirejs(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.retirejs import RetirejsTool
        tool = RetirejsTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.path, domain=args.domain or "")
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_brutespray(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.brutespray import BrutesprayTool
        tool = BrutesprayTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.nmap_xml, domain=args.domain or "")
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_nuclei_cve(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.nuclei import NucleiTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = NucleiTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "scan"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(
            targets=targets, work_dir=work_dir,
            severity=args.severity or "critical,high",
            rate_limit=args.rate_limit or 100,
            templates=["cves/"],
        )
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_nuclei_takeover(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.nuclei import NucleiTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = NucleiTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "scan"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(
            targets=targets, work_dir=work_dir,
            templates=["takeovers/"],
        )
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_nuclei_panels(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.nuclei import NucleiTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = NucleiTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "scan"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(
            targets=targets, work_dir=work_dir,
            templates=["exposed-panels/", "misconfiguration/"],
        )
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_nuclei_dast(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.nuclei import NucleiTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = NucleiTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "scan"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(
            targets=targets, work_dir=work_dir,
            rate_limit=args.rate_limit or 10,
            dast=True,
            concurrency=args.concurrency or 3,
        )
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_testssl(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.testssl import TestsslTool
        tool = TestsslTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_sslyze(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.sslyze import SslyzeTool
        tool = SslyzeTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.target)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_nikto(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.nikto import NiktoTool
        tool = NiktoTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_security_headers(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.security_headers import SecurityHeadersTool
        tool = SecurityHeadersTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _bba_cli._output(result)
    finally:
        await db.close()


# --- Phase 4 scan command handlers ---


async def cmd_scan_crlfuzz(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.crlfuzz import CrlfuzzTool
        tool = CrlfuzzTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.target)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_sstimap(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.sstimap import SstimapTool
        tool = SstimapTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_commix(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.commix import CommixTool
        tool = CommixTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_ghauri(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.ghauri import GhauriTool
        tool = GhauriTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url, level=args.level, technique=args.technique)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_nosqli(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.nosqli import NosqliTool
        tool = NosqliTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_xsstrike(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.xsstrike import XSStrikeTool
        tool = XSStrikeTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url, blind=args.blind, crawl=args.crawl)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_jwt_tool(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.jwt_tool import JwtToolTool
        tool = JwtToolTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.token, domain=args.domain, mode=args.mode, wordlist=args.wordlist)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_ppfuzz(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
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
        _bba_cli._output(result)
    finally:
        await db.close()


# --- Phase 5A scan command handlers ---


async def cmd_scan_interactsh_generate(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.interactsh import InteractshTool
        tool = InteractshTool(runner=runner, db=db, program=args.program)
        result = await tool.generate_urls(count=args.count, server=args.server)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_interactsh_poll(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.interactsh import InteractshTool
        tool = InteractshTool(runner=runner, db=db, program=args.program)
        result = await tool.poll_interactions(args.session_file, domain=args.domain)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_nomore403(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.nomore403 import Nomore403Tool
        tool = Nomore403Tool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_jsluice_urls(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.jsluice import JsluiceTool
        tool = JsluiceTool(runner=runner, db=db, program=args.program)
        result = await tool.run_urls(args.js_url, domain=args.domain)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_jsluice_secrets(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.jsluice import JsluiceTool
        tool = JsluiceTool(runner=runner, db=db, program=args.program)
        result = await tool.run_secrets(args.js_url, domain=args.domain)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_subzy(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.subzy import SubzyTool
        if Path(args.targets).is_file():
            targets = Path(args.targets).read_text().strip().splitlines()
        else:
            targets = [t.strip() for t in args.targets.split(",") if t.strip()]
        tool = SubzyTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "scan"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_clairvoyance(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.clairvoyance import ClairvoyanceTool
        tool = ClairvoyanceTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url, wordlist=args.wordlist)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_cache_scanner(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.cache_scanner import CacheScannerTool
        tool = CacheScannerTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _bba_cli._output(result)
    finally:
        await db.close()


# --- Notify commands ---


async def cmd_scan_notify(args: argparse.Namespace) -> None:
    scope_cfg = _bba_cli._load_scope(args.program)
    scope = ScopeValidator(scope_cfg)
    runner = ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(),
                        sanitizer=Sanitizer(), output_dir=_bba_cli.OUTPUT_DIR)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.notify import NotifyTool
        tool = NotifyTool(runner=runner, db=db, program=args.program)
        result = await tool.send(args.message, provider_config=args.provider_config)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_scan_notify_findings(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
    try:
        from bba.notifier import Notifier
        notifier = Notifier(db=db, provider_config=args.provider_config)
        await notifier.notify_findings(args.program, severity_threshold=args.severity)
        _bba_cli._output({"sent": True, "program": args.program, "severity_threshold": args.severity})
    finally:
        await db.close()


def register_scan_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register all scan subcommands onto the top-level subparsers."""
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
