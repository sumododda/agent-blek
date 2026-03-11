"""BBA CLI — agents invoke security tools via this interface.

Usage:
    bba recon subfinder <domain> --program <prog>
    bba recon httpx <targets_file> --program <prog>
    bba recon katana <targets_file> --program <prog>
    bba recon gau <domain> --program <prog>
    bba scan nuclei <targets_file> --program <prog> [--severity] [--tags] [--rate-limit]
    bba scan ffuf <url-with-FUZZ> --program <prog> [--wordlist]
    bba scan sqlmap <url> --program <prog>
    bba scan dalfox <url> --program <prog>
    bba db subdomains --program <prog>
    bba db services --program <prog>
    bba db findings --program <prog> [--severity] [--status]
    bba db summary --program <prog>
    bba db add-finding --program <prog> ...
    bba db update-finding <id> --status <status>
    bba report --program <prog>
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
        result = await tool.run(
            targets=targets,
            work_dir=work_dir,
            severity=args.severity or "high,critical",
            rate_limit=args.rate_limit or 100,
            tags=args.tags,
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

    # --- scan ---
    scan = subparsers.add_parser("scan", help="Vulnerability scanning tools")
    scan_sub = scan.add_subparsers(dest="tool", required=True)

    nu = scan_sub.add_parser("nuclei", help="Template-based vulnerability scanning")
    nu.add_argument("targets", help="Targets file or comma-separated URLs")
    nu.add_argument("--program", required=True, help="Program name")
    nu.add_argument("--severity", default=None, help="Severity filter (e.g. high,critical)")
    nu.add_argument("--tags", default=None, help="Nuclei template tags")
    nu.add_argument("--rate-limit", type=int, default=None, help="Requests per second")
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

    # --- report ---
    rpt = subparsers.add_parser("report", help="Generate report")
    rpt.add_argument("--program", required=True, help="Program name")
    rpt.set_defaults(func=cmd_report)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    asyncio.run(args.func(args))


if __name__ == "__main__":
    main()
