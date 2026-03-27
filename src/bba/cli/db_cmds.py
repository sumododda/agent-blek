"""Database command handlers and parser registration."""

from __future__ import annotations

import argparse

import bba.cli as _bba_cli


# --- Database commands ---


async def cmd_db_subdomains(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
    try:
        rows = await db.get_subdomains(args.program)
        _bba_cli._output(rows)
    finally:
        await db.close()


async def cmd_db_services(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
    try:
        rows = await db.get_services(args.program)
        _bba_cli._output(rows)
    finally:
        await db.close()


async def cmd_db_findings(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
    try:
        rows = await db.get_findings(
            args.program,
            severity=args.severity,
            status=args.status,
        )
        _bba_cli._output(rows)
    finally:
        await db.close()


async def cmd_db_summary(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
    try:
        summary = await db.get_program_summary(args.program)
        _bba_cli._output(summary)
    finally:
        await db.close()


async def cmd_db_add_finding(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
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
        _bba_cli._output({"id": finding_id, "status": "created"})
    finally:
        await db.close()


async def cmd_db_update_finding(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
    try:
        await db.update_finding_status(args.finding_id, args.status, reason=getattr(args, "reason", None))
        _bba_cli._output({"id": args.finding_id, "status": args.status, "updated": True})
    finally:
        await db.close()


async def cmd_db_ports(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
    try:
        rows = await db.get_ports(args.program)
        _bba_cli._output(rows)
    finally:
        await db.close()


async def cmd_db_urls(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
    try:
        rows = await db.get_urls(args.program, source=args.source)
        _bba_cli._output(rows)
    finally:
        await db.close()


async def cmd_db_js_files(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
    try:
        rows = await db.get_js_files(args.program)
        _bba_cli._output(rows)
    finally:
        await db.close()


async def cmd_db_secrets(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
    try:
        rows = await db.get_secrets(args.program, status=args.status)
        _bba_cli._output(rows)
    finally:
        await db.close()


async def cmd_db_screenshots(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
    try:
        rows = await db.get_screenshots(args.program)
        _bba_cli._output(rows)
    finally:
        await db.close()


# --- Scan state commands ---


async def cmd_db_scan_history(args: argparse.Namespace) -> None:
    from bba.scan_state import ScanState
    db = await _bba_cli._get_db()
    try:
        state = ScanState(db)
        await state.initialize()
        cursor = await db._conn.execute(
            "SELECT id, status, started_at, finished_at FROM scan_runs WHERE program = ? ORDER BY id DESC LIMIT 20",
            (args.program,),
        )
        rows = await cursor.fetchall()
        runs = [{"id": r[0], "status": r[1], "started_at": r[2], "finished_at": r[3]} for r in rows]
        _bba_cli._output(runs)
    finally:
        await db.close()


async def cmd_db_scan_status(args: argparse.Namespace) -> None:
    from bba.scan_state import ScanState
    db = await _bba_cli._get_db()
    try:
        state = ScanState(db)
        await state.initialize()
        cursor = await db._conn.execute(
            "SELECT phase, status, error, started_at, finished_at FROM scan_phases WHERE run_id = ? ORDER BY id",
            (args.run_id,),
        )
        rows = await cursor.fetchall()
        phases = [{"phase": r[0], "status": r[1], "error": r[2], "started_at": r[3], "finished_at": r[4]} for r in rows]
        _bba_cli._output(phases)
    finally:
        await db.close()


async def cmd_db_scan_diff(args: argparse.Namespace) -> None:
    from bba.scan_state import ScanState
    db = await _bba_cli._get_db()
    try:
        state = ScanState(db)
        await state.initialize()
        diff = await state.diff_snapshots(args.old_run_id, args.new_run_id, args.category)
        _bba_cli._output(diff)
    finally:
        await db.close()


async def cmd_db_set_phase_output(args: argparse.Namespace) -> None:
    from bba.scan_state import ScanState
    db = await _bba_cli._get_db()
    try:
        state = ScanState(db)
        await state.initialize()
        latest = await state.get_latest_run(args.program)
        if not latest:
            _bba_cli._output({"error": "No scan runs found for program"})
            return
        await state.set_phase_output(latest["id"], args.phase, args.key, args.value)
        _bba_cli._output({"run_id": latest["id"], "phase": args.phase, "key": args.key, "stored": True})
    finally:
        await db.close()


async def cmd_db_get_phase_output(args: argparse.Namespace) -> None:
    from bba.scan_state import ScanState
    db = await _bba_cli._get_db()
    try:
        state = ScanState(db)
        await state.initialize()
        latest = await state.get_latest_run(args.program)
        if not latest:
            _bba_cli._output({"error": "No scan runs found for program"})
            return
        value = await state.get_phase_output(latest["id"], args.phase, args.key)
        _bba_cli._output({"phase": args.phase, "key": args.key, "value": value})
    finally:
        await db.close()


async def cmd_db_coverage(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
    try:
        summary = await db.get_coverage_summary(args.program)
        _bba_cli._output(summary)
    finally:
        await db.close()


async def cmd_db_add_coverage(args: argparse.Namespace) -> None:
    from bba.scan_state import ScanState
    db = await _bba_cli._get_db()
    try:
        state = ScanState(db)
        await state.initialize()
        latest = await state.get_latest_run(args.program)
        if not latest:
            _bba_cli._output({"error": "No scan runs found for program"})
            return
        tested = args.tested.lower() in ("true", "1", "yes")
        await db.add_coverage(latest["id"], args.program, args.url, args.phase, args.category, tested, args.skip_reason)
        _bba_cli._output({"stored": True})
    finally:
        await db.close()


def register_db_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register all db subcommands onto the top-level subparsers."""
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
    db_upd.add_argument("--reason", default=None, help="Reason for status change")
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

    db_spo = db_sub.add_parser("set-phase-output", help="Store structured phase output")
    db_spo.add_argument("--program", required=True, help="Program name")
    db_spo.add_argument("--phase", required=True, help="Phase name")
    db_spo.add_argument("--key", required=True, help="Output key")
    db_spo.add_argument("--value", required=True, help="Output value (JSON string)")
    db_spo.set_defaults(func=cmd_db_set_phase_output)

    db_gpo = db_sub.add_parser("get-phase-output", help="Retrieve structured phase output")
    db_gpo.add_argument("--program", required=True, help="Program name")
    db_gpo.add_argument("--phase", required=True, help="Phase name")
    db_gpo.add_argument("--key", required=True, help="Output key")
    db_gpo.set_defaults(func=cmd_db_get_phase_output)

    db_cov = db_sub.add_parser("coverage", help="Show coverage summary")
    db_cov.add_argument("--program", required=True, help="Program name")
    db_cov.set_defaults(func=cmd_db_coverage)

    db_acov = db_sub.add_parser("add-coverage", help="Add coverage entry")
    db_acov.add_argument("--program", required=True, help="Program name")
    db_acov.add_argument("--url", required=True, help="URL tested")
    db_acov.add_argument("--phase", required=True, help="Phase name")
    db_acov.add_argument("--category", default=None, help="Test category")
    db_acov.add_argument("--tested", required=True, help="Whether URL was tested (true/false)")
    db_acov.add_argument("--skip-reason", default=None, help="Reason for skipping")
    db_acov.set_defaults(func=cmd_db_add_coverage)
