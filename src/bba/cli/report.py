"""Report, wordlist, and scope import handlers and parser registration."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import bba.cli as _bba_cli
from bba.reporter import ReportGenerator


# --- Wordlist commands ---


def cmd_wordlist_download(args: argparse.Namespace) -> None:
    from bba.wordlist_manager import WordlistManager
    manager = WordlistManager()
    result = manager.download(args.name)
    _bba_cli._output(result)


def cmd_wordlist_list(args: argparse.Namespace) -> None:
    from bba.wordlist_manager import WordlistManager
    manager = WordlistManager()
    result = manager.list()
    _bba_cli._output(result)


# --- Report command ---


async def cmd_report(args: argparse.Namespace) -> None:
    db = await _bba_cli._get_db()
    try:
        reporter = ReportGenerator(db=db)
        report = await reporter.generate(args.program)
        output_dir = _bba_cli.OUTPUT_DIR / "reports"
        path = await reporter.save(args.program, output_dir)
        _bba_cli._output({"report_path": str(path), "report": report})
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
        _bba_cli._output({"error": f"Failed to fetch H1 scope: {e}"})
        return

    importer = ScopeImporter()
    scope = importer.parse_hackerone(data, name)
    output = Path(args.output) if args.output else _bba_cli.PROGRAMS_DIR / f"{name}.yaml"
    importer.save_yaml(scope, output)
    _bba_cli._output({"saved": str(output), "in_scope_domains": len(scope["in_scope"]["domains"]),
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
        _bba_cli._output({"error": f"Failed to fetch Bugcrowd scope: {e}"})
        return

    importer = ScopeImporter()
    scope = importer.parse_bugcrowd(data, name)
    output = Path(args.output) if args.output else _bba_cli.PROGRAMS_DIR / f"{name}.yaml"
    importer.save_yaml(scope, output)
    _bba_cli._output({"saved": str(output), "in_scope_domains": len(scope["in_scope"]["domains"]),
                      "in_scope_cidrs": len(scope["in_scope"]["cidrs"]),
                      "out_of_scope": len(scope["out_of_scope"]["domains"])})


def register_report_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register wordlist, report, and scope subcommands onto the top-level subparsers."""
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
