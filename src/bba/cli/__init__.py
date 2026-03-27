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
from bba.sanitizer import Sanitizer
from bba.scope import ScopeConfig, ScopeValidator
from bba.tool_runner import ToolRunner

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "db" / "findings.db"
OUTPUT_DIR = DATA_DIR / "output"
PROGRAMS_DIR = DATA_DIR / "programs"
DEFAULT_WORDLIST = str(DATA_DIR / "wordlists" / "seclists" / "Discovery" / "Web-Content" / "common.txt")


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


# Re-export all cmd_* functions so that `from bba.cli import cmd_*` works,
# and so that patch("bba.cli._get_db") affects them via the module-level reference.
from bba.cli.recon import (  # noqa: E402
    cmd_recon_subfinder,
    cmd_recon_httpx,
    cmd_recon_katana,
    cmd_recon_gau,
    cmd_recon_crtsh,
    cmd_recon_amass,
    cmd_recon_dnsx,
    cmd_recon_wafw00f,
    cmd_recon_naabu,
    cmd_recon_nmap,
    cmd_recon_gowitness,
    cmd_recon_hakrevdns,
    cmd_recon_cdncheck,
    cmd_recon_asnmap,
    cmd_recon_tlsx,
    cmd_recon_waymore,
    cmd_recon_graphw00f,
    cmd_recon_shodan,
    cmd_recon_cewler,
    cmd_recon_uro,
    cmd_recon_qsreplace,
)
from bba.cli.scan import (  # noqa: E402
    cmd_scan_nuclei,
    cmd_scan_ffuf,
    cmd_scan_sqlmap,
    cmd_scan_dalfox,
    cmd_scan_feroxbuster,
    cmd_scan_arjun,
    cmd_scan_paramspider,
    cmd_scan_uncover,
    cmd_scan_s3scanner,
    cmd_scan_retirejs,
    cmd_scan_brutespray,
    cmd_scan_nuclei_cve,
    cmd_scan_nuclei_takeover,
    cmd_scan_nuclei_panels,
    cmd_scan_nuclei_dast,
    cmd_scan_testssl,
    cmd_scan_sslyze,
    cmd_scan_nikto,
    cmd_scan_security_headers,
    cmd_scan_crlfuzz,
    cmd_scan_sstimap,
    cmd_scan_commix,
    cmd_scan_ghauri,
    cmd_scan_nosqli,
    cmd_scan_xsstrike,
    cmd_scan_jwt_tool,
    cmd_scan_ppfuzz,
    cmd_scan_interactsh_generate,
    cmd_scan_interactsh_poll,
    cmd_scan_nomore403,
    cmd_scan_jsluice_urls,
    cmd_scan_jsluice_secrets,
    cmd_scan_subzy,
    cmd_scan_clairvoyance,
    cmd_scan_cache_scanner,
    cmd_scan_notify,
    cmd_scan_notify_findings,
)
from bba.cli.db_cmds import (  # noqa: E402
    cmd_db_subdomains,
    cmd_db_services,
    cmd_db_findings,
    cmd_db_summary,
    cmd_db_add_finding,
    cmd_db_update_finding,
    cmd_db_ports,
    cmd_db_urls,
    cmd_db_js_files,
    cmd_db_secrets,
    cmd_db_screenshots,
    cmd_db_scan_history,
    cmd_db_scan_status,
    cmd_db_scan_diff,
    cmd_db_set_phase_output,
    cmd_db_get_phase_output,
    cmd_db_coverage,
    cmd_db_add_coverage,
)
from bba.cli.report import (  # noqa: E402
    cmd_wordlist_download,
    cmd_wordlist_list,
    cmd_report,
    cmd_scope_import_h1,
    cmd_scope_import_bc,
)


def build_parser() -> argparse.ArgumentParser:
    from bba.cli.recon import register_recon_commands
    from bba.cli.scan import register_scan_commands
    from bba.cli.db_cmds import register_db_commands
    from bba.cli.report import register_report_commands

    parser = argparse.ArgumentParser(prog="bba", description="Offensive Security Agent CLI")
    parser.add_argument("--dry-run", action="store_true", help="Log commands without executing")
    subparsers = parser.add_subparsers(dest="command", required=True)

    register_recon_commands(subparsers)
    register_scan_commands(subparsers)
    register_db_commands(subparsers)
    register_report_commands(subparsers)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    result = args.func(args)
    if asyncio.iscoroutine(result):
        asyncio.run(result)


if __name__ == "__main__":
    main()
