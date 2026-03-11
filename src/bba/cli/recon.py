"""Recon command handlers and parser registration."""

from __future__ import annotations

import argparse
from pathlib import Path

import bba.cli as _bba_cli


# --- Recon commands ---


async def cmd_recon_subfinder(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.subfinder import SubfinderTool
        tool = SubfinderTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.domain)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_httpx(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.httpx_runner import HttpxTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            domains = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            domains = [t.strip() for t in args.targets.split(",")]
        tool = HttpxTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(domains, work_dir=work_dir)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_katana(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.katana import KatanaTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = KatanaTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_gau(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.gau import GauTool
        tool = GauTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.domain)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_crtsh(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.crtsh import CrtshTool
        tool = CrtshTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.domain)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_amass(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.amass import AmassTool
        tool = AmassTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.domain)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_dnsx(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.dnsx import DnsxTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = DnsxTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_wafw00f(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.wafw00f import Wafw00fTool
        tool = Wafw00fTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_naabu(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.naabu import NaabuTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = NaabuTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir, ports=args.ports, scan_type=args.scan_type)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_nmap(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.nmap_runner import NmapTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = NmapTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir, ports=args.ports)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_gowitness(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.gowitness import GowitnessTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = GowitnessTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_hakrevdns(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.hakrevdns import HakrevdnsTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = HakrevdnsTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_cdncheck(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.cdncheck import CdncheckTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = CdncheckTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_asnmap(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.asnmap import AsnmapTool
        tool = AsnmapTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.domain)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_tlsx(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.tlsx import TlsxTool
        targets_file = Path(args.targets)
        if targets_file.exists():
            targets = [l.strip() for l in targets_file.read_text().splitlines() if l.strip()]
        else:
            targets = [t.strip() for t in args.targets.split(",")]
        tool = TlsxTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(targets, work_dir=work_dir)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_waymore(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.waymore import WaymoreTool
        tool = WaymoreTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.domain)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_graphw00f(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.graphw00f import Graphw00fTool
        tool = Graphw00fTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.url)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_shodan(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.shodan_cli import ShodanTool
        tool = ShodanTool(runner=runner, db=db, program=args.program)
        result = await tool.run(args.query, domain=args.domain or args.query)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_cewler(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
    try:
        from bba.tools.cewler import CewlerTool
        tool = CewlerTool(runner=runner, db=db, program=args.program)
        work_dir = _bba_cli.OUTPUT_DIR / "recon"
        work_dir.mkdir(parents=True, exist_ok=True)
        result = await tool.run(args.url, work_dir, depth=args.depth)
        _bba_cli._output(result)
    finally:
        await db.close()


async def cmd_recon_uro(args: argparse.Namespace) -> None:
    scope = _bba_cli._load_scope(args.program)
    runner = _bba_cli._make_runner(scope)
    db = await _bba_cli._get_db()
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
        _bba_cli._output(result)
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
    _bba_cli._output({"total": len(results), "urls": results, "payload": args.payload})


def register_recon_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register all recon subcommands onto the top-level subparsers."""
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
