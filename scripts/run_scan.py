#!/usr/bin/env python3
"""Run the full bug bounty pipeline against a target."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from bba.db import Database
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.scope import ScopeConfig, ScopeValidator
from bba.tool_runner import ToolRunner
from bba.tools.httpx_runner import HttpxTool
from bba.tools.nuclei import NucleiTool
from bba.tools.ffuf import FfufTool
from bba.tools.subfinder import SubfinderTool
from bba.validator import FindingValidator
from bba.reporter import ReportGenerator


async def main():
    # Configuration
    TARGET_DOMAIN = sys.argv[1] if len(sys.argv) > 1 else "simba.blekcipher.com"
    PROGRAM = TARGET_DOMAIN.split(".")[0]
    TARGET_URL = f"https://{TARGET_DOMAIN}"
    WORK_DIR = Path(f"/tmp/bba-{PROGRAM}-scan")
    RPS = 10  # Requests per second - be polite to live targets

    # Setup
    config = ScopeConfig(
        program=PROGRAM,
        platform="self-owned",
        in_scope_domains=[TARGET_DOMAIN, f"*.{TARGET_DOMAIN}"],
    )
    validator = ScopeValidator(config)
    runner = ToolRunner(
        scope=validator,
        rate_limiter=MultiTargetRateLimiter(default_rps=float(RPS)),
        sanitizer=Sanitizer(),
        output_dir=WORK_DIR / "output",
    )
    db = Database(WORK_DIR / "findings.db")
    await db.initialize()

    # Ensure work directories exist
    for d in ["recon", "scan", "fuzz", "output", "reports"]:
        (WORK_DIR / d).mkdir(parents=True, exist_ok=True)

    print(f"Target: {TARGET_DOMAIN}")
    print(f"Work dir: {WORK_DIR}")
    print()

    # Phase 1: Subdomain enumeration
    print("=" * 60)
    print("PHASE 1: Subdomain Enumeration (subfinder)")
    print("=" * 60)
    subfinder_tool = SubfinderTool(runner=runner, db=db, program=PROGRAM)
    sub_result = await subfinder_tool.run(TARGET_DOMAIN)
    subdomains = sub_result.get("domains", [])
    print(f"  Subdomains found: {sub_result.get('total', 0)}")
    if subdomains:
        for sd in subdomains[:20]:
            print(f"    - {sd}")
        if len(subdomains) > 20:
            print(f"    ... and {len(subdomains) - 20} more")
    print()

    # Phase 2: Service discovery (httpx)
    print("=" * 60)
    print("PHASE 2: Service Discovery (httpx)")
    print("=" * 60)
    httpx_tool = HttpxTool(runner=runner, db=db, program=PROGRAM)
    # Probe the main domain + any discovered subdomains
    targets_to_probe = [TARGET_URL] + [f"https://{sd}" for sd in subdomains if sd != TARGET_DOMAIN]
    httpx_result = await httpx_tool.run(targets_to_probe, work_dir=WORK_DIR / "recon")
    print(f"  Live services: {httpx_result['live']}")
    print(f"  Technologies: {httpx_result.get('technologies', {})}")
    if httpx_result.get("services"):
        for svc in httpx_result["services"][:10]:
            print(f"    - {svc}")
    print()

    # Phase 3: Nuclei vulnerability scan
    print("=" * 60)
    print("PHASE 3: Vulnerability Scanning (nuclei)")
    print("=" * 60)
    nuclei_tool = NucleiTool(runner=runner, db=db, program=PROGRAM)
    techs = list(httpx_result.get("technologies", {}).keys())
    scan_opts = nuclei_tool.select_scan_options(techs)
    print(f"  Scan config: severity=info-critical, rate_limit={RPS}, tags={scan_opts.get('tags')}")

    # Build target list from live services
    nuclei_targets = []
    if httpx_result.get("services"):
        nuclei_targets = [s if "://" in s else f"https://{s}" for s in httpx_result["services"]]
    else:
        nuclei_targets = [TARGET_URL]

    nuclei_result = await nuclei_tool.run(
        targets=nuclei_targets,
        work_dir=WORK_DIR / "scan",
        severity="info,low,medium,high,critical",
        rate_limit=RPS,
    )
    print(f"  Findings: {nuclei_result['total']}")
    if nuclei_result.get("by_severity"):
        for sev, count in nuclei_result["by_severity"].items():
            print(f"    {sev}: {count}")
    print()

    # Phase 4: Directory fuzzing (ffuf)
    print("=" * 60)
    print("PHASE 4: Directory Fuzzing (ffuf)")
    print("=" * 60)
    ffuf_tool = FfufTool(runner=runner, db=db, program=PROGRAM)
    wordlist = WORK_DIR / "fuzz" / "wordlist.txt"
    wordlist.write_text("\n".join([
        "api", "admin", "login", "register", "dashboard", "docs",
        ".env", ".git", ".gitignore", "backup", "config", "debug",
        "robots.txt", "sitemap.xml", "security.txt", ".well-known",
        "swagger", "api-docs", "graphql", "health", "metrics", "status",
        "static", "assets", "uploads", "media", "images", "public",
        "wp-admin", "wp-login", "wp-content", "xmlrpc.php",
        "server-status", "server-info", "phpinfo.php", "info.php",
        "actuator", "console", "monitor", "trace",
        "v1", "v2", "api/v1", "api/v2",
        "auth", "oauth", "token", "callback",
        "test", "staging", "dev", "internal",
        "db", "database", "sql", "phpmyadmin",
        "cgi-bin", "scripts", "includes", "tmp",
    ]) + "\n")
    ffuf_result = await ffuf_tool.run(
        target_url=f"{TARGET_URL}/FUZZ",
        wordlist=str(wordlist),
    )
    print(f"  Paths found: {ffuf_result['total']}")
    print(f"  Interesting: {ffuf_result.get('interesting', 0)}")
    if ffuf_result.get("results"):
        for r in ffuf_result["results"][:15]:
            print(f"    [{r.get('status', '?')}] {r.get('url', '?')}")
        if len(ffuf_result["results"]) > 15:
            print(f"    ... and {len(ffuf_result['results']) - 15} more")
    print()

    # Phase 5: Validate findings
    print("=" * 60)
    print("PHASE 5: Finding Validation")
    print("=" * 60)
    fv = FindingValidator(runner=runner, db=db)
    val_results = await fv.validate_findings(PROGRAM)
    summary = fv.get_summary(val_results)
    print(f"  Total re-tested: {summary['total']}")
    print(f"  By status: {summary.get('by_status', {})}")
    print()

    # Phase 6: Generate report
    print("=" * 60)
    print("PHASE 6: Report Generation")
    print("=" * 60)
    reporter = ReportGenerator(db=db)
    report = await reporter.generate(PROGRAM)
    report_path = await reporter.save(PROGRAM, output_dir=WORK_DIR / "reports")
    print(f"  Report saved to: {report_path}")
    print()

    # Print full report
    print("=" * 60)
    print("FULL REPORT")
    print("=" * 60)
    print(report)

    # Print all findings
    print()
    print("=" * 60)
    print("ALL FINDINGS (raw)")
    print("=" * 60)
    all_findings = await db.get_findings(PROGRAM)
    if not all_findings:
        print("  No findings.")
    for f in all_findings:
        print(f"  [{f['severity'].upper():8s}] [{f['status']:15s}] {f['vuln_type']}")
        print(f"           URL: {f['url']}")
        print(f"           Tool: {f['tool']} | Confidence: {f['confidence']:.0%}")
        if f.get("evidence"):
            print(f"           Evidence: {f['evidence'][:200]}")
        print()

    await db.close()
    print(f"\nDatabase saved at: {WORK_DIR / 'findings.db'}")


if __name__ == "__main__":
    asyncio.run(main())
