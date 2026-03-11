# Phase 5B: Tool Cleanup + High-Value Additions

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove abandoned/stale tools with actively maintained replacements, add high-value missing integrations (jsluice, clairvoyance, WCVS, cewler, subzy), replace qsreplace with native Python, enhance existing tool wrappers (sqlmap/dalfox/ffuf), and update agent prompts to use nuclei templates instead of stale single-purpose scanners.

**Architecture:** Dead tool wrappers are deleted and their functionality replaced by either nuclei templates (agent intelligence, not code) or actively maintained alternatives. New tools follow the established wrapper pattern. qsreplace becomes a pure-Python utility (no subprocess).

**Tech Stack:** Python 3.13+, existing bba modules

**Depends on:** Phase 5A should be completed first (hardened tool_runner, adaptive rate limiter).

---

## Tool Audit Summary (Web-Verified March 2026)

### Removals (abandoned/stale with better alternatives)

| Tool | Status | Replacement |
|------|--------|-------------|
| subjack | ABANDONED (archived Jan 2024) | subzy (PentestPad, active) + nuclei takeover templates |
| kiterunner | STALE (last release Apr 2021) | feroxbuster + ffuf with API wordlists |
| LinkFinder | ABANDONED (~2020) | jsluice (BishopFox, active) |
| SecretFinder | ABANDONED (~2021) | jsluice + trufflehog |
| cloud_enum | ABANDONED (author says "no longer use it") | nuclei cloud templates |
| GitDorker | STALE (~2021) | trufflehog --github |
| CORScanner | STALE (~2021) | nuclei CORS templates |
| smuggler | STALE (~2021) | nuclei HTTP smuggling templates |
| getJS | STALE (Jul 2024) | katana JS extraction + jsluice |
| qsreplace | STALE (~2020) | Native Python (no external dep needed) |

### Additions (actively maintained, verified)

| Tool | Version | Last Activity | Stars |
|------|---------|---------------|-------|
| jsluice (BishopFox) | Jan 2025 | Active | 1.8k |
| clairvoyance | v2.5.5 Dec 2025 | Active | 1.3k |
| WCVS (Hackmanit) | v2.0.0 Aug 2025 | Active | 1.2k |
| cewler | v1.4.1 Jan 2026 | Active | 144 |
| subzy (PentestPad) | Sep 2024 | Active | 1.5k |

### Dropped from original plan (stale)

| Tool | Reason |
|------|--------|
| GraphQLmap | Stale 1+ year, clairvoyance covers GraphQL |
| CMSeeK | Stale since Aug 2023, nuclei CMS templates instead |
| OpenRedireX | Stale since Aug 2023, nuclei redirect templates instead |
| SSRFmap | Stale since 2022, no good CLI alternative — leave for manual testing |

---

## File Structure

```
src/bba/tools/
    qsreplace.py         # REWRITE — pure Python, no subprocess
    jsluice.py           # CREATE — JS URL/path/secret extraction (replaces linkfinder/secretfinder)
    clairvoyance.py      # CREATE — GraphQL schema reconstruction
    cache_scanner.py     # CREATE — Web cache poisoning/deception (WCVS)
    cewler.py            # CREATE — Custom wordlist from target content
    subzy.py             # CREATE — Subdomain takeover detection (replaces subjack)
    sqlmap_runner.py     # MODIFY — add --tamper, --header, --cookie, --data flags
    dalfox.py            # MODIFY — add pipe mode for mass scanning
    ffuf.py              # MODIFY — add recursive mode, custom matchers

DELETE:
    subjack.py           # ABANDONED — replaced by subzy
    kiterunner.py        # STALE — replaced by feroxbuster/ffuf
    linkfinder.py        # ABANDONED — replaced by jsluice
    secretfinder.py      # ABANDONED — replaced by jsluice
    cloudenum.py         # ABANDONED — replaced by nuclei templates
    github_dorker.py     # STALE — replaced by trufflehog
    corscanner.py        # STALE — replaced by nuclei templates
    smuggler.py          # STALE — replaced by nuclei templates
    getjs.py             # STALE — replaced by katana + jsluice

tests/
    DELETE: test_tools_subjack.py, test_tools_kiterunner.py, test_tools_linkfinder.py,
            test_tools_secretfinder.py, test_tools_cloudenum.py, test_tools_github_dorker.py,
            test_tools_corscanner.py, test_tools_smuggler.py, test_tools_getjs.py,
            test_tools_qsreplace.py (rewrite)
    CREATE: test_tools_jsluice.py, test_tools_clairvoyance.py, test_tools_cache_scanner.py,
            test_tools_cewler.py, test_tools_subzy.py, test_qsreplace_native.py
```

---

## Chunk 1: Dead Tool Removal + qsreplace Native Rewrite

### Task 1: Remove Abandoned Tool Wrappers

Delete 9 tool wrappers and their tests that have been replaced by actively maintained alternatives.

**Files:**
- Delete: `src/bba/tools/subjack.py`, `src/bba/tools/kiterunner.py`, `src/bba/tools/linkfinder.py`, `src/bba/tools/secretfinder.py`, `src/bba/tools/cloudenum.py`, `src/bba/tools/github_dorker.py`, `src/bba/tools/corscanner.py`, `src/bba/tools/smuggler.py`, `src/bba/tools/getjs.py`
- Delete: corresponding test files
- Modify: `src/bba/cli.py` — remove subparsers and handlers for deleted tools
- Modify: `scripts/install-tools.sh` — remove install commands for deleted tools

- [ ] **Step 1: Delete tool wrapper files**

```bash
rm src/bba/tools/subjack.py src/bba/tools/kiterunner.py src/bba/tools/linkfinder.py \
   src/bba/tools/secretfinder.py src/bba/tools/cloudenum.py src/bba/tools/github_dorker.py \
   src/bba/tools/corscanner.py src/bba/tools/smuggler.py src/bba/tools/getjs.py
```

- [ ] **Step 2: Delete corresponding test files**

```bash
rm tests/test_tools_subjack.py tests/test_tools_kiterunner.py tests/test_tools_linkfinder.py \
   tests/test_tools_secretfinder.py tests/test_tools_cloudenum.py tests/test_tools_github_dorker.py \
   tests/test_tools_corscanner.py tests/test_tools_smuggler.py tests/test_tools_getjs.py
```

- [ ] **Step 3: Remove CLI subparsers and handlers for deleted tools**

In `src/bba/cli.py`, remove the argument parser registrations and `cmd_*` handler functions for: subjack, kiterunner, linkfinder, secretfinder, cloud-enum, github-dork, corscanner, smuggler, getjs.

- [ ] **Step 4: Remove install commands from scripts/install-tools.sh**

Remove install lines for: subjack, kiterunner, LinkFinder, SecretFinder, cloud_enum, GitDorker, CORScanner, smuggler, getJS.

- [ ] **Step 5: Run tests to verify nothing breaks**

Run: `uv run python -m pytest tests/ --ignore=tests/integration -q`
Expected: All remaining tests pass (count will be lower due to deleted test files)

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: remove 9 abandoned/stale tool wrappers (subjack, kiterunner, linkfinder, secretfinder, cloud_enum, gitdorker, corscanner, smuggler, getjs)"
```

---

### Task 2: Rewrite qsreplace as Pure Python

Replace the external `qsreplace` binary dependency with a native Python implementation. This eliminates the shell injection vulnerability, removes a stale dependency, and is faster (no subprocess spawn).

**Files:**
- Rewrite: `src/bba/tools/qsreplace.py`
- Rewrite: `tests/test_tools_qsreplace.py`
- Modify: `src/bba/cli.py` — update handler to use new API
- Modify: `scripts/install-tools.sh` — remove qsreplace install

- [ ] **Step 1: Write tests for native implementation**

```python
# tests/test_tools_qsreplace.py
import pytest
from bba.tools.qsreplace import QsreplaceTool


class TestQsreplaceTool:
    def test_replace_single_param(self):
        tool = QsreplaceTool()
        result = tool.replace("https://example.com/page?id=123", "FUZZ")
        assert result == "https://example.com/page?id=FUZZ"

    def test_replace_multiple_params(self):
        tool = QsreplaceTool()
        result = tool.replace("https://example.com/search?q=test&page=1&lang=en", "PAYLOAD")
        assert "q=PAYLOAD" in result
        assert "page=PAYLOAD" in result
        assert "lang=PAYLOAD" in result

    def test_no_params_returns_none(self):
        tool = QsreplaceTool()
        result = tool.replace("https://example.com/page", "FUZZ")
        assert result is None

    def test_empty_param_value(self):
        tool = QsreplaceTool()
        result = tool.replace("https://example.com/page?id=", "FUZZ")
        assert result == "https://example.com/page?id=FUZZ"

    def test_preserves_path_and_fragment(self):
        tool = QsreplaceTool()
        result = tool.replace("https://example.com/api/v1?token=abc#section", "REPLACED")
        assert "/api/v1" in result
        assert "token=REPLACED" in result

    def test_shell_metacharacters_safe(self):
        """Payload with shell metacharacters must be handled safely."""
        tool = QsreplaceTool()
        payload = "'; rm -rf /; echo '"
        result = tool.replace("https://example.com/page?id=1", payload)
        assert payload in result  # Literal string, no shell interpretation

    def test_batch_replace(self):
        tool = QsreplaceTool()
        urls = [
            "https://example.com/a?id=1",
            "https://example.com/b?name=foo&age=30",
            "https://example.com/c",  # no params
        ]
        results = tool.batch_replace(urls, "XSS")
        assert len(results) == 2  # URL without params excluded
        assert all("XSS" in r for r in results)

    def test_deduplicates_results(self):
        tool = QsreplaceTool()
        urls = [
            "https://example.com/a?id=1",
            "https://example.com/a?id=2",
            "https://example.com/a?id=3",
        ]
        results = tool.batch_replace(urls, "FUZZ")
        # All produce same output: ?id=FUZZ — should deduplicate
        assert len(results) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_tools_qsreplace.py -v`
Expected: FAIL

- [ ] **Step 3: Implement native QsreplaceTool**

```python
# src/bba/tools/qsreplace.py
"""Query string parameter replacement — pure Python, no external dependency."""
from __future__ import annotations

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class QsreplaceTool:
    """Replace all query string parameter values with a given payload.

    Pure Python implementation — no subprocess, no shell, no external binary.
    """

    def replace(self, url: str, payload: str) -> str | None:
        """Replace all query param values in url with payload. Returns None if no params."""
        parsed = urlparse(url)
        if not parsed.query:
            return None
        params = parse_qs(parsed.query, keep_blank_values=True)
        replaced = {k: [payload] for k in params}
        new_query = urlencode(replaced, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def batch_replace(self, urls: list[str], payload: str) -> list[str]:
        """Replace params in all URLs, deduplicate results."""
        seen: set[str] = set()
        results: list[str] = []
        for url in urls:
            replaced = self.replace(url, payload)
            if replaced and replaced not in seen:
                seen.add(replaced)
                results.append(replaced)
        return results
```

- [ ] **Step 4: Update CLI handler**

Replace the async `cmd_recon_qsreplace` handler in `cli.py` to use the new synchronous API:

```python
async def cmd_recon_qsreplace(args):
    from bba.tools.qsreplace import QsreplaceTool
    tool = QsreplaceTool()
    urls = Path(args.targets).read_text().strip().splitlines()
    results = tool.batch_replace(urls, args.payload)
    print(json.dumps({"total": len(results), "urls": results, "payload": args.payload}))
```

- [ ] **Step 5: Remove qsreplace from install script**

- [ ] **Step 6: Run tests**

Run: `uv run python -m pytest tests/test_tools_qsreplace.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/bba/tools/qsreplace.py tests/test_tools_qsreplace.py src/bba/cli.py scripts/install-tools.sh
git commit -m "refactor: replace qsreplace binary with native Python implementation (fixes shell injection)"
```

---

## Chunk 2: New Tool Integrations

### Task 3: jsluice — Superior JS Analysis (replaces LinkFinder + SecretFinder + getJS)

`jsluice` extracts URLs, paths, secrets from JavaScript files using AST analysis (not regex). Far more accurate than the 3 tools it replaces. Go binary from BishopFox, actively maintained.

**Files:**
- Create: `src/bba/tools/jsluice.py`
- Create: `tests/test_tools_jsluice.py`

```python
# src/bba/tools/jsluice.py
"""JavaScript URL/path/secret extraction via jsluice (AST-based)."""
from __future__ import annotations
import json
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class JsluiceTool:
    """Extract URLs, paths, and secrets from JS files using AST analysis."""

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command_urls(self, js_file: str) -> list[str]:
        return ["jsluice", "urls", "-R", js_file]

    def build_command_secrets(self, js_file: str) -> list[str]:
        return ["jsluice", "secrets", js_file]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            if not line.strip():
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results

    async def run_urls(self, js_url: str, domain: str) -> dict:
        result = await self.runner.run_command(
            tool="jsluice", command=self.build_command_urls(js_url),
            targets=[domain], timeout=60,
        )
        if not result.success:
            return {"total": 0, "urls": [], "error": result.error}
        entries = self.parse_output(result.output)
        urls = [e.get("url", "") for e in entries if e.get("url")]
        if urls:
            await self.db.add_urls_bulk(self.program, urls, "jsluice")
        return {"total": len(urls), "urls": urls, "source": js_url}

    async def run_secrets(self, js_url: str, domain: str) -> dict:
        result = await self.runner.run_command(
            tool="jsluice", command=self.build_command_secrets(js_url),
            targets=[domain], timeout=60,
        )
        if not result.success:
            return {"total": 0, "secrets": [], "error": result.error}
        entries = self.parse_output(result.output)
        for entry in entries:
            kind = entry.get("kind", "unknown")
            data = json.dumps(entry.get("data", {}))
            await self.db.add_secret(
                program=self.program, secret_type=kind, value=data,
                source_url=js_url, source_file="", tool="jsluice",
                confidence=0.8,
            )
        return {"total": len(entries), "secrets": entries, "source": js_url}
```

Tests: build_command_urls, build_command_secrets, parse_output JSON, run_urls stores in DB, run_secrets stores secrets, handles failure.

- [ ] Implement + test + commit: `feat: add jsluice JS analysis tool (replaces linkfinder, secretfinder, getjs)`

---

### Task 4: subzy — Subdomain Takeover Detection (replaces subjack)

`subzy` checks for subdomain takeover vulnerabilities. Actively maintained by PentestPad, replaces the archived subjack.

**Files:**
- Create: `src/bba/tools/subzy.py`
- Create: `tests/test_tools_subzy.py`

```python
# src/bba/tools/subzy.py
"""Subdomain takeover detection via subzy (replaces archived subjack)."""
from __future__ import annotations
import json
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner


class SubzyTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, targets: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "subzy_targets.txt"
        input_file.write_text("\n".join(targets) + "\n")
        return ["subzy", "run", "--targets", str(input_file), "--output", "json"]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                if entry.get("vulnerable"):
                    results.append(entry)
            except json.JSONDecodeError:
                continue
        return results

    async def run(self, targets: list[str], work_dir: Path) -> dict:
        domains = [t for t in targets if not t.startswith("http")]
        result = await self.runner.run_command(
            tool="subzy", command=self.build_command(targets, work_dir),
            targets=domains or targets, timeout=300,
        )
        if not result.success:
            return {"total": 0, "vulnerable": [], "error": result.error}
        vulns = self.parse_output(result.output)
        for v in vulns:
            domain = v.get("subdomain", "")
            service = v.get("service", "unknown")
            await self.db.add_finding(
                program=self.program, domain=domain, url=f"https://{domain}",
                vuln_type="subdomain-takeover", severity="high", tool="subzy",
                evidence=f"Service: {service}. CNAME: {v.get('cname', '')}",
                confidence=0.9,
            )
        return {"total": len(vulns), "vulnerable": vulns, "scanned": len(targets)}
```

- [ ] Implement + test + commit: `feat: add subzy subdomain takeover tool (replaces archived subjack)`

---

### Task 5: clairvoyance — GraphQL Schema Reconstruction

When introspection is disabled, `clairvoyance` reconstructs the schema by brute-forcing field names. Actively maintained (v2.5.5 Dec 2025).

**Files:**
- Create: `src/bba/tools/clairvoyance.py`
- Create: `tests/test_tools_clairvoyance.py`

```python
# src/bba/tools/clairvoyance.py
"""GraphQL schema reconstruction when introspection is disabled."""
from __future__ import annotations
import json
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class ClairvoyanceTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str, wordlist: str | None = None) -> list[str]:
        cmd = ["clairvoyance", "-u", url, "-o", "-"]
        if wordlist:
            cmd.extend(["-w", wordlist])
        return cmd

    def parse_output(self, output: str) -> dict:
        try:
            schema = json.loads(output)
            types = schema.get("data", {}).get("__schema", {}).get("types", [])
            return {"schema": schema, "type_count": len(types)}
        except json.JSONDecodeError:
            return {"schema": None, "type_count": 0, "raw": output[:2000]}

    async def run(self, url: str, wordlist: str | None = None) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="clairvoyance", command=self.build_command(url, wordlist),
            targets=[domain] if domain else [url], timeout=300,
        )
        if not result.success:
            return {"success": False, "url": url, "error": result.error}
        parsed_result = self.parse_output(result.output)
        if parsed_result["type_count"] > 0:
            await self.db.log_action(
                "graphql_schema_reconstructed", "clairvoyance", url,
                f"Reconstructed {parsed_result['type_count']} types",
            )
        return {"success": parsed_result["type_count"] > 0, "url": url,
                "types_found": parsed_result["type_count"]}
```

- [ ] Implement + test + commit: `feat: add clairvoyance GraphQL schema reconstruction`

---

### Task 6: Web Cache Vulnerability Scanner (WCVS)

Tests for cache poisoning and cache deception. Actively maintained by Hackmanit GmbH (v2.0.0 rewrite Aug 2025).

**Files:**
- Create: `src/bba/tools/cache_scanner.py`
- Create: `tests/test_tools_cache_scanner.py`

```python
# src/bba/tools/cache_scanner.py
"""Web cache poisoning and deception detection via WCVS."""
from __future__ import annotations
import re
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

_VULN_PATTERN = re.compile(r"(?:VULNERABLE|POISONED|CACHED|cache.*(?:hit|poison|decept))", re.I)
_TECHNIQUE_PATTERN = re.compile(r"(?:technique|method|header):\s*(.+)", re.I)


class CacheScannerTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["Web-Cache-Vulnerability-Scanner", "-u", url, "-v"]

    def parse_output(self, output: str) -> list[dict]:
        findings = []
        for line in output.strip().splitlines():
            if _VULN_PATTERN.search(line):
                technique = _TECHNIQUE_PATTERN.search(line)
                findings.append({
                    "detail": line.strip(),
                    "technique": technique.group(1).strip() if technique else "unknown",
                })
        return findings

    async def run(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="cache-scanner", command=self.build_command(url),
            targets=[domain] if domain else [url], timeout=180,
        )
        if not result.success:
            return {"vulnerable": False, "url": url, "error": result.error}
        findings = self.parse_output(result.output)
        for f in findings:
            await self.db.add_finding(
                program=self.program, domain=domain, url=url,
                vuln_type="cache-poisoning", severity="high",
                tool="cache-scanner", evidence=f["detail"][:2000],
                confidence=0.8,
            )
        return {"vulnerable": bool(findings), "url": url, "findings": findings}
```

- [ ] Implement + test + commit: `feat: add web cache vulnerability scanner (WCVS)`

---

### Task 7: cewler — Custom Wordlist Generation

Crawls a website and generates a custom wordlist from its content. Actively maintained (v1.4.1 Jan 2026).

**Files:**
- Create: `src/bba/tools/cewler.py`
- Create: `tests/test_tools_cewler.py`

```python
# src/bba/tools/cewler.py
"""Custom wordlist generation from target content via cewler."""
from __future__ import annotations
from pathlib import Path
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class CewlerTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str, depth: int = 2, output_file: str | None = None) -> list[str]:
        cmd = ["cewler", "-u", url, "-d", str(depth)]
        if output_file:
            cmd.extend(["-o", output_file])
        return cmd

    def parse_output(self, output: str) -> list[str]:
        return [w.strip() for w in output.strip().splitlines() if w.strip() and len(w.strip()) > 2]

    async def run(self, url: str, work_dir: Path, depth: int = 2) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        output_file = work_dir / f"cewler_{domain}.txt"
        result = await self.runner.run_command(
            tool="cewler", command=self.build_command(url, depth, str(output_file)),
            targets=[domain] if domain else [url], timeout=120,
        )
        if not result.success:
            return {"total": 0, "wordlist": None, "error": result.error}
        words = self.parse_output(result.output)
        if output_file.exists():
            words = [w.strip() for w in output_file.read_text().splitlines() if w.strip()]
        return {"total": len(words), "wordlist": str(output_file) if output_file.exists() else None,
                "sample": words[:20], "url": url}
```

- [ ] Implement + test + commit: `feat: add cewler custom wordlist generation`

---

## Chunk 3: Enhance Existing Tool Wrappers

### Task 8: Enhance sqlmap with WAF Bypass Flags

**Files:**
- Modify: `src/bba/tools/sqlmap_runner.py`

Add `--tamper`, `--headers`, `--cookie`, `--data`, `--method` parameters:

```python
def build_command(self, target_url: str, tamper: str | None = None,
                  headers: str | None = None, cookie: str | None = None,
                  data: str | None = None, method: str | None = None) -> list[str]:
    cmd = ["sqlmap", "-u", target_url, "--batch", "--level=2", "--risk=2"]
    if tamper:
        cmd.extend(["--tamper", tamper])
    if headers:
        cmd.extend(["--headers", headers])
    if cookie:
        cmd.extend(["--cookie", cookie])
    if data:
        cmd.extend(["--data", data])
    if method:
        cmd.extend(["--method", method])
    return cmd
```

- [ ] Test + commit: `feat: add WAF bypass flags to sqlmap wrapper`

---

### Task 9: Enhance dalfox with Pipe Mode

Add pipe mode for mass scanning — reads URLs from stdin:

```python
def build_command_pipe(self, work_dir: Path) -> list[str]:
    """Build command for pipe mode — reads URLs from stdin."""
    return ["dalfox", "pipe", "--silence", "--format", "json"]
```

- [ ] Test + commit: `feat: add pipe mode to dalfox for mass XSS scanning`

---

### Task 10: Enhance ffuf with Recursive Mode

Add `-recursion`, `-recursion-depth`, `-mc` (match codes), `-fc` (filter codes):

```python
def build_command(self, ..., recursive: bool = False, recursion_depth: int = 2,
                  match_codes: str | None = None, filter_codes: str | None = None):
    if recursive:
        cmd.extend(["-recursion", "-recursion-depth", str(recursion_depth)])
    if match_codes:
        cmd.extend(["-mc", match_codes])
    if filter_codes:
        cmd.extend(["-fc", filter_codes])
```

- [ ] Test + commit: `feat: add recursive mode and custom matchers to ffuf`

---

## Chunk 4: CLI + Install + Agent Prompt Updates

### Task 11: CLI Commands + Install Script for New Tools

**Files:**
- Modify: `src/bba/cli.py` — add subparsers for jsluice, subzy, clairvoyance, cache-scanner, cewler
- Modify: `scripts/install-tools.sh` — add install commands, remove dead tools

```bash
# New installs
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
go install github.com/PentestPad/subzy@latest
pip install clairvoyance
go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest
pip install cewler

# Remove dead tool installs
# (delete lines for: subjack, kiterunner, LinkFinder, SecretFinder, cloud_enum,
#  GitDorker, CORScanner, smuggler, getJS, qsreplace)
```

- [ ] Test + commit: `feat: add CLI commands and installers for Phase 5B tools`

---

### Task 12: Update Agent Prompts — Replace Stale Tools with Nuclei Templates

**Files:**
- Modify: `.claude/agents/scanner.md`
- Modify: `.claude/agents/vuln-tester.md`
- Modify: `.claude/agents/recon.md`
- Modify: `CLAUDE.md`

Key changes:
1. Replace `corscanner` references with `nuclei -tags cors`
2. Replace `smuggler` references with `nuclei -tags http-smuggling`
3. Replace `linkfinder`/`secretfinder`/`getjs` references with `jsluice`
4. Replace `subjack` references with `subzy`
5. Add `clairvoyance` to GraphQL testing pipeline
6. Add `cache-scanner` to scanner agent
7. Add `cewler` to recon agent for target-specific wordlists
8. Update CLAUDE.md CLI reference (remove dead commands, add new ones)
9. Replace `cloud-enum` references with nuclei cloud templates
10. Add nuclei template categories for: CMS detection (`-tags cms`), CORS (`-tags cors`), CRLF (`-tags crlf`), HTTP smuggling (`-tags http-smuggling`), open redirect (`-tags redirect`)

- [ ] Commit: `docs: update agent prompts to use active tools, replace stale tools with nuclei templates`

---

## Summary

| Task | Action | Impact |
|------|--------|--------|
| 1 | Remove 9 dead tool wrappers | CLEANUP — eliminate abandoned dependencies |
| 2 | Rewrite qsreplace as pure Python | SECURITY + CLEANUP — fix shell injection, drop stale dep |
| 3 | Add jsluice | HIGH VALUE — replaces 3 stale tools with 1 active one |
| 4 | Add subzy | REQUIRED — replaces archived subjack |
| 5 | Add clairvoyance | HIGH VALUE — GraphQL schema extraction |
| 6 | Add WCVS cache scanner | HIGH VALUE — underexploited vuln class |
| 7 | Add cewler | MEDIUM — target-specific wordlists |
| 8 | Enhance sqlmap | MEDIUM — WAF bypass capability |
| 9 | Enhance dalfox | MEDIUM — mass scanning mode |
| 10 | Enhance ffuf | MEDIUM — recursive discovery |
| 11 | CLI + install for new tools | INTEGRATION |
| 12 | Update agent prompts | INTELLIGENCE — agents use active tools |

### Net Change
- **Removed:** 10 stale/abandoned tools (subjack, kiterunner, linkfinder, secretfinder, cloud_enum, gitdorker, corscanner, smuggler, getjs, qsreplace binary)
- **Added:** 5 actively maintained tools (jsluice, subzy, clairvoyance, WCVS, cewler)
- **Rewritten:** 1 (qsreplace → native Python)
- **Enhanced:** 3 (sqlmap, dalfox, ffuf)
- **Replaced by nuclei templates:** CORS, CRLF, HTTP smuggling, open redirect, CMS detection, subdomain takeover (supplemental)
