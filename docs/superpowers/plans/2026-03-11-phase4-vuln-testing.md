# Phase 4: Vulnerability Testing by Category — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add category-specific vulnerability testing pipelines covering XSS, SQLi, SSRF, SSTI, command injection, CRLF, CORS, JWT, HTTP smuggling, NoSQLi, prototype pollution, open redirect, LFI, 403 bypass, and more — orchestrated by a new vuln-tester agent that reasons about which categories apply to each target.

**Architecture:** 12 new tool wrappers follow the existing pattern (build_command → parse_output → run → store findings). 2 pipeline utility tools (uro, qsreplace) provide URL deduplication and payload injection. A new vuln-tester agent receives classified URLs + tech profiles and dispatches category-specific testing pipelines with explicit reasoning. Enhanced gf_patterns covers all vulnerability categories. The coordinator gains a Phase 4 stage between scanning and deep-dive.

**Tech Stack:** Python 3.13+, existing bba modules (ToolRunner, Database, ScopeConfig), pytest with unittest.mock

---

## File Structure

```
src/bba/tools/
    uro.py              # URL deduplication utility
    qsreplace.py        # Query string payload injection
    crlfuzz.py          # CRLF injection scanner
    sstimap.py          # SSTI detection
    commix.py           # Command injection
    ghauri.py           # Advanced SQLi (complement to sqlmap)
    nosqli.py           # NoSQL injection
    xsstrike.py         # XSS detection (complement to dalfox)
    corscanner.py       # CORS misconfiguration
    jwt_tool.py         # JWT vulnerability testing
    smuggler.py         # HTTP request smuggling
    ppfuzz.py           # Prototype pollution
    gf_patterns.py      # MODIFY — add ssti, cmdi, crlf, jwt, cors, xxe, prototype-pollution patterns

src/bba/cli.py          # MODIFY — add subparsers for all 12 new tools

.claude/agents/vuln-tester.md   # New agent — category-specific vuln testing
.claude/commands/scan-target.md  # MODIFY — add Phase 4 vuln testing stage

scripts/install-tools.sh  # MODIFY — add installation for new tools

tests/
    test_tools_uro.py
    test_tools_qsreplace.py
    test_tools_crlfuzz.py
    test_tools_sstimap.py
    test_tools_commix.py
    test_tools_ghauri.py
    test_tools_nosqli.py
    test_tools_xsstrike.py
    test_tools_corscanner.py
    test_tools_jwt_tool.py
    test_tools_smuggler.py
    test_tools_ppfuzz.py
```

---

## Chunk 1: Pipeline Utilities & Enhanced GF Patterns

### Task 1: URL Deduplication Utility (uro)

`uro` removes duplicate/similar URLs by normalizing query parameters, removing tracking params, and collapsing similar paths. It's a Python pip package (`pip install uro`).

**Files:**
- Create: `src/bba/tools/uro.py`
- Test: `tests/test_tools_uro.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tools_uro.py
from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, patch
from bba.tools.uro import UroTool
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import OutputSanitizer

SCOPE = {"program": "test-corp", "domains": ["*.example.com"], "cidrs": [], "exclude": []}

@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))

@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(), sanitizer=OutputSanitizer(), output_dir=tmp_path / "output")

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()

class TestUroTool:
    def test_build_command(self, runner, db, tmp_path):
        tool = UroTool(runner=runner, db=db, program="test-corp")
        urls = ["https://example.com/a?id=1", "https://example.com/a?id=2"]
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        cmd = tool.build_command(urls, work_dir)
        assert cmd[0] == "uro"
        assert "-i" in cmd

    def test_parse_output(self, runner, db):
        tool = UroTool(runner=runner, db=db, program="test-corp")
        output = "https://example.com/a?id=1\nhttps://example.com/b?name=test\n"
        result = tool.parse_output(output)
        assert len(result) == 2
        assert "https://example.com/a?id=1" in result

    def test_parse_empty_output(self, runner, db):
        tool = UroTool(runner=runner, db=db, program="test-corp")
        assert tool.parse_output("") == []
        assert tool.parse_output("\n\n") == []

    @pytest.mark.asyncio
    async def test_run_returns_deduped_urls(self, runner, db, tmp_path):
        tool = UroTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output="https://example.com/a?id=1\nhttps://example.com/b\n", raw_file=None, error=None, duration=1.0)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run(["https://example.com/a?id=1", "https://example.com/a?id=2", "https://example.com/b"], tmp_path)
        assert result["total"] == 2
        assert "https://example.com/a?id=1" in result["urls"]

    @pytest.mark.asyncio
    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = UroTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", raw_file=None, error="crash", duration=0.1)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run(["https://example.com/a"], tmp_path)
        assert result["total"] == 0
        assert "error" in result
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_tools_uro.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'bba.tools.uro'`

- [ ] **Step 3: Write implementation**

```python
# src/bba/tools/uro.py
"""URL deduplication via uro — removes duplicate/similar URLs."""
from __future__ import annotations
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner


class UroTool:
    """Deduplicate URLs by normalizing query params and collapsing similar paths."""

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, urls: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "uro_input.txt"
        input_file.write_text("\n".join(urls) + "\n")
        return ["uro", "-i", str(input_file)]

    def parse_output(self, output: str) -> list[str]:
        return [line.strip() for line in output.strip().splitlines() if line.strip()]

    async def run(self, urls: list[str], work_dir: Path) -> dict:
        if not urls:
            return {"total": 0, "urls": [], "original_count": 0}
        domains = list({u.split("/")[2] for u in urls if "://" in u})
        result = await self.runner.run_command(
            tool="uro", command=self.build_command(urls, work_dir),
            targets=domains or ["unknown"], timeout=120,
        )
        if not result.success:
            return {"total": 0, "urls": [], "original_count": len(urls), "error": result.error}
        deduped = self.parse_output(result.output)
        return {"total": len(deduped), "urls": deduped, "original_count": len(urls), "reduced_by": len(urls) - len(deduped)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_tools_uro.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/bba/tools/uro.py tests/test_tools_uro.py
git commit -m "feat: add uro URL deduplication tool wrapper"
```

---

### Task 2: Query String Payload Injection (qsreplace)

`qsreplace` replaces all query string parameter values with a given payload. Go binary from tomnomnom.

**Files:**
- Create: `src/bba/tools/qsreplace.py`
- Test: `tests/test_tools_qsreplace.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tools_qsreplace.py
from __future__ import annotations
import pytest
from unittest.mock import patch
from bba.tools.qsreplace import QsreplaceTool
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import OutputSanitizer

SCOPE = {"program": "test-corp", "domains": ["*.example.com"], "cidrs": [], "exclude": []}

@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))

@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(), sanitizer=OutputSanitizer(), output_dir=tmp_path / "output")

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()

class TestQsreplaceTool:
    def test_build_command(self, runner, db, tmp_path):
        tool = QsreplaceTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        cmd = tool.build_command(["https://example.com/a?id=1"], "FUZZ", work_dir)
        assert cmd[0] == "qsreplace"
        assert "FUZZ" in cmd

    def test_parse_output(self, runner, db):
        tool = QsreplaceTool(runner=runner, db=db, program="test-corp")
        output = "https://example.com/a?id=FUZZ\nhttps://example.com/b?name=FUZZ\n"
        result = tool.parse_output(output)
        assert len(result) == 2

    def test_parse_empty(self, runner, db):
        tool = QsreplaceTool(runner=runner, db=db, program="test-corp")
        assert tool.parse_output("") == []

    @pytest.mark.asyncio
    async def test_run_replaces_params(self, runner, db, tmp_path):
        tool = QsreplaceTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output="https://example.com/a?id=PAYLOAD\n", raw_file=None, error=None, duration=0.5)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run(["https://example.com/a?id=1"], "PAYLOAD", tmp_path)
        assert result["total"] == 1
        assert "PAYLOAD" in result["urls"][0]

    @pytest.mark.asyncio
    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = QsreplaceTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", raw_file=None, error="not found", duration=0.1)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run(["https://example.com/a?id=1"], "FUZZ", tmp_path)
        assert result["total"] == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_tools_qsreplace.py -v`
Expected: FAIL

- [ ] **Step 3: Write implementation**

```python
# src/bba/tools/qsreplace.py
"""Query string parameter value replacement for payload injection pipelines."""
from __future__ import annotations
from pathlib import Path
from bba.db import Database
from bba.tool_runner import ToolRunner


class QsreplaceTool:
    """Replace all query string parameter values with a given payload."""

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, urls: list[str], payload: str, work_dir: Path) -> list[str]:
        input_file = work_dir / "qsreplace_input.txt"
        input_file.write_text("\n".join(urls) + "\n")
        return ["sh", "-c", f"cat {input_file} | qsreplace '{payload}'"]

    def parse_output(self, output: str) -> list[str]:
        return [line.strip() for line in output.strip().splitlines() if line.strip()]

    async def run(self, urls: list[str], payload: str, work_dir: Path) -> dict:
        if not urls:
            return {"total": 0, "urls": [], "payload": payload}
        domains = list({u.split("/")[2] for u in urls if "://" in u})
        result = await self.runner.run_command(
            tool="qsreplace", command=self.build_command(urls, payload, work_dir),
            targets=domains or ["unknown"], timeout=60,
        )
        if not result.success:
            return {"total": 0, "urls": [], "payload": payload, "error": result.error}
        replaced = self.parse_output(result.output)
        return {"total": len(replaced), "urls": replaced, "payload": payload}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_tools_qsreplace.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/bba/tools/qsreplace.py tests/test_tools_qsreplace.py
git commit -m "feat: add qsreplace payload injection tool wrapper"
```

---

### Task 3: Enhance GF Patterns with Full Vulnerability Categories

**Files:**
- Modify: `src/bba/tools/gf_patterns.py`
- Modify: `tests/test_tools_gf_patterns.py`

- [ ] **Step 1: Write failing tests for new patterns**

Add test cases for ssti, cmdi, crlf, cors, jwt, xxe, prototype-pollution, upload patterns to the existing test file.

```python
# Add to existing test file
def test_ssti_pattern(self, runner, db):
    tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
    urls = ["https://example.com/render?template=test", "https://example.com/page?name=hello"]
    result = tool.classify_urls(urls)
    assert len(result["ssti"]) >= 1

def test_cmdi_pattern(self, runner, db):
    tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
    urls = ["https://example.com/api?cmd=ls", "https://example.com/ping?ip=127.0.0.1"]
    result = tool.classify_urls(urls)
    assert len(result["cmdi"]) >= 1

def test_crlf_pattern(self, runner, db):
    tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
    urls = ["https://example.com/redirect?url=http://evil.com", "https://example.com/lang?locale=en"]
    result = tool.classify_urls(urls)
    assert len(result["crlf"]) >= 1

def test_cors_pattern(self, runner, db):
    tool = GfPatternsTool(runner=runner, db=db, program="test-corp")
    urls = ["https://example.com/api/data?callback=func", "https://example.com/jsonp?cb=test"]
    result = tool.classify_urls(urls)
    assert len(result["cors"]) >= 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_tools_gf_patterns.py -v`
Expected: FAIL — KeyError on new pattern names

- [ ] **Step 3: Add new patterns to PATTERNS dict**

Add to `src/bba/tools/gf_patterns.py` PATTERNS dict:

```python
"ssti": re.compile(
    r"[?&](template|render|preview|theme|view|layout|content|page|name|msg|text|body|title|desc|comment|input|field|data|value|expression|eval|output|display|format|engine|tpl|snippet)=",
    re.IGNORECASE,
),
"cmdi": re.compile(
    r"[?&](cmd|exec|command|execute|ping|query|jump|code|reg|do|func|arg|option|load|process|step|read|function|req|feature|exe|module|payload|run|print|daemon|upload|log|ip|cli|dir|address|host|port|timeout)=",
    re.IGNORECASE,
),
"crlf": re.compile(
    r"[?&](url|redirect|redir|return|next|dest|destination|rurl|out|view|target|to|goto|link|forward|continue|returnUrl|returnTo|location|locale|lang|origin|callback|path)=",
    re.IGNORECASE,
),
"cors": re.compile(
    r"[?&](callback|jsonp|cb|json_callback|jsonpcallback|_callback|api_callback|endpoint|origin)=",
    re.IGNORECASE,
),
"jwt": re.compile(
    r"[?&](token|jwt|auth_token|access_token|id_token|session_token|bearer|authorization)=",
    re.IGNORECASE,
),
"xxe": re.compile(
    r"[?&](xml|xmldata|soap|wsdl|content|data|payload|body|file|document|feed|rss|import|export|upload)=",
    re.IGNORECASE,
),
"prototype-pollution": re.compile(
    r"[?&](__proto__|constructor|prototype)[\[.=]",
    re.IGNORECASE,
),
"upload": re.compile(
    r"[?&](file|upload|attachment|document|image|img|photo|avatar|media|import)=",
    re.IGNORECASE,
),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run python -m pytest tests/test_tools_gf_patterns.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/bba/tools/gf_patterns.py tests/test_tools_gf_patterns.py
git commit -m "feat: expand gf patterns with ssti, cmdi, crlf, cors, jwt, xxe, upload categories"
```

---

## Chunk 2: Injection Testing Tools

### Task 4: CRLF Injection Scanner (crlfuzz)

`crlfuzz` is a Go binary from ProjectDiscovery that tests for CRLF injection vulnerabilities. Outputs JSON.

**Files:**
- Create: `src/bba/tools/crlfuzz.py`
- Test: `tests/test_tools_crlfuzz.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tools_crlfuzz.py
from __future__ import annotations
import pytest
from unittest.mock import patch
from bba.tools.crlfuzz import CrlfuzzTool
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import OutputSanitizer

SCOPE = {"program": "test-corp", "domains": ["*.example.com"], "cidrs": [], "exclude": []}

@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))

@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(), sanitizer=OutputSanitizer(), output_dir=tmp_path / "output")

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()

class TestCrlfuzzTool:
    def test_build_command_single(self, runner, db):
        tool = CrlfuzzTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://example.com")
        assert cmd == ["crlfuzz", "-u", "https://example.com", "-s"]

    def test_build_command_list(self, runner, db, tmp_path):
        tool = CrlfuzzTool(runner=runner, db=db, program="test-corp")
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        cmd = tool.build_command_list(["https://example.com/a", "https://example.com/b"], work_dir)
        assert "-l" in cmd

    def test_parse_output(self, runner, db):
        tool = CrlfuzzTool(runner=runner, db=db, program="test-corp")
        output = "https://example.com/a\nhttps://example.com/b\n"
        result = tool.parse_output(output)
        assert len(result) == 2

    def test_parse_empty(self, runner, db):
        tool = CrlfuzzTool(runner=runner, db=db, program="test-corp")
        assert tool.parse_output("") == []

    @pytest.mark.asyncio
    async def test_run_stores_findings(self, runner, db):
        tool = CrlfuzzTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output="https://example.com/vuln?param=test\n", raw_file=None, error=None, duration=5.0)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com/vuln?param=test")
        assert result["total"] == 1
        findings = await db.get_findings("test-corp")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "crlf-injection"

    @pytest.mark.asyncio
    async def test_run_handles_failure(self, runner, db):
        tool = CrlfuzzTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", raw_file=None, error="timeout", duration=0.1)
        with patch.object(runner, "run_command", return_value=mock_result):
            result = await tool.run("https://example.com")
        assert result["total"] == 0
        assert "error" in result
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_tools_crlfuzz.py -v`
Expected: FAIL

- [ ] **Step 3: Write implementation**

```python
# src/bba/tools/crlfuzz.py
"""CRLF injection scanning via crlfuzz."""
from __future__ import annotations
from pathlib import Path
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class CrlfuzzTool:
    """Scan URLs for CRLF injection vulnerabilities."""

    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["crlfuzz", "-u", url, "-s"]

    def build_command_list(self, urls: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "crlfuzz_input.txt"
        input_file.write_text("\n".join(urls) + "\n")
        return ["crlfuzz", "-l", str(input_file), "-s"]

    def parse_output(self, output: str) -> list[str]:
        return [line.strip() for line in output.strip().splitlines() if line.strip()]

    async def run(self, target: str, work_dir: Path | None = None) -> dict:
        parsed = urlparse(target)
        domain = parsed.hostname or target
        cmd = self.build_command(target)
        result = await self.runner.run_command(
            tool="crlfuzz", command=cmd, targets=[domain], timeout=120,
        )
        if not result.success:
            return {"total": 0, "vulnerable": [], "error": result.error}
        vulnerable = self.parse_output(result.output)
        for vuln_url in vulnerable:
            await self.db.add_finding(
                program=self.program, domain=domain, url=vuln_url,
                vuln_type="crlf-injection", severity="medium", tool="crlfuzz",
                evidence=f"CRLF injection confirmed at {vuln_url}", confidence=0.8,
            )
        return {"total": len(vulnerable), "vulnerable": vulnerable}

    async def run_list(self, urls: list[str], work_dir: Path) -> dict:
        domains = list({urlparse(u).hostname for u in urls if urlparse(u).hostname})
        cmd = self.build_command_list(urls, work_dir)
        result = await self.runner.run_command(
            tool="crlfuzz", command=cmd, targets=domains or ["unknown"], timeout=300,
        )
        if not result.success:
            return {"total": 0, "vulnerable": [], "error": result.error}
        vulnerable = self.parse_output(result.output)
        for vuln_url in vulnerable:
            parsed = urlparse(vuln_url)
            await self.db.add_finding(
                program=self.program, domain=parsed.hostname or "", url=vuln_url,
                vuln_type="crlf-injection", severity="medium", tool="crlfuzz",
                evidence=f"CRLF injection confirmed at {vuln_url}", confidence=0.8,
            )
        return {"total": len(vulnerable), "vulnerable": vulnerable, "scanned": len(urls)}
```

- [ ] **Step 4: Run tests**

Run: `uv run python -m pytest tests/test_tools_crlfuzz.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/bba/tools/crlfuzz.py tests/test_tools_crlfuzz.py
git commit -m "feat: add crlfuzz CRLF injection scanner"
```

---

### Task 5: SSTI Detection (SSTImap)

`sstimap` detects Server-Side Template Injection. Python tool, outputs to stdout with identified template engine and payloads.

**Files:**
- Create: `src/bba/tools/sstimap.py`
- Test: `tests/test_tools_sstimap.py`

- [ ] **Step 1–5: Follow the tool wrapper template**

Test pattern: build_command produces `["sstimap", "-u", url, "--no-color"]`, parse_output extracts "Identified" lines and engine names via regex, run stores findings with vuln_type="ssti", severity="critical", confidence=0.9.

```python
# src/bba/tools/sstimap.py
"""Server-Side Template Injection detection via SSTImap."""
from __future__ import annotations
import re
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

_ENGINE_PATTERN = re.compile(r"(?:Identified|Confirmed|Detected).*?(?:engine|injection).*?:\s*(\S+)", re.I)
_VULN_PATTERN = re.compile(r"(?:exploitable|injectable|confirmed|identified)", re.I)


class SstimapTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["sstimap", "-u", url, "--no-color"]

    def parse_output(self, output: str) -> dict:
        engines = _ENGINE_PATTERN.findall(output)
        vulnerable = bool(_VULN_PATTERN.search(output))
        return {"vulnerable": vulnerable, "engines": engines, "raw": output[:2000]}

    async def run(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="sstimap", command=self.build_command(url),
            targets=[domain] if domain else [url], timeout=180,
        )
        if not result.success:
            return {"vulnerable": False, "url": url, "error": result.error}
        parsed_result = self.parse_output(result.output)
        if parsed_result["vulnerable"]:
            engine_str = ", ".join(parsed_result["engines"]) or "unknown"
            await self.db.add_finding(
                program=self.program, domain=domain, url=url,
                vuln_type="ssti", severity="critical", tool="sstimap",
                evidence=f"Template engine: {engine_str}. {parsed_result['raw'][:500]}",
                confidence=0.9,
            )
        return {"vulnerable": parsed_result["vulnerable"], "url": url, "engines": parsed_result["engines"]}
```

Test: Verify build_command, parse_output with sample "Identified injection: Jinja2" text, run mock with finding storage.

- [ ] Commit: `feat: add sstimap SSTI detection tool`

---

### Task 6: Command Injection (Commix)

`commix` is a Python command injection exploitation tool. Outputs injection results to stdout.

**Files:**
- Create: `src/bba/tools/commix.py`
- Test: `tests/test_tools_commix.py`

```python
# src/bba/tools/commix.py
"""OS command injection detection via commix."""
from __future__ import annotations
import re
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

_VULN_PATTERN = re.compile(r"(?:is vulnerable|injectable|command injection)", re.I)
_TECHNIQUE_PATTERN = re.compile(r"(?:technique|via)\s*[:\-]\s*(.+)", re.I)


class CommixTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["commix", "--url", url, "--batch", "--output-dir=/dev/null"]

    def is_vulnerable(self, output: str) -> bool:
        return bool(_VULN_PATTERN.search(output))

    def extract_technique(self, output: str) -> str:
        match = _TECHNIQUE_PATTERN.search(output)
        return match.group(1).strip() if match else "unknown"

    async def run(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="commix", command=self.build_command(url),
            targets=[domain] if domain else [url], timeout=300,
        )
        if not result.success:
            return {"vulnerable": False, "url": url, "error": result.error}
        vulnerable = self.is_vulnerable(result.output)
        if vulnerable:
            technique = self.extract_technique(result.output)
            await self.db.add_finding(
                program=self.program, domain=domain, url=url,
                vuln_type="command-injection", severity="critical", tool="commix",
                evidence=f"Technique: {technique}. {result.output[:1000]}",
                confidence=0.9,
            )
        return {"vulnerable": vulnerable, "url": url, "technique": self.extract_technique(result.output) if vulnerable else None}
```

Test: Same pattern. Verify build_command includes `--batch`, parse vulnerability detection regex, mock run with finding storage.

- [ ] Commit: `feat: add commix command injection tool`

---

### Task 7: Advanced SQLi (Ghauri)

`ghauri` is a Python SQLi tool (complement to sqlmap) that's better at blind injection. Outputs structured text.

**Files:**
- Create: `src/bba/tools/ghauri.py`
- Test: `tests/test_tools_ghauri.py`

```python
# src/bba/tools/ghauri.py
"""Advanced SQL injection detection via ghauri."""
from __future__ import annotations
import re
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

_VULN_PATTERN = re.compile(r"(?:is vulnerable|Parameter.*injectable|SQL injection)", re.I)
_PARAM_PATTERN = re.compile(r"Parameter:\s*['\"]?(\w+)", re.I)
_TECHNIQUE_PATTERN = re.compile(r"Type:\s*(.+)", re.I)


class GhauriTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str, level: int = 2, technique: str | None = None) -> list[str]:
        cmd = ["ghauri", "-u", url, "--batch", "--level", str(level)]
        if technique:
            cmd.extend(["--technique", technique])
        return cmd

    def is_vulnerable(self, output: str) -> bool:
        return bool(_VULN_PATTERN.search(output))

    async def run(self, url: str, level: int = 2, technique: str | None = None) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="ghauri", command=self.build_command(url, level, technique),
            targets=[domain] if domain else [url], timeout=300,
        )
        if not result.success:
            return {"vulnerable": False, "url": url, "error": result.error}
        vulnerable = self.is_vulnerable(result.output)
        if vulnerable:
            param = _PARAM_PATTERN.search(result.output)
            tech = _TECHNIQUE_PATTERN.search(result.output)
            await self.db.add_finding(
                program=self.program, domain=domain, url=url,
                vuln_type="sql-injection", severity="critical", tool="ghauri",
                evidence=f"Param: {param.group(1) if param else 'unknown'}, Type: {tech.group(1) if tech else 'unknown'}. {result.output[:1000]}",
                confidence=0.9,
            )
        return {"vulnerable": vulnerable, "url": url, "output_preview": result.output[:500]}
```

- [ ] Commit: `feat: add ghauri advanced SQLi detection tool`

---

### Task 8: NoSQL Injection (nosqli)

`nosqli` is a Go tool from Charlie Belmer that tests for NoSQL injection.

**Files:**
- Create: `src/bba/tools/nosqli.py`
- Test: `tests/test_tools_nosqli.py`

```python
# src/bba/tools/nosqli.py
"""NoSQL injection detection via nosqli."""
from __future__ import annotations
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class NosqliTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["nosqli", "scan", "-t", url]

    def parse_output(self, output: str) -> list[dict]:
        findings = []
        for line in output.strip().splitlines():
            lower = line.lower()
            if "vulnerable" in lower or "injection" in lower:
                findings.append({"detail": line.strip()})
        return findings

    async def run(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="nosqli", command=self.build_command(url),
            targets=[domain] if domain else [url], timeout=120,
        )
        if not result.success:
            return {"vulnerable": False, "url": url, "error": result.error}
        findings = self.parse_output(result.output)
        if findings:
            await self.db.add_finding(
                program=self.program, domain=domain, url=url,
                vuln_type="nosql-injection", severity="high", tool="nosqli",
                evidence="; ".join(f["detail"] for f in findings)[:2000],
                confidence=0.85,
            )
        return {"vulnerable": bool(findings), "url": url, "findings": findings}
```

- [ ] Commit: `feat: add nosqli NoSQL injection detection tool`

---

## Chunk 3: Web Security Tools

### Task 9: XSS Detection (XSStrike)

`xsstrike` is a Python XSS scanner with WAF detection, fuzzing, and context analysis. Complements dalfox.

**Files:**
- Create: `src/bba/tools/xsstrike.py`
- Test: `tests/test_tools_xsstrike.py`

```python
# src/bba/tools/xsstrike.py
"""XSS detection via XSStrike with WAF bypass and context analysis."""
from __future__ import annotations
import re
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

_VULN_PATTERN = re.compile(r"(?:Vulnerable|XSS confirmed|Payload:)\s*(.*)", re.I)
_WAF_PATTERN = re.compile(r"WAF detected:\s*(.+)", re.I)


class XSStrikeTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str, blind: bool = False, crawl: bool = False) -> list[str]:
        cmd = ["xsstrike", "-u", url, "--skip"]
        if blind:
            cmd.append("--blind")
        if crawl:
            cmd.extend(["--crawl", "-l", "2"])
        return cmd

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for match in _VULN_PATTERN.finditer(output):
            results.append({"payload": match.group(1).strip()})
        return results

    def detect_waf(self, output: str) -> str | None:
        match = _WAF_PATTERN.search(output)
        return match.group(1).strip() if match else None

    async def run(self, url: str, blind: bool = False, crawl: bool = False) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="xsstrike", command=self.build_command(url, blind, crawl),
            targets=[domain] if domain else [url], timeout=180,
        )
        if not result.success:
            return {"vulnerable": False, "url": url, "error": result.error}
        findings = self.parse_output(result.output)
        waf = self.detect_waf(result.output)
        for f in findings:
            await self.db.add_finding(
                program=self.program, domain=domain, url=url,
                vuln_type="xss", severity="high", tool="xsstrike",
                evidence=f"Payload: {f['payload']}" + (f", WAF: {waf}" if waf else ""),
                confidence=0.85,
            )
        return {"vulnerable": bool(findings), "url": url, "findings": findings, "waf": waf}
```

- [ ] Commit: `feat: add xsstrike XSS detection tool`

---

### Task 10: CORS Misconfiguration (CORScanner)

`corscanner` tests for CORS misconfiguration with various Origin headers.

**Files:**
- Create: `src/bba/tools/corscanner.py`
- Test: `tests/test_tools_corscanner.py`

```python
# src/bba/tools/corscanner.py
"""CORS misconfiguration detection via CORScanner."""
from __future__ import annotations
import json
from pathlib import Path
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class CORScannerTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["python3", "-m", "CORScanner.cors_scan", "-u", url, "-q"]

    def build_command_list(self, urls: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "cors_input.txt"
        input_file.write_text("\n".join(urls) + "\n")
        return ["python3", "-m", "CORScanner.cors_scan", "-i", str(input_file), "-q"]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            try:
                entry = json.loads(line)
                if entry.get("vulnerable"):
                    results.append(entry)
            except json.JSONDecodeError:
                if "vulnerable" in line.lower() or "misconfigured" in line.lower():
                    results.append({"url": line.strip(), "type": "cors-misconfiguration"})
        return results

    async def run(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="corscanner", command=self.build_command(url),
            targets=[domain] if domain else [url], timeout=60,
        )
        if not result.success:
            return {"total": 0, "findings": [], "error": result.error}
        findings = self.parse_output(result.output)
        for f in findings:
            severity = "critical" if f.get("credentials") else "medium"
            await self.db.add_finding(
                program=self.program, domain=domain, url=f.get("url", url),
                vuln_type="cors-misconfiguration", severity=severity, tool="corscanner",
                evidence=json.dumps(f)[:2000], confidence=0.85,
            )
        return {"total": len(findings), "findings": findings}
```

- [ ] Commit: `feat: add corscanner CORS misconfiguration detection`

---

### Task 11: JWT Vulnerability Testing (jwt_tool)

`jwt_tool` tests JWT tokens for algorithm confusion, weak secrets, and claim manipulation.

**Files:**
- Create: `src/bba/tools/jwt_tool.py`
- Test: `tests/test_tools_jwt_tool.py`

```python
# src/bba/tools/jwt_tool.py
"""JWT vulnerability testing via jwt_tool."""
from __future__ import annotations
import re
from bba.db import Database
from bba.tool_runner import ToolRunner

_VULN_PATTERN = re.compile(r"(?:VULNERABLE|EXPLOITABLE|WEAK SECRET|alg.*none.*accepted)", re.I)
_ALG_NONE = re.compile(r"alg.*none.*accepted", re.I)
_WEAK_SECRET = re.compile(r"(?:weak.*secret|cracked|secret.*found).*?[:\-]\s*(.+)", re.I)


class JwtToolTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command_scan(self, token: str) -> list[str]:
        return ["jwt_tool", token, "-M", "at", "-t", "https://example.com", "-np"]

    def build_command_crack(self, token: str, wordlist: str) -> list[str]:
        return ["jwt_tool", token, "-C", "-d", wordlist, "-np"]

    def parse_output(self, output: str) -> dict:
        vulns = []
        if _ALG_NONE.search(output):
            vulns.append({"type": "alg-none", "detail": "Algorithm 'none' accepted"})
        weak_match = _WEAK_SECRET.search(output)
        if weak_match:
            vulns.append({"type": "weak-secret", "detail": f"Secret: {weak_match.group(1)}"})
        for match in _VULN_PATTERN.finditer(output):
            if not any(v["detail"] in match.group(0) for v in vulns):
                vulns.append({"type": "jwt-vuln", "detail": match.group(0).strip()})
        return {"vulnerable": bool(vulns), "vulns": vulns}

    async def run(self, token: str, domain: str, mode: str = "scan", wordlist: str | None = None) -> dict:
        if mode == "crack" and wordlist:
            cmd = self.build_command_crack(token, wordlist)
        else:
            cmd = self.build_command_scan(token)
        result = await self.runner.run_command(
            tool="jwt_tool", command=cmd, targets=[domain], timeout=300,
        )
        if not result.success:
            return {"vulnerable": False, "error": result.error}
        parsed = self.parse_output(result.output)
        for vuln in parsed["vulns"]:
            await self.db.add_finding(
                program=self.program, domain=domain, url=f"jwt://{domain}",
                vuln_type=f"jwt-{vuln['type']}", severity="critical" if vuln["type"] == "alg-none" else "high",
                tool="jwt_tool", evidence=vuln["detail"], confidence=0.9,
            )
        return {"vulnerable": parsed["vulnerable"], "vulns": parsed["vulns"]}
```

- [ ] Commit: `feat: add jwt_tool JWT vulnerability testing`

---

### Task 12: HTTP Request Smuggling (smuggler)

`smuggler` tests for CL.TE, TE.CL, and TE.TE HTTP request smuggling.

**Files:**
- Create: `src/bba/tools/smuggler.py`
- Test: `tests/test_tools_smuggler.py`

```python
# src/bba/tools/smuggler.py
"""HTTP request smuggling detection via smuggler."""
from __future__ import annotations
import re
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner

_VULN_PATTERN = re.compile(r"(?:VULNERABLE|DESYNC|smuggl)", re.I)
_TECHNIQUE_PATTERN = re.compile(r"(CL\.TE|TE\.CL|TE\.TE|H2\.CL|H2\.TE)", re.I)


class SmugglerTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, url: str) -> list[str]:
        return ["python3", "-m", "smuggler", "-u", url, "-q"]

    def parse_output(self, output: str) -> list[dict]:
        findings = []
        for line in output.strip().splitlines():
            if _VULN_PATTERN.search(line):
                technique = _TECHNIQUE_PATTERN.search(line)
                findings.append({
                    "detail": line.strip(),
                    "technique": technique.group(1) if technique else "unknown",
                })
        return findings

    async def run(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        result = await self.runner.run_command(
            tool="smuggler", command=self.build_command(url),
            targets=[domain] if domain else [url], timeout=120,
        )
        if not result.success:
            return {"vulnerable": False, "url": url, "error": result.error}
        findings = self.parse_output(result.output)
        for f in findings:
            await self.db.add_finding(
                program=self.program, domain=domain, url=url,
                vuln_type="http-smuggling", severity="critical", tool="smuggler",
                evidence=f"Technique: {f['technique']}. {f['detail']}", confidence=0.85,
            )
        return {"vulnerable": bool(findings), "url": url, "findings": findings}
```

- [ ] Commit: `feat: add smuggler HTTP request smuggling detection`

---

### Task 13: Prototype Pollution (ppfuzz)

`ppfuzz` is a Rust tool that scans for client-side prototype pollution via headless browser.

**Files:**
- Create: `src/bba/tools/ppfuzz.py`
- Test: `tests/test_tools_ppfuzz.py`

```python
# src/bba/tools/ppfuzz.py
"""Client-side prototype pollution detection via ppfuzz."""
from __future__ import annotations
from pathlib import Path
from urllib.parse import urlparse
from bba.db import Database
from bba.tool_runner import ToolRunner


class PpfuzzTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, urls: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "ppfuzz_input.txt"
        input_file.write_text("\n".join(urls) + "\n")
        return ["ppfuzz", "-l", str(input_file)]

    def parse_output(self, output: str) -> list[dict]:
        findings = []
        for line in output.strip().splitlines():
            lower = line.lower()
            if "vulnerable" in lower or "pollut" in lower or "proto" in lower:
                findings.append({"url": line.strip()})
        return findings

    async def run(self, urls: list[str], work_dir: Path) -> dict:
        domains = list({urlparse(u).hostname for u in urls if urlparse(u).hostname})
        result = await self.runner.run_command(
            tool="ppfuzz", command=self.build_command(urls, work_dir),
            targets=domains or ["unknown"], timeout=300,
        )
        if not result.success:
            return {"total": 0, "findings": [], "error": result.error}
        findings = self.parse_output(result.output)
        for f in findings:
            await self.db.add_finding(
                program=self.program, domain=domains[0] if domains else "",
                url=f["url"], vuln_type="prototype-pollution", severity="high",
                tool="ppfuzz", evidence=f["url"], confidence=0.75,
            )
        return {"total": len(findings), "findings": findings, "scanned": len(urls)}
```

- [ ] Commit: `feat: add ppfuzz prototype pollution detection`

---

## Chunk 4: CLI Integration

### Task 14: Add All New Tool CLI Subparsers

**Files:**
- Modify: `src/bba/cli.py`

Add subparsers and command handlers for all 12 new tools under existing `recon` and `scan` groups:

**Under `scan` subparser:**

| Command | Tool Class | Key Args |
|---------|-----------|----------|
| `bba scan crlfuzz <url\|targets> --program` | CrlfuzzTool | single URL or `-l` list |
| `bba scan sstimap <url> --program` | SstimapTool | single URL |
| `bba scan commix <url> --program` | CommixTool | single URL |
| `bba scan ghauri <url> --program [--level] [--technique]` | GhauriTool | level 1-5, technique B/E/U/T |
| `bba scan nosqli <url> --program` | NosqliTool | single URL |
| `bba scan xsstrike <url> --program [--blind] [--crawl]` | XSStrikeTool | blind XSS, crawl mode |
| `bba scan corscanner <url\|targets> --program` | CORScannerTool | single or list |
| `bba scan jwt-tool <token> --program --domain [--mode] [--wordlist]` | JwtToolTool | scan/crack modes |
| `bba scan smuggler <url> --program` | SmugglerTool | single URL |
| `bba scan ppfuzz <targets> --program` | PpfuzzTool | URL list |

**Under `recon` subparser (utilities):**

| Command | Tool Class | Key Args |
|---------|-----------|----------|
| `bba recon uro <targets> --program` | UroTool | URL list |
| `bba recon qsreplace <targets> --program --payload` | QsreplaceTool | payload string |

- [ ] **Step 1: Add argument parsers**

For each tool, add a subparser following the existing pattern in cli.py. Example for crlfuzz:

```python
p = scan_sub.add_parser("crlfuzz", help="CRLF injection scanning")
p.add_argument("target", help="URL or comma-separated targets")
p.add_argument("--program", required=True)
p.set_defaults(func=cmd_scan_crlfuzz)
```

- [ ] **Step 2: Add command handlers**

For each tool, add an async handler following the existing pattern. Example:

```python
async def cmd_scan_crlfuzz(args):
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
```

- [ ] **Step 3: Run full test suite**

Run: `uv run python -m pytest tests/ --ignore=tests/integration -q`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/bba/cli.py
git commit -m "feat: add CLI commands for Phase 4 vulnerability testing tools"
```

---

### Task 15: Update Install Script

**Files:**
- Modify: `scripts/install-tools.sh`

Add installation for all new tools:

```bash
# Phase 4 — Vulnerability Testing Tools
install_go_tool "crlfuzz" "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
install_go_tool "qsreplace" "github.com/tomnomnom/qsreplace@latest"
install_go_tool "nosqli" "github.com/Charlie-belmer/nosqli@latest"
pip_install "uro"
pip_install "sstimap" "git+https://github.com/vladko312/SSTImap.git"
pip_install "commix" "git+https://github.com/commixproject/commix.git"
pip_install "ghauri" "git+https://github.com/r0oth3x49/ghauri.git"
pip_install "xsstrike" "git+https://github.com/s0md3v/XSStrike.git"
pip_install "CORScanner" "git+https://github.com/chenjj/CORScanner.git"
pip_install "jwt_tool" "git+https://github.com/ticarpi/jwt_tool.git"
pip_install "smuggler" "git+https://github.com/defparam/smuggler.git"
cargo_install "ppfuzz"
```

- [ ] Commit: `feat: add Phase 4 tool installation to install script`

---

## Chunk 5: Vuln-Tester Agent

### Task 16: Create the Vulnerability Testing Agent

This is the core intelligence of Phase 4. The agent receives:
- Classified URLs from gf_patterns
- Live service profiles from httpx (tech stack, WAF, status codes)
- Existing scan results from the scanner agent

It dispatches category-specific testing pipelines and reasons about findings.

**Files:**
- Create: `.claude/agents/vuln-tester.md`

- [ ] **Step 1: Write the agent definition**

```markdown
---
model: sonnet
description: Category-specific vulnerability testing with methodology-driven pipeline orchestration
tools:
  - Bash
  - Read
  - Glob
  - Grep
  - Agent
---

# Vulnerability Tester Agent

You are a specialized vulnerability testing agent for authorized bug bounty programs. You receive classified URLs, tech profiles, and existing scan results, then execute category-specific testing pipelines.

## CRITICAL RULES

1. NEVER test targets outside the provided scope
2. ALWAYS use `uv run bba` for tool invocation
3. Rate limit aggressively — prefer accuracy over speed
4. Log reasoning for every category decision

## Input Format

You receive:
- **Classified URLs**: Output from gf_patterns (xss, sqli, ssrf, ssti, cmdi, crlf, lfi, rce, idor, redirect, cors, jwt, xxe, upload)
- **Tech profiles**: HTTP services with technology stack, WAF presence, response codes
- **Existing findings**: Results from the scanner agent phase
- **Program name**: For scope and DB operations

## Phase 1: URL Preparation

Before testing, deduplicate and prepare URLs:

```bash
# Deduplicate URLs to reduce noise
uv run bba recon uro <all-urls> --program <prog>
```

## Phase 2: Category Decision Tree

For each category with classified URLs, evaluate whether to test based on:
- Number of candidate URLs (skip if < 2 for expensive tools)
- WAF presence (adjust techniques)
- Tech stack relevance
- Existing findings (avoid re-testing confirmed vulns)

### XSS Testing Pipeline

**When:** gf_patterns returns xss URLs AND target serves HTML responses
**Tools:** dalfox (primary), xsstrike (WAF bypass/blind)

```bash
# Step 1: Mass reflected XSS via dalfox pipe
# Feed gf-classified XSS URLs through dalfox
uv run bba scan dalfox "<url>" --program <prog>

# Step 2: If WAF detected, use xsstrike for evasion
uv run bba scan xsstrike "<url>" --program <prog> --blind

# Step 3: Check error pages for XSS (404, 500)
# Use curl to test common error triggers with XSS payloads
```

**Advanced XSS (recommend for deep-dive if basic XSS found):**
- Blind XSS: Inject OOB callback payloads in all input fields
- DOM XSS: Analyze JS files from linkfinder for source-to-sink chains
- CRLF→XSS chain: Test via crlfuzz first, then chain to XSS
- CSP bypass: Check CSP headers, look for unsafe-inline, JSONP endpoints on whitelisted domains

### SQL Injection Pipeline

**When:** gf_patterns returns sqli URLs
**Tools:** sqlmap (primary), ghauri (blind/time-based complement)

```bash
# Step 1: Mass SQLi detection
uv run bba scan sqlmap "<url>" --program <prog>

# Step 2: For URLs sqlmap missed, try ghauri (better at blind)
uv run bba scan ghauri "<url>" --program <prog> --level 3

# Step 3: Test NoSQL injection on JSON endpoints
uv run bba scan nosqli "<url>" --program <prog>
```

**Decision logic:**
- If target uses MongoDB/NoSQL tech → prioritize nosqli
- If WAF blocks sqlmap → use ghauri with time-based only (--technique T)
- Test headers, cookies, JSON bodies — not just GET params

### SSRF Testing Pipeline

**When:** gf_patterns returns ssrf URLs OR url/fetch/load parameters found
**Tools:** Manual curl-based testing via bash (no dedicated tool wrapper needed)

```bash
# Step 1: Test each SSRF-candidate URL with OOB callback
# Replace param value with interactsh/burp collaborator URL
uv run bba recon qsreplace "<urls>" --program <prog> --payload "https://CALLBACK_URL"

# Step 2: Test cloud metadata endpoints
# AWS: http://169.254.169.254/latest/meta-data/
# GCP: http://metadata.google.internal/computeMetadata/v1/
# Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

**Agent reasoning:** SSRF often requires manual verification. Flag any URL parameters that accept URLs/paths as high-priority for deep-dive agent.

### SSTI Testing Pipeline

**When:** gf_patterns returns ssti URLs OR template/render/preview parameters found
**Tools:** sstimap

```bash
# Test each candidate URL for template injection
uv run bba scan sstimap "<url>" --program <prog>
```

**If SSTI confirmed:** This is almost always critical (RCE). Immediately flag for validator agent.

### Command Injection Pipeline

**When:** gf_patterns returns cmdi/rce URLs OR cmd/exec/ping parameters found
**Tools:** commix

```bash
uv run bba scan commix "<url>" --program <prog>
```

### CRLF Injection Pipeline

**When:** gf_patterns returns crlf URLs OR redirect parameters found
**Tools:** crlfuzz

```bash
# Mass CRLF test on all redirect/url parameters
uv run bba scan crlfuzz "<url-or-targets>" --program <prog>
```

**Chain:** If CRLF found → test for response splitting → XSS via injected headers

### CORS Misconfiguration Pipeline

**When:** API endpoints found OR cors-classified URLs
**Tools:** corscanner

```bash
uv run bba scan corscanner "<url>" --program <prog>
```

**Critical condition:** Access-Control-Allow-Credentials: true + reflected arbitrary Origin = P1

### JWT Testing Pipeline

**When:** jwt_patterns found in URLs/cookies OR Authorization headers use Bearer tokens
**Tools:** jwt_tool

```bash
# Extract JWTs from prior scan results, test each
uv run bba scan jwt-tool "<token>" --program <prog> --domain <domain>

# If alg:none works → critical
# Try weak secret brute-force
uv run bba scan jwt-tool "<token>" --program <prog> --domain <domain> --mode crack --wordlist jwt-secrets.txt
```

### HTTP Smuggling Pipeline

**When:** Target uses reverse proxy (detected via response headers) OR multiple backend servers
**Tools:** smuggler

```bash
uv run bba scan smuggler "<url>" --program <prog>
```

**Priority:** Test smuggling on targets behind CDN/load balancer (CloudFront, Akamai, Fastly)

### LFI / Path Traversal Pipeline

**When:** gf_patterns returns lfi URLs OR file/path/include parameters found
**Tools:** ffuf with traversal wordlists

```bash
# Use ffuf with path traversal wordlist
uv run bba scan ffuf "<url-with-FUZZ>" --program <prog> --wordlist /path/to/LFI-Jhaddix.txt
```

### Prototype Pollution Pipeline

**When:** JS-heavy SPA detected AND gf_patterns returns prototype-pollution candidates
**Tools:** ppfuzz

```bash
uv run bba scan ppfuzz "<targets>" --program <prog>
```

### Open Redirect Pipeline

**When:** gf_patterns returns redirect URLs
**Tools:** Manual testing via httpx redirect following

```bash
# Replace redirect params with external URL, check if followed
uv run bba recon qsreplace "<urls>" --program <prog> --payload "https://evil.com"
# Then check responses for redirect via httpx
```

### 403 Bypass Testing

**When:** Scanner found 403 responses on interesting paths
**Approach:** Agent uses curl with bypass techniques:

1. Path manipulation: `..;/admin`, `/%2e/admin`, `/admin/./`
2. Header injection: `X-Original-URL: /admin`, `X-Forwarded-For: 127.0.0.1`
3. Method switching: GET→POST, OPTIONS
4. Encoding: URL encode, double encode, Unicode

This is purely agent intelligence — no tool wrapper needed. Use bash + curl.

### WAF Bypass Strategies

Applied across all categories when WAF is detected:
- Reduce rate to 5-10 req/s
- Use encoding: double URL encoding, Unicode, mixed case
- For XSS: dalfox --waf-evasion, xsstrike WAF mode
- For SQLi: ghauri with time-based only (least detectable)
- For SSTI: Use less common template syntax variations
- Comment injection: `/**/`, inline comments
- Chunked encoding for smuggling

## Phase 3: Finding Consolidation

After all category tests complete:

1. Query all new findings: `uv run bba db findings --program <prog>`
2. Deduplicate findings (same URL + same vuln type = one finding)
3. Cross-reference: Does an SSRF finding enable access to cloud metadata? Does CRLF chain to XSS?
4. Assign priority based on exploitability and impact

## Output Format

```
## VULNERABILITY TESTING RESULTS

### Categories Tested
[List each category tested with URL count and tool used]

### CRITICAL FINDINGS
[vuln_type] [url] — [evidence summary]
Confidence: [0.0-1.0]
Chain potential: [describe any chaining opportunities]

### HIGH FINDINGS
[Same format]

### MEDIUM FINDINGS
[Same format]

### CHAINS IDENTIFIED
[Describe multi-step attack chains: CRLF→XSS, SSRF→Cloud metadata, Open redirect→OAuth token theft]

### CATEGORIES SKIPPED
[List categories skipped with reasoning: no candidate URLs, tech stack irrelevant, etc.]

### MANUAL TESTING RECOMMENDATIONS
[List techniques that require interactive tools (Burp Suite) or manual analysis:]
- Stored XSS in input fields (requires form interaction)
- IDOR/BOLA testing (requires multiple auth sessions)
- Race conditions (requires parallel request tooling)
- Business logic flaws (requires understanding of application workflow)
- File upload testing (requires crafted file creation)
- 2FA bypass (requires account with 2FA enabled)
- SAML attacks (requires SAML SSO flow)
- OAuth token theft (requires OAuth flow interaction)
- WebSocket testing (requires WS connection)
- Cache deception (requires cache behavior analysis)
```
```

- [ ] **Step 2: Commit**

```bash
git add .claude/agents/vuln-tester.md
git commit -m "feat: add vuln-tester agent with category-specific testing pipelines"
```

---

## Chunk 6: Coordinator Integration

### Task 17: Add Phase 4 to Scan-Target Coordinator

**Files:**
- Modify: `.claude/commands/scan-target.md`

Insert Phase 4 between the current scanner phase and the deep-dive phase:

- [ ] **Step 1: Add Phase 4 — Vulnerability Testing**

After the scanner agent completes (current Phase 7) and before deep-dive (current Phase 9), add:

```markdown
## Phase 4 — Category-Specific Vulnerability Testing

After the scanner agent completes and before deep-dive:

### COORDINATOR REASONING — Vulnerability Testing Assessment

Analyze scanner results and decide which vulnerability categories warrant dedicated testing:

1. **URL Classification**: Use gf_patterns output to identify testable categories
2. **Tech Profile**: Use httpx fingerprinting to determine relevant categories
3. **WAF Awareness**: Adjust testing strategy if WAF is present
4. **Existing Findings**: Skip categories where scanner already found confirmed vulns

### Dispatch Vuln-Tester Agent

Spawn the vuln-tester agent with:
- All classified URLs from recon phase
- Tech profiles from httpx
- Scanner agent findings summary
- WAF detection results
- Program name

```
Use Agent tool:
  subagent_type: general-purpose
  model: sonnet
  prompt: |
    You are the vuln-tester agent. Follow .claude/agents/vuln-tester.md exactly.

    Program: {program}
    Classified URLs: {gf_output}
    Tech profiles: {httpx_output}
    Scanner findings: {scanner_summary}
    WAF status: {waf_results}

    Execute category-specific testing pipelines. Report all findings.
```

### COORDINATOR REASONING — Post-Vuln-Testing

Analyze vuln-tester output:
- Which categories produced findings?
- Any attack chains identified (CRLF→XSS, SSRF→metadata)?
- Which findings need deep-dive validation?
- Update deep-dive targets with new findings
```

This extends the coordinator from 13 to 15 phases (renumbering existing phases 8-13 to 10-15).

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/scan-target.md
git commit -m "feat: integrate Phase 4 vuln testing into coordinator pipeline"
```

---

### Task 18: Run Full Test Suite & Verify

- [ ] **Step 1: Run all tests**

```bash
uv run python -m pytest tests/ --ignore=tests/integration -v
```

Expected: All tests pass (existing 451 + ~60 new = ~511 tests)

- [ ] **Step 2: Verify CLI help shows new commands**

```bash
uv run bba scan --help
uv run bba recon --help
```

Expected: All new tool subcommands visible

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "feat: Phase 4 vulnerability testing by category — complete"
```

---

## Summary

| Component | Count | Description |
|-----------|-------|-------------|
| New tool wrappers | 12 | crlfuzz, sstimap, commix, ghauri, nosqli, xsstrike, corscanner, jwt_tool, smuggler, ppfuzz, uro, qsreplace |
| Enhanced patterns | 8 | ssti, cmdi, crlf, cors, jwt, xxe, prototype-pollution, upload added to gf_patterns |
| New agent | 1 | vuln-tester.md — category-specific testing orchestration |
| Coordinator update | 1 | Phase 4 integration between scanner and deep-dive |
| Test files | 12 | One per new tool wrapper |
| CLI commands | 12 | Subparsers + handlers for all new tools |

**Vulnerability categories covered by automation:**
- XSS (dalfox + xsstrike + crlfuzz chain)
- SQLi (sqlmap + ghauri)
- NoSQLi (nosqli)
- SSRF (qsreplace + manual curl)
- SSTI (sstimap)
- Command injection (commix)
- CRLF injection (crlfuzz)
- CORS misconfiguration (corscanner)
- JWT attacks (jwt_tool)
- HTTP smuggling (smuggler)
- Prototype pollution (ppfuzz)
- LFI/path traversal (ffuf with traversal wordlists)
- Open redirect (qsreplace + httpx)
- 403 bypass (agent intelligence + curl)
- WAF bypass (strategy layer across all tools)

**Categories requiring manual/Burp Suite testing (flagged by agent):**
- Stored XSS, DOM XSS, blind XSS (partial automation)
- IDOR/BOLA (requires multi-session context)
- Authentication & session (requires account interaction)
- Business logic & race conditions
- File upload exploitation
- SAML/SSO attacks
- Cache deception/poisoning
- XXE (partial via nuclei, full requires Burp)
- CSRF (detection only, exploitation manual)
