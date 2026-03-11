# Bug Bounty Agent — Phase 3: Scanning Pipeline

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build vulnerability scanning tool wrappers (nuclei, ffuf, sqlmap, dalfox) that select scanning strategies based on discovered technologies, parse findings into the database with severity classification, and chain into a scanning pipeline orchestrator.

**Architecture:** Each scanner wrapper builds CLI commands, runs through ToolRunner, parses structured output, stores findings in the database with severity/confidence scores, and returns summaries. The scanning pipeline reads services from the database, selects tools based on detected technologies, and coordinates parallel scanning. Tests mock subprocess execution.

**Tech Stack:** Python 3.13+, existing bba modules, pytest with unittest.mock

---

## File Structure

```
src/bba/tools/
    nuclei.py          # Nuclei vulnerability scanner wrapper
    ffuf.py            # Directory/vhost fuzzing wrapper
    sqlmap_runner.py   # SQL injection scanner wrapper
    dalfox.py          # XSS scanner wrapper
    scan_pipeline.py   # Scanning pipeline orchestrator
tests/
    test_tools_nuclei.py
    test_tools_ffuf.py
    test_tools_sqlmap.py
    test_tools_dalfox.py
    test_tools_scan_pipeline.py
```

---

## Chunk 1: Nuclei and Ffuf

### Task 1: Nuclei Wrapper

**Files:**
- Create: `src/bba/tools/nuclei.py`
- Create: `tests/test_tools_nuclei.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_tools_nuclei.py`:
```python
import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.nuclei import NucleiTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

NUCLEI_OUTPUT = "\n".join([
    json.dumps({
        "template-id": "cve-2021-44228",
        "info": {"name": "Log4j RCE", "severity": "critical", "tags": ["cve", "rce"]},
        "host": "https://api.example.com",
        "matched-at": "https://api.example.com/login",
        "matcher-name": "log4j",
        "extracted-results": ["${jndi:ldap://...}"],
    }),
    json.dumps({
        "template-id": "exposed-panels",
        "info": {"name": "Admin Panel Detected", "severity": "info", "tags": ["panel"]},
        "host": "https://shop.example.com",
        "matched-at": "https://shop.example.com/admin",
    }),
    json.dumps({
        "template-id": "xss-reflected",
        "info": {"name": "Reflected XSS", "severity": "high", "tags": ["xss"]},
        "host": "https://shop.example.com",
        "matched-at": "https://shop.example.com/search?q=test",
        "extracted-results": ["<script>alert(1)</script>"],
    }),
]) + "\n"


@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))

@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(default_rps=100), sanitizer=Sanitizer(), output_dir=tmp_path / "output")

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestNucleiTool:
    def test_builds_command_with_targets_file(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(
            ["https://api.example.com", "https://shop.example.com"],
            work_dir=tmp_path,
            severity="high,critical",
            rate_limit=100,
        )
        assert "nuclei" in cmd
        assert "-l" in cmd
        assert "-severity" in cmd
        assert "high,critical" in cmd
        assert "-rl" in cmd
        assert "100" in cmd
        assert "-json" in cmd

    def test_builds_command_with_tags(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(
            ["https://api.example.com"],
            work_dir=tmp_path,
            tags="wordpress,wp-plugin",
        )
        assert "-tags" in cmd
        assert "wordpress,wp-plugin" in cmd

    def test_parses_json_output(self, runner, db):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(NUCLEI_OUTPUT)
        assert len(results) == 3
        assert results[0]["template-id"] == "cve-2021-44228"
        assert results[0]["info"]["severity"] == "critical"

    def test_parses_empty_output(self, runner, db):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    async def test_run_stores_findings_in_db(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=NUCLEI_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(
                ["https://api.example.com", "https://shop.example.com"],
                work_dir=tmp_path,
            )

        findings = await db.get_findings("test-corp")
        assert len(findings) == 3
        assert summary["total"] == 3
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["high"] == 1

    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["https://api.example.com"], work_dir=tmp_path)

        assert summary["total"] == 0
        assert summary["error"] == "timeout"

    def test_select_templates_for_wordpress(self, runner, db):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        opts = tool.select_scan_options(technologies=["apache", "php", "wordpress"])
        assert "wordpress" in opts["tags"]

    def test_select_templates_for_api(self, runner, db):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        opts = tool.select_scan_options(technologies=["nginx", "python", "flask"])
        assert opts["severity"] == "high,critical"

    def test_select_templates_default(self, runner, db):
        tool = NucleiTool(runner=runner, db=db, program="test-corp")
        opts = tool.select_scan_options(technologies=[])
        assert opts["severity"] == "high,critical"
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement nuclei.py**

`src/bba/tools/nuclei.py`:
```python
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from bba.db import Database
from bba.tool_runner import ToolRunner


# Technology-to-template mapping
TECH_TAG_MAP = {
    "wordpress": "wordpress,wp-plugin,wp-theme",
    "joomla": "joomla",
    "drupal": "drupal",
    "apache": "apache",
    "nginx": "nginx",
    "iis": "iis",
    "tomcat": "tomcat",
    "jenkins": "jenkins",
    "grafana": "grafana",
    "gitlab": "gitlab",
}


class NucleiTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(
        self,
        targets: list[str],
        work_dir: Path,
        severity: str = "high,critical",
        rate_limit: int = 100,
        tags: str | None = None,
    ) -> list[str]:
        input_file = work_dir / "nuclei_targets.txt"
        input_file.write_text("\n".join(targets) + "\n")
        cmd = ["nuclei", "-l", str(input_file), "-json", "-silent"]
        if severity:
            cmd.extend(["-severity", severity])
        if rate_limit:
            cmd.extend(["-rl", str(rate_limit)])
        if tags:
            cmd.extend(["-tags", tags])
        return cmd

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results

    def select_scan_options(self, technologies: list[str]) -> dict:
        tags = []
        for tech in technologies:
            tech_lower = tech.lower()
            if tech_lower in TECH_TAG_MAP:
                tags.append(TECH_TAG_MAP[tech_lower])

        return {
            "severity": "high,critical",
            "tags": ",".join(tags) if tags else None,
        }

    async def run(
        self,
        targets: list[str],
        work_dir: Path,
        severity: str = "high,critical",
        rate_limit: int = 100,
        tags: str | None = None,
    ) -> dict:
        # Extract domains for scope validation
        domains = []
        for t in targets:
            parsed = urlparse(t)
            if parsed.hostname:
                domains.append(parsed.hostname)
            else:
                domains.append(t)

        result = await self.runner.run_command(
            tool="nuclei",
            command=self.build_command(targets, work_dir, severity, rate_limit, tags),
            targets=domains,
        )

        if not result.success:
            return {"total": 0, "findings": [], "by_severity": {}, "error": result.error}

        entries = self.parse_output(result.output)
        severity_counter: Counter = Counter()

        for entry in entries:
            info = entry.get("info", {})
            sev = info.get("severity", "unknown")
            severity_counter[sev] += 1

            matched_at = entry.get("matched-at", "")
            host = entry.get("host", "")
            parsed_host = urlparse(host)
            domain = parsed_host.hostname or host

            evidence_parts = []
            if entry.get("template-id"):
                evidence_parts.append(f"template: {entry['template-id']}")
            if entry.get("extracted-results"):
                evidence_parts.append(f"extracted: {entry['extracted-results']}")
            if entry.get("matcher-name"):
                evidence_parts.append(f"matcher: {entry['matcher-name']}")

            confidence = {"critical": 0.95, "high": 0.85, "medium": 0.7, "low": 0.5, "info": 0.3}.get(sev, 0.5)

            await self.db.add_finding(
                program=self.program,
                domain=domain,
                url=matched_at,
                vuln_type=info.get("name", entry.get("template-id", "unknown")),
                severity=sev,
                tool="nuclei",
                evidence="; ".join(evidence_parts),
                confidence=confidence,
            )

        return {
            "total": len(entries),
            "findings": [
                {"template": e.get("template-id"), "severity": e.get("info", {}).get("severity"), "url": e.get("matched-at")}
                for e in entries
            ],
            "by_severity": dict(severity_counter),
        }
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add src/bba/tools/nuclei.py tests/test_tools_nuclei.py
git commit -m "feat: nuclei wrapper with template selection and finding storage"
```

---

### Task 2: Ffuf Wrapper

**Files:**
- Create: `src/bba/tools/ffuf.py`
- Create: `tests/test_tools_ffuf.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_tools_ffuf.py`:
```python
import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.ffuf import FfufTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

FFUF_OUTPUT = json.dumps({
    "results": [
        {"input": {"FUZZ": "admin"}, "url": "https://shop.example.com/admin", "status": 200, "length": 4521, "words": 312},
        {"input": {"FUZZ": "backup"}, "url": "https://shop.example.com/backup", "status": 403, "length": 287, "words": 14},
        {"input": {"FUZZ": ".env"}, "url": "https://shop.example.com/.env", "status": 200, "length": 890, "words": 45},
    ]
})


@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))

@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(default_rps=100), sanitizer=Sanitizer(), output_dir=tmp_path / "output")

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestFfufTool:
    def test_builds_command(self, runner, db):
        tool = FfufTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(
            target_url="https://shop.example.com/FUZZ",
            wordlist="/usr/share/wordlists/common.txt",
        )
        assert "ffuf" in cmd
        assert "-u" in cmd
        assert "https://shop.example.com/FUZZ" in cmd
        assert "-w" in cmd
        assert "-json" in cmd
        assert "-fc" in cmd

    def test_parses_json_output(self, runner, db):
        tool = FfufTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(FFUF_OUTPUT)
        assert len(results) == 3
        assert results[0]["url"] == "https://shop.example.com/admin"
        assert results[2]["input"]["FUZZ"] == ".env"

    def test_parses_empty_output(self, runner, db):
        tool = FfufTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    async def test_run_stores_interesting_findings(self, runner, db):
        tool = FfufTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=FFUF_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(
                target_url="https://shop.example.com/FUZZ",
                wordlist="/usr/share/wordlists/common.txt",
            )

        assert summary["total"] == 3
        assert summary["interesting"] >= 1  # .env is interesting

    async def test_run_handles_failure(self, runner, db):
        tool = FfufTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="crash")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(
                target_url="https://shop.example.com/FUZZ",
                wordlist="/usr/share/wordlists/common.txt",
            )
        assert summary["total"] == 0
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement ffuf.py**

`src/bba/tools/ffuf.py`:
```python
from __future__ import annotations

import json
from urllib.parse import urlparse

from bba.db import Database
from bba.tool_runner import ToolRunner

INTERESTING_PATHS = {".env", "backup", ".git", "config", "debug", "phpinfo", "server-status", "wp-config"}
INTERESTING_STATUS = {200, 403}


class FfufTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(
        self,
        target_url: str,
        wordlist: str,
        filter_codes: str = "404",
    ) -> list[str]:
        return [
            "ffuf", "-u", target_url, "-w", wordlist,
            "-json", "-silent", "-fc", filter_codes,
        ]

    def parse_output(self, output: str) -> list[dict]:
        if not output.strip():
            return []
        try:
            data = json.loads(output)
            return data.get("results", [])
        except json.JSONDecodeError:
            return []

    def _is_interesting(self, result: dict) -> bool:
        fuzz_value = result.get("input", {}).get("FUZZ", "").lower()
        return any(p in fuzz_value for p in INTERESTING_PATHS)

    async def run(
        self,
        target_url: str,
        wordlist: str,
        filter_codes: str = "404",
    ) -> dict:
        parsed = urlparse(target_url)
        domain = parsed.hostname or ""

        result = await self.runner.run_command(
            tool="ffuf",
            command=self.build_command(target_url, wordlist, filter_codes),
            targets=[domain] if domain else [target_url],
        )

        if not result.success:
            return {"total": 0, "results": [], "interesting": 0, "error": result.error}

        entries = self.parse_output(result.output)
        interesting_count = 0

        for entry in entries:
            if self._is_interesting(entry):
                interesting_count += 1
                await self.db.add_finding(
                    program=self.program,
                    domain=domain,
                    url=entry.get("url", ""),
                    vuln_type="directory-exposure",
                    severity="medium",
                    tool="ffuf",
                    evidence=f"status={entry.get('status')}, length={entry.get('length')}, fuzz={entry.get('input', {}).get('FUZZ', '')}",
                    confidence=0.7,
                )

        return {
            "total": len(entries),
            "results": [{"url": e.get("url"), "status": e.get("status")} for e in entries],
            "interesting": interesting_count,
        }
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add src/bba/tools/ffuf.py tests/test_tools_ffuf.py
git commit -m "feat: ffuf wrapper with directory fuzzing and interesting path detection"
```

---

## Chunk 2: SQLMap, Dalfox, and Scan Pipeline

### Task 3: SQLMap and Dalfox Wrappers

**Files:**
- Create: `src/bba/tools/sqlmap_runner.py`
- Create: `src/bba/tools/dalfox.py`
- Create: `tests/test_tools_sqlmap.py`
- Create: `tests/test_tools_dalfox.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_tools_sqlmap.py`:
```python
import json
import pytest
from unittest.mock import patch

from bba.tools.sqlmap_runner import SqlmapTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

SQLMAP_OUTPUT = """[INFO] testing 'AND boolean-based blind'
[INFO] GET parameter 'id' is vulnerable
[INFO] the back-end DBMS is MySQL
[CRITICAL] parameter 'id' is vulnerable to SQL injection
back-end DBMS: MySQL >= 5.0
"""


@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))

@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(default_rps=100), sanitizer=Sanitizer(), output_dir=tmp_path / "output")

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestSqlmapTool:
    def test_builds_command(self, runner, db):
        tool = SqlmapTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://shop.example.com/product?id=1")
        assert "sqlmap" in cmd
        assert "-u" in cmd
        assert "--batch" in cmd

    def test_detects_vulnerability_in_output(self, runner, db):
        tool = SqlmapTool(runner=runner, db=db, program="test-corp")
        assert tool.is_vulnerable(SQLMAP_OUTPUT) is True

    def test_clean_output_not_vulnerable(self, runner, db):
        tool = SqlmapTool(runner=runner, db=db, program="test-corp")
        assert tool.is_vulnerable("[INFO] testing connection\n[INFO] all tested parameters do not appear to be injectable") is False

    async def test_run_stores_finding_when_vulnerable(self, runner, db):
        tool = SqlmapTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=SQLMAP_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://shop.example.com/product?id=1")

        assert summary["vulnerable"] is True
        findings = await db.get_findings("test-corp")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "sql-injection"

    async def test_run_no_finding_when_clean(self, runner, db):
        tool = SqlmapTool(runner=runner, db=db, program="test-corp")
        clean_output = "[INFO] all tested parameters do not appear to be injectable"
        mock_result = ToolResult(success=True, output=clean_output, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://shop.example.com/product?id=1")

        assert summary["vulnerable"] is False
        findings = await db.get_findings("test-corp")
        assert len(findings) == 0
```

`tests/test_tools_dalfox.py`:
```python
import json
import pytest
from unittest.mock import patch

from bba.tools.dalfox import DalfoxTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

DALFOX_OUTPUT = "\n".join([
    json.dumps({
        "type": "G",
        "inject_type": "inHTML-URL",
        "poc_type": "plain",
        "method": "GET",
        "data": "https://shop.example.com/search?q=%3Csvg%20onload%3Dalert(1)%3E",
        "param": "q",
        "payload": "<svg onload=alert(1)>",
        "evidence": "reflected",
    }),
]) + "\n"


@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))

@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(default_rps=100), sanitizer=Sanitizer(), output_dir=tmp_path / "output")

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestDalfoxTool:
    def test_builds_command(self, runner, db):
        tool = DalfoxTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("https://shop.example.com/search?q=test")
        assert "dalfox" in cmd
        assert "url" in cmd
        assert "--silence" in cmd
        assert "--format" in cmd
        assert "json" in cmd

    def test_parses_json_output(self, runner, db):
        tool = DalfoxTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(DALFOX_OUTPUT)
        assert len(results) == 1
        assert results[0]["param"] == "q"
        assert "alert(1)" in results[0]["payload"]

    async def test_run_stores_findings(self, runner, db):
        tool = DalfoxTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=DALFOX_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://shop.example.com/search?q=test")

        assert summary["total"] == 1
        findings = await db.get_findings("test-corp")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "xss"

    async def test_run_handles_no_findings(self, runner, db):
        tool = DalfoxTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output="", raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://shop.example.com/search?q=test")

        assert summary["total"] == 0

    async def test_run_handles_failure(self, runner, db):
        tool = DalfoxTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="crash")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("https://shop.example.com/search?q=test")

        assert summary["total"] == 0
        assert summary["error"] == "crash"
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement sqlmap_runner.py and dalfox.py**

`src/bba/tools/sqlmap_runner.py`:
```python
from __future__ import annotations

import re
from urllib.parse import urlparse

from bba.db import Database
from bba.tool_runner import ToolRunner

_VULN_PATTERN = re.compile(r"is vulnerable|injectable", re.I)
_NOT_VULN_PATTERN = re.compile(r"do not appear to be injectable|not vulnerable", re.I)


class SqlmapTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, target_url: str) -> list[str]:
        return ["sqlmap", "-u", target_url, "--batch", "--level=2", "--risk=2"]

    def is_vulnerable(self, output: str) -> bool:
        if _NOT_VULN_PATTERN.search(output):
            return False
        return bool(_VULN_PATTERN.search(output))

    async def run(self, target_url: str) -> dict:
        parsed = urlparse(target_url)
        domain = parsed.hostname or ""

        result = await self.runner.run_command(
            tool="sqlmap",
            command=self.build_command(target_url),
            targets=[domain] if domain else [target_url],
            timeout=300,
        )

        if not result.success:
            return {"vulnerable": False, "error": result.error}

        vulnerable = self.is_vulnerable(result.output)

        if vulnerable:
            await self.db.add_finding(
                program=self.program,
                domain=domain,
                url=target_url,
                vuln_type="sql-injection",
                severity="critical",
                tool="sqlmap",
                evidence=result.output[:2000],
                confidence=0.9,
            )

        return {"vulnerable": vulnerable, "url": target_url, "output_preview": result.output[:500]}
```

`src/bba/tools/dalfox.py`:
```python
from __future__ import annotations

import json
from urllib.parse import urlparse

from bba.db import Database
from bba.tool_runner import ToolRunner


class DalfoxTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, target_url: str) -> list[str]:
        return ["dalfox", "url", target_url, "--silence", "--format", "json"]

    def parse_output(self, output: str) -> list[dict]:
        results = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results

    async def run(self, target_url: str) -> dict:
        parsed = urlparse(target_url)
        domain = parsed.hostname or ""

        result = await self.runner.run_command(
            tool="dalfox",
            command=self.build_command(target_url),
            targets=[domain] if domain else [target_url],
        )

        if not result.success:
            return {"total": 0, "findings": [], "error": result.error}

        entries = self.parse_output(result.output)

        for entry in entries:
            await self.db.add_finding(
                program=self.program,
                domain=domain,
                url=entry.get("data", target_url),
                vuln_type="xss",
                severity="high",
                tool="dalfox",
                evidence=f"param={entry.get('param', '')}, payload={entry.get('payload', '')}, type={entry.get('inject_type', '')}",
                confidence=0.85,
            )

        return {
            "total": len(entries),
            "findings": [
                {"param": e.get("param"), "payload": e.get("payload"), "url": e.get("data")}
                for e in entries
            ],
        }
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add src/bba/tools/sqlmap_runner.py src/bba/tools/dalfox.py tests/test_tools_sqlmap.py tests/test_tools_dalfox.py
git commit -m "feat: sqlmap and dalfox wrappers for SQLi and XSS scanning"
```

---

### Task 4: Scanning Pipeline Orchestrator

**Files:**
- Create: `src/bba/tools/scan_pipeline.py`
- Create: `tests/test_tools_scan_pipeline.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_tools_scan_pipeline.py`:
```python
import pytest
from unittest.mock import patch, AsyncMock
from pathlib import Path

from bba.tools.scan_pipeline import ScanPipeline
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner
from bba.db import Database

SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}


@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))

@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(scope=scope, rate_limiter=MultiTargetRateLimiter(default_rps=100), sanitizer=Sanitizer(), output_dir=tmp_path / "output")

@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestScanPipeline:
    async def test_runs_nuclei_on_all_services(self, runner, db, tmp_path):
        # Pre-populate services
        await db.add_service("test-corp", "api.example.com", "1.2.3.4", 443, 200, "API", "nginx,python")
        await db.add_service("test-corp", "shop.example.com", "5.6.7.8", 443, 200, "Shop", "apache,wordpress")

        pipeline = ScanPipeline(runner=runner, db=db, program="test-corp", work_dir=tmp_path)

        nuclei_summary = {"total": 2, "findings": [], "by_severity": {"high": 1, "critical": 1}}

        with patch.object(pipeline, "_run_nuclei", return_value=nuclei_summary) as mock_nuclei:
            result = await pipeline.run()

        mock_nuclei.assert_called_once()
        assert result["nuclei"]["total"] == 2

    async def test_runs_ffuf_on_services(self, runner, db, tmp_path):
        await db.add_service("test-corp", "shop.example.com", "5.6.7.8", 443, 200, "Shop", "apache")

        pipeline = ScanPipeline(runner=runner, db=db, program="test-corp", work_dir=tmp_path)

        nuclei_summary = {"total": 0, "findings": [], "by_severity": {}}
        ffuf_summary = {"total": 5, "results": [], "interesting": 2}

        with patch.object(pipeline, "_run_nuclei", return_value=nuclei_summary), \
             patch.object(pipeline, "_run_ffuf", return_value=ffuf_summary):
            result = await pipeline.run()

        assert result["ffuf"]["total"] == 5

    async def test_skips_scan_when_no_services(self, runner, db, tmp_path):
        pipeline = ScanPipeline(runner=runner, db=db, program="test-corp", work_dir=tmp_path)
        result = await pipeline.run()
        assert result["nuclei"]["total"] == 0
        assert result["services_scanned"] == 0

    def test_format_summary(self, runner, db, tmp_path):
        pipeline = ScanPipeline(runner=runner, db=db, program="test-corp", work_dir=tmp_path)
        result = {
            "services_scanned": 10,
            "nuclei": {"total": 5, "by_severity": {"critical": 1, "high": 2, "medium": 2}},
            "ffuf": {"total": 20, "interesting": 3},
        }
        text = pipeline.format_summary(result)
        assert "10 services" in text
        assert "critical" in text.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement scan_pipeline.py**

`src/bba/tools/scan_pipeline.py`:
```python
from __future__ import annotations

from pathlib import Path

from bba.db import Database
from bba.tool_runner import ToolRunner
from bba.tools.nuclei import NucleiTool
from bba.tools.ffuf import FfufTool


DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


class ScanPipeline:
    def __init__(self, runner: ToolRunner, db: Database, program: str, work_dir: Path):
        self.runner = runner
        self.db = db
        self.program = program
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)

    async def _run_nuclei(
        self, targets: list[str], technologies: list[str],
    ) -> dict:
        tool = NucleiTool(runner=self.runner, db=self.db, program=self.program)
        opts = tool.select_scan_options(technologies=technologies)
        return await tool.run(
            targets=targets,
            work_dir=self.work_dir,
            severity=opts["severity"],
            tags=opts.get("tags"),
        )

    async def _run_ffuf(self, targets: list[str]) -> dict:
        tool = FfufTool(runner=self.runner, db=self.db, program=self.program)
        all_results = {"total": 0, "results": [], "interesting": 0}
        for target in targets:
            summary = await tool.run(
                target_url=f"{target}/FUZZ",
                wordlist=DEFAULT_WORDLIST,
            )
            all_results["total"] += summary.get("total", 0)
            all_results["results"].extend(summary.get("results", []))
            all_results["interesting"] += summary.get("interesting", 0)
        return all_results

    async def run(self) -> dict:
        services = await self.db.get_services(self.program)

        if not services:
            return {
                "services_scanned": 0,
                "nuclei": {"total": 0, "findings": [], "by_severity": {}},
                "ffuf": {"total": 0, "results": [], "interesting": 0},
            }

        # Build target URLs from services
        targets = []
        all_techs = []
        for svc in services:
            port = svc.get("port", 443)
            scheme = "https" if port == 443 else "http"
            targets.append(f"{scheme}://{svc['domain']}")
            if svc.get("technologies"):
                all_techs.extend(svc["technologies"].split(","))

        # Run nuclei across all targets
        nuclei_summary = await self._run_nuclei(targets, all_techs)

        # Run ffuf on each target
        ffuf_summary = await self._run_ffuf(targets)

        return {
            "services_scanned": len(services),
            "nuclei": nuclei_summary,
            "ffuf": ffuf_summary,
        }

    def format_summary(self, result: dict) -> str:
        lines = []
        lines.append(f"Scanned {result['services_scanned']} services")

        nuclei = result["nuclei"]
        if nuclei["total"] > 0:
            lines.append(f"Nuclei: {nuclei['total']} findings")
            for sev, count in nuclei.get("by_severity", {}).items():
                lines.append(f"  {sev}: {count}")
        else:
            lines.append("Nuclei: no findings")

        ffuf = result["ffuf"]
        lines.append(f"Ffuf: {ffuf['total']} paths found, {ffuf.get('interesting', 0)} interesting")

        return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add src/bba/tools/scan_pipeline.py tests/test_tools_scan_pipeline.py
git commit -m "feat: scanning pipeline orchestrator with nuclei and ffuf coordination"
```

---

## What Phase 3 Produces

- **4 scanner wrappers** — nuclei (with template selection), ffuf (with interesting path detection), sqlmap (with vulnerability detection), dalfox (with XSS finding storage)
- **1 scanning pipeline** — reads services from DB, selects tools by technology, coordinates scans
- **~25 new tests**

## What Comes Next (Phase 4)

Phase 4 builds the validator sub-agent: re-testing findings, generating PoC evidence with curl/Playwright, confidence scoring, and Markdown report generation.
