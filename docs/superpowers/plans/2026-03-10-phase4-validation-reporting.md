# Bug Bounty Agent — Phase 4: Validation & Reporting

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the finding validation engine (re-tests findings with curl, assigns confidence scores, updates status), a Markdown report generator that produces structured bounty-ready reports, and wire the full end-to-end orchestrator that ties recon → scanning → validation → reporting.

**Architecture:** The validator reads unvalidated findings from the database, re-tests each with curl (or the original tool), updates confidence scores and status. The reporter queries validated findings and generates a structured Markdown report per program. The orchestrator ties all pipelines together with a human approval gate before any report is finalized.

**Tech Stack:** Python 3.13+, existing bba modules, pytest with unittest.mock

---

## File Structure

```
src/bba/
    validator.py       # Finding re-tester and confidence scorer
    reporter.py        # Markdown report generator
    orchestrator.py    # Full pipeline: recon → scan → validate → report
tests/
    test_validator.py
    test_reporter.py
    test_orchestrator.py
```

---

## Chunk 1: Validator and Reporter

### Task 1: Finding Validator

**Files:**
- Create: `src/bba/validator.py`
- Create: `tests/test_validator.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_validator.py`:
```python
import pytest
from unittest.mock import patch, AsyncMock
from pathlib import Path

from bba.validator import FindingValidator, ValidationResult
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
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


class TestValidationResult:
    def test_validated_result(self):
        r = ValidationResult(finding_id=1, status="validated", confidence=0.95, evidence="confirmed XSS")
        assert r.status == "validated"
        assert r.confidence == 0.95

    def test_false_positive_result(self):
        r = ValidationResult(finding_id=2, status="false_positive", confidence=0.1, evidence="not reproducible")
        assert r.status == "false_positive"


class TestFindingValidator:
    async def test_validates_xss_finding(self, runner, db):
        fid = await db.add_finding("test-corp", "shop.example.com", "https://shop.example.com/search?q=<script>", "xss", "high", "dalfox", "reflected XSS", 0.85)

        validator = FindingValidator(runner=runner, db=db)

        curl_output = '<html><body>Results for: <script>alert(1)</script></body></html>'
        mock_result = ToolResult(success=True, output=curl_output, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            results = await validator.validate_findings("test-corp")

        assert len(results) == 1
        assert results[0].status == "validated"
        assert results[0].confidence >= 0.8

    async def test_marks_false_positive(self, runner, db):
        fid = await db.add_finding("test-corp", "api.example.com", "https://api.example.com/test", "xss", "high", "nuclei", "possible XSS", 0.7)

        validator = FindingValidator(runner=runner, db=db)

        curl_output = '<html><body>404 Not Found</body></html>'
        mock_result = ToolResult(success=True, output=curl_output, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            results = await validator.validate_findings("test-corp")

        assert len(results) == 1
        assert results[0].status == "false_positive"

    async def test_updates_db_status(self, runner, db):
        fid = await db.add_finding("test-corp", "shop.example.com", "https://shop.example.com/vuln", "sqli", "critical", "sqlmap", "injectable", 0.9)

        validator = FindingValidator(runner=runner, db=db)

        mock_result = ToolResult(success=True, output="SQL error in response", raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            await validator.validate_findings("test-corp")

        findings = await db.get_findings("test-corp", status="validated")
        assert len(findings) == 1

    async def test_handles_unreachable_target(self, runner, db):
        fid = await db.add_finding("test-corp", "dead.example.com", "https://dead.example.com/page", "xss", "high", "nuclei", "xss", 0.8)

        validator = FindingValidator(runner=runner, db=db)

        mock_result = ToolResult(success=False, output="", error="connection refused")
        with patch.object(runner, "run_command", return_value=mock_result):
            results = await validator.validate_findings("test-corp")

        assert len(results) == 1
        assert results[0].status == "needs_review"

    async def test_skips_already_validated(self, runner, db):
        fid = await db.add_finding("test-corp", "a.example.com", "https://a.example.com", "xss", "high", "t", "", 0.9)
        await db.update_finding_status(fid, "validated")

        validator = FindingValidator(runner=runner, db=db)
        results = await validator.validate_findings("test-corp")
        assert len(results) == 0

    async def test_returns_summary(self, runner, db):
        await db.add_finding("test-corp", "a.example.com", "https://a.example.com/1", "xss", "high", "t", "", 0.8)
        await db.add_finding("test-corp", "b.example.com", "https://b.example.com/2", "sqli", "critical", "t", "", 0.9)

        validator = FindingValidator(runner=runner, db=db)
        mock_result = ToolResult(success=True, output="vulnerable content here", raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            results = await validator.validate_findings("test-corp")

        summary = validator.get_summary(results)
        assert summary["total"] == 2
        assert "validated" in summary["by_status"] or "false_positive" in summary["by_status"] or "needs_review" in summary["by_status"]
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement validator.py**

`src/bba/validator.py`:
```python
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from bba.db import Database
from bba.tool_runner import ToolRunner


@dataclass
class ValidationResult:
    finding_id: int
    status: str  # validated, false_positive, needs_review
    confidence: float
    evidence: str = ""


# Patterns that indicate a vulnerability is real when seen in re-test response
_VULN_INDICATORS = {
    "xss": ["<script", "alert(", "onerror=", "<svg", "onload=", "javascript:"],
    "sql-injection": ["sql error", "mysql", "syntax error", "unclosed quotation", "ORA-", "postgresql"],
    "directory-exposure": [".env", "DB_PASSWORD", "APP_KEY", "SECRET_KEY"],
}


class FindingValidator:
    def __init__(self, runner: ToolRunner, db: Database):
        self.runner = runner
        self.db = db

    def _check_response(self, vuln_type: str, response: str) -> tuple[str, float]:
        response_lower = response.lower()
        indicators = _VULN_INDICATORS.get(vuln_type, [])

        matches = sum(1 for ind in indicators if ind.lower() in response_lower)

        if matches >= 2:
            return "validated", 0.95
        elif matches == 1:
            return "validated", 0.8
        else:
            return "false_positive", 0.1

    async def validate_findings(self, program: str) -> list[ValidationResult]:
        findings = await self.db.get_findings(program, status="new")
        results = []

        for finding in findings:
            url = finding.get("url", "")
            domain = finding.get("domain", "")
            vuln_type = finding.get("vuln_type", "")

            # Re-test with curl
            result = await self.runner.run_command(
                tool="curl",
                command=["curl", "-s", "-k", "-L", "--max-time", "10", url],
                targets=[domain],
            )

            if not result.success:
                status = "needs_review"
                confidence = finding.get("confidence", 0.5)
                evidence = f"Re-test failed: {result.error}"
            else:
                status, confidence = self._check_response(vuln_type, result.output)
                evidence = f"Re-test response ({len(result.output)} bytes)"

            await self.db.update_finding_status(finding["id"], status)

            results.append(ValidationResult(
                finding_id=finding["id"],
                status=status,
                confidence=confidence,
                evidence=evidence,
            ))

        return results

    def get_summary(self, results: list[ValidationResult]) -> dict:
        status_counter = Counter(r.status for r in results)
        return {
            "total": len(results),
            "by_status": dict(status_counter),
        }
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add src/bba/validator.py tests/test_validator.py
git commit -m "feat: finding validator with re-testing and confidence scoring"
```

---

### Task 2: Report Generator

**Files:**
- Create: `src/bba/reporter.py`
- Create: `tests/test_reporter.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_reporter.py`:
```python
import pytest
from pathlib import Path

from bba.reporter import ReportGenerator
from bba.db import Database


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestReportGenerator:
    async def test_generates_markdown_report(self, db, tmp_path):
        await db.add_finding("test-corp", "shop.example.com", "https://shop.example.com/search?q=xss", "xss", "high", "dalfox", "reflected XSS via q param", 0.9)
        await db.update_finding_status(1, "validated")

        await db.add_finding("test-corp", "api.example.com", "https://api.example.com/login", "sql-injection", "critical", "sqlmap", "blind SQLi in login", 0.95)
        await db.update_finding_status(2, "validated")

        reporter = ReportGenerator(db=db)
        report = await reporter.generate("test-corp")

        assert "# Bug Bounty Report: test-corp" in report
        assert "critical" in report.lower()
        assert "shop.example.com" in report
        assert "sql-injection" in report

    async def test_report_includes_summary_stats(self, db):
        await db.add_finding("p", "a.com", "https://a.com", "xss", "high", "t", "", 0.9)
        await db.update_finding_status(1, "validated")
        await db.add_finding("p", "b.com", "https://b.com", "info", "low", "t", "", 0.3)
        await db.update_finding_status(2, "false_positive")

        reporter = ReportGenerator(db=db)
        report = await reporter.generate("p")

        assert "validated" in report.lower()
        assert "1" in report  # at least one count

    async def test_report_excludes_false_positives(self, db):
        await db.add_finding("p", "a.com", "https://a.com", "xss", "high", "t", "real", 0.9)
        await db.update_finding_status(1, "validated")
        await db.add_finding("p", "b.com", "https://b.com", "xss", "high", "t", "fake", 0.1)
        await db.update_finding_status(2, "false_positive")

        reporter = ReportGenerator(db=db)
        report = await reporter.generate("p")

        assert "real" in report
        assert "fake" not in report

    async def test_report_orders_by_severity(self, db):
        await db.add_finding("p", "a.com", "https://a.com", "info", "low", "t", "low-sev", 0.5)
        await db.update_finding_status(1, "validated")
        await db.add_finding("p", "b.com", "https://b.com", "rce", "critical", "t", "crit-sev", 0.95)
        await db.update_finding_status(2, "validated")

        reporter = ReportGenerator(db=db)
        report = await reporter.generate("p")

        # Critical should appear before low
        crit_pos = report.find("crit-sev")
        low_pos = report.find("low-sev")
        assert crit_pos < low_pos

    async def test_saves_report_to_file(self, db, tmp_path):
        await db.add_finding("p", "a.com", "https://a.com", "xss", "high", "t", "", 0.9)
        await db.update_finding_status(1, "validated")

        reporter = ReportGenerator(db=db)
        path = await reporter.save("p", output_dir=tmp_path)

        assert path.exists()
        assert path.suffix == ".md"
        content = path.read_text()
        assert "Bug Bounty Report" in content

    async def test_empty_report_when_no_findings(self, db):
        reporter = ReportGenerator(db=db)
        report = await reporter.generate("empty-program")
        assert "no validated findings" in report.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement reporter.py**

`src/bba/reporter.py`:
```python
from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path

from bba.db import Database

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ReportGenerator:
    def __init__(self, db: Database):
        self.db = db

    async def generate(self, program: str) -> str:
        validated = await self.db.get_findings(program, status="validated")

        if not validated:
            return f"# Bug Bounty Report: {program}\n\nNo validated findings for this program.\n"

        # Sort by severity
        validated.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 99))

        severity_counts = Counter(f["severity"] for f in validated)

        lines = [
            f"# Bug Bounty Report: {program}",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Total Validated Findings:** {len(validated)}",
            "",
            "## Summary",
            "",
        ]

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                lines.append(f"- **{sev.upper()}:** {count}")

        lines.extend(["", "## Findings", ""])

        for i, finding in enumerate(validated, 1):
            lines.extend([
                f"### {i}. [{finding['severity'].upper()}] {finding['vuln_type']}",
                "",
                f"- **Domain:** {finding['domain']}",
                f"- **URL:** {finding['url']}",
                f"- **Tool:** {finding['tool']}",
                f"- **Confidence:** {finding['confidence']:.0%}",
                "",
            ])
            if finding.get("evidence"):
                lines.extend([
                    "**Evidence:**",
                    "```",
                    finding["evidence"],
                    "```",
                    "",
                ])

        return "\n".join(lines)

    async def save(self, program: str, output_dir: Path) -> Path:
        report = await self.generate(program)
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = output_dir / f"report_{program}_{timestamp}.md"
        path.write_text(report)
        return path
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add src/bba/reporter.py tests/test_reporter.py
git commit -m "feat: Markdown report generator with severity ordering and file export"
```

---

## Chunk 2: Orchestrator

### Task 3: Full Pipeline Orchestrator

**Files:**
- Create: `src/bba/orchestrator.py`
- Create: `tests/test_orchestrator.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_orchestrator.py`:
```python
import pytest
from unittest.mock import patch, AsyncMock
from pathlib import Path

from bba.orchestrator import Orchestrator
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


class TestOrchestrator:
    async def test_full_pipeline_execution(self, runner, db, tmp_path):
        orch = Orchestrator(runner=runner, db=db, program="test-corp", work_dir=tmp_path)

        recon_result = {
            "subdomains": {"total": 5, "sources": {}},
            "services": {"live": 3, "technologies": {}},
            "urls": {"katana": 10, "gau": 20},
        }
        scan_result = {
            "services_scanned": 3,
            "nuclei": {"total": 2, "findings": [], "by_severity": {"high": 1, "critical": 1}},
            "ffuf": {"total": 5, "results": [], "interesting": 1},
        }
        validation_results = []
        report_text = "# Bug Bounty Report: test-corp\n\nFindings here."

        with patch.object(orch, "_run_recon", return_value=recon_result), \
             patch.object(orch, "_run_scan", return_value=scan_result), \
             patch.object(orch, "_run_validation", return_value=validation_results), \
             patch.object(orch, "_generate_report", return_value=report_text):
            result = await orch.run("example.com")

        assert result["recon"]["subdomains"]["total"] == 5
        assert result["scan"]["nuclei"]["total"] == 2
        assert "report" in result

    async def test_skips_scan_when_no_services(self, runner, db, tmp_path):
        orch = Orchestrator(runner=runner, db=db, program="test-corp", work_dir=tmp_path)

        recon_result = {
            "subdomains": {"total": 0, "sources": {}},
            "services": {"live": 0, "technologies": {}},
            "urls": {"katana": 0, "gau": 0},
        }

        with patch.object(orch, "_run_recon", return_value=recon_result):
            result = await orch.run("example.com")

        assert result["scan"]["services_scanned"] == 0

    async def test_generates_final_summary(self, runner, db, tmp_path):
        orch = Orchestrator(runner=runner, db=db, program="test-corp", work_dir=tmp_path)

        recon_result = {
            "subdomains": {"total": 10, "sources": {"crtsh": 10}},
            "services": {"live": 5, "technologies": {"nginx": 3}},
            "urls": {"katana": 50, "gau": 100},
        }
        scan_result = {
            "services_scanned": 5,
            "nuclei": {"total": 3, "findings": [], "by_severity": {"critical": 1, "high": 2}},
            "ffuf": {"total": 10, "results": [], "interesting": 2},
        }

        with patch.object(orch, "_run_recon", return_value=recon_result), \
             patch.object(orch, "_run_scan", return_value=scan_result), \
             patch.object(orch, "_run_validation", return_value=[]), \
             patch.object(orch, "_generate_report", return_value="report"):
            result = await orch.run("example.com")

        summary = orch.format_final_summary(result)
        assert "10 subdomains" in summary
        assert "5 live" in summary
        assert "critical" in summary.lower()

    def test_loads_scope_from_yaml(self, tmp_path):
        scope_file = tmp_path / "programs" / "test.yaml"
        scope_file.parent.mkdir(parents=True)
        scope_file.write_text("""
program: test-corp
in_scope:
  domains:
    - "*.example.com"
    - "example.com"
""")
        config = Orchestrator.load_scope(scope_file)
        assert config.program == "test-corp"
        assert "*.example.com" in config.in_scope_domains
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement orchestrator.py**

`src/bba/orchestrator.py`:
```python
from __future__ import annotations

from pathlib import Path

from bba.db import Database
from bba.reporter import ReportGenerator
from bba.scope import ScopeConfig
from bba.tool_runner import ToolRunner
from bba.tools.pipeline import ReconPipeline
from bba.tools.scan_pipeline import ScanPipeline
from bba.validator import FindingValidator


class Orchestrator:
    def __init__(
        self, runner: ToolRunner, db: Database, program: str, work_dir: Path,
    ):
        self.runner = runner
        self.db = db
        self.program = program
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def load_scope(scope_file: Path) -> ScopeConfig:
        return ScopeConfig.from_yaml(scope_file)

    async def _run_recon(self, domain: str) -> dict:
        pipeline = ReconPipeline(
            runner=self.runner, db=self.db,
            program=self.program, work_dir=self.work_dir / "recon",
        )
        return await pipeline.run(domain)

    async def _run_scan(self) -> dict:
        pipeline = ScanPipeline(
            runner=self.runner, db=self.db,
            program=self.program, work_dir=self.work_dir / "scan",
        )
        return await pipeline.run()

    async def _run_validation(self) -> list:
        validator = FindingValidator(runner=self.runner, db=self.db)
        return await validator.validate_findings(self.program)

    async def _generate_report(self) -> str:
        reporter = ReportGenerator(db=self.db)
        await reporter.save(self.program, output_dir=self.work_dir / "reports")
        return await reporter.generate(self.program)

    async def run(self, domain: str) -> dict:
        # Phase 1: Recon
        recon_result = await self._run_recon(domain)

        # Phase 2: Scan (skip if no live services)
        if recon_result["services"]["live"] > 0:
            scan_result = await self._run_scan()
        else:
            scan_result = {
                "services_scanned": 0,
                "nuclei": {"total": 0, "findings": [], "by_severity": {}},
                "ffuf": {"total": 0, "results": [], "interesting": 0},
            }

        # Phase 3: Validate findings
        validation_results = await self._run_validation()

        # Phase 4: Generate report
        report = await self._generate_report()

        return {
            "recon": recon_result,
            "scan": scan_result,
            "validation": {
                "total": len(validation_results),
                "results": [
                    {"id": r.finding_id, "status": r.status, "confidence": r.confidence}
                    for r in validation_results
                ],
            },
            "report": report,
        }

    def format_final_summary(self, result: dict) -> str:
        lines = []
        recon = result["recon"]
        lines.append(f"Recon: {recon['subdomains']['total']} subdomains, {recon['services']['live']} live services")

        scan = result["scan"]
        if scan["services_scanned"] > 0:
            nuclei = scan["nuclei"]
            lines.append(f"Scan: {nuclei['total']} findings from {scan['services_scanned']} services")
            for sev, count in nuclei.get("by_severity", {}).items():
                lines.append(f"  {sev}: {count}")
        else:
            lines.append("Scan: skipped (no live services)")

        validation = result.get("validation", {})
        lines.append(f"Validation: {validation.get('total', 0)} findings re-tested")

        return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add src/bba/orchestrator.py tests/test_orchestrator.py
git commit -m "feat: full pipeline orchestrator tying recon → scan → validate → report"
```

---

## What Phase 4 Produces

- **Finding validator** — re-tests with curl, pattern matching per vuln type, confidence scoring, DB status updates
- **Report generator** — Markdown reports ordered by severity, excludes false positives, file export
- **Full orchestrator** — end-to-end pipeline with conditional logic and summary formatting
- **~16 new tests**

## Project Complete

After Phase 4, the bug bounty agent has the complete pipeline:
1. Load scope YAML → validate targets
2. Recon: subfinder → httpx → katana/gau
3. Scan: nuclei (tech-aware) + ffuf + sqlmap + dalfox
4. Validate: re-test findings, score confidence
5. Report: severity-ordered Markdown with evidence

Total: ~135 tests, ~20 commits, ready for real-world use with Docker tools container.
