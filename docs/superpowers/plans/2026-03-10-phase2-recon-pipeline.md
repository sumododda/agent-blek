# Bug Bounty Agent — Phase 2: Recon Pipeline

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Python tool wrappers for recon tools (subfinder, httpx, katana, gau) that parse JSON output into the database and produce LLM-friendly summaries, plus a pipeline orchestrator that chains them.

**Architecture:** Each tool wrapper builds CLI commands, runs them through ToolRunner (which enforces scope/rate/sanitization), parses JSON lines from stdout, stores structured results in the database, and returns a summary dict. The pipeline orchestrator chains wrappers in sequence: subfinder → httpx → katana/gau. Since tools may not be installed on the dev machine, tests mock subprocess execution.

**Tech Stack:** Python 3.13+, existing bba modules (ToolRunner, Database, ScopeValidator), pytest with unittest.mock

---

## File Structure

```
src/bba/tools/
    __init__.py
    subfinder.py      # Subdomain enumeration wrapper
    httpx_runner.py   # HTTP probing wrapper (named to avoid collision with httpx package)
    katana.py         # URL crawling wrapper
    gau.py            # URL harvesting from archives
    pipeline.py       # Orchestrates recon flow
tests/
    test_tools_subfinder.py
    test_tools_httpx.py
    test_tools_katana.py
    test_tools_gau.py
    test_tools_pipeline.py
```

---

## Chunk 1: Tool Wrappers

### Task 1: Subfinder Wrapper

**Files:**
- Create: `src/bba/tools/__init__.py`
- Create: `src/bba/tools/subfinder.py`
- Create: `tests/test_tools_subfinder.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_tools_subfinder.py`:
```python
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path

from bba.tools.subfinder import SubfinderTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database


SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

SUBFINDER_OUTPUT = "\n".join([
    json.dumps({"host": "api.example.com", "source": "crtsh"}),
    json.dumps({"host": "shop.example.com", "source": "virustotal"}),
    json.dumps({"host": "mail.example.com", "source": "hackertarget"}),
]) + "\n"


@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))


@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(
        scope=scope,
        rate_limiter=MultiTargetRateLimiter(default_rps=100),
        sanitizer=Sanitizer(),
        output_dir=tmp_path / "output",
    )


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestSubfinderTool:
    def test_builds_command(self, runner, db):
        tool = SubfinderTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("example.com")
        assert "subfinder" in cmd
        assert "-d" in cmd
        assert "example.com" in cmd
        assert "-silent" in cmd
        assert "-json" in cmd

    def test_parses_json_output(self, runner, db):
        tool = SubfinderTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(SUBFINDER_OUTPUT)
        assert len(results) == 3
        assert results[0]["host"] == "api.example.com"
        assert results[1]["source"] == "virustotal"

    def test_parses_empty_output(self, runner, db):
        tool = SubfinderTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output("")
        assert results == []

    def test_parses_output_with_invalid_lines(self, runner, db):
        tool = SubfinderTool(runner=runner, db=db, program="test-corp")
        output = json.dumps({"host": "a.example.com", "source": "x"}) + "\nbad line\n"
        results = tool.parse_output(output)
        assert len(results) == 1

    async def test_run_stores_in_db(self, runner, db):
        tool = SubfinderTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(
            success=True,
            output=SUBFINDER_OUTPUT,
            raw_file=Path("/tmp/test.json"),
        )
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")

        subs = await db.get_subdomains("test-corp")
        assert len(subs) == 3
        assert summary["total"] == 3
        assert summary["sources"]["crtsh"] == 1

    async def test_run_returns_summary(self, runner, db):
        tool = SubfinderTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=SUBFINDER_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")

        assert "total" in summary
        assert "domains" in summary
        assert "sources" in summary

    async def test_run_handles_failure(self, runner, db):
        tool = SubfinderTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="not found")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")

        assert summary["total"] == 0
        assert summary["error"] == "not found"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_tools_subfinder.py -v`

- [ ] **Step 3: Implement subfinder.py**

`src/bba/tools/__init__.py` — empty file

`src/bba/tools/subfinder.py`:
```python
from __future__ import annotations

import json
from collections import Counter

from bba.db import Database
from bba.tool_runner import ToolRunner


class SubfinderTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, domain: str) -> list[str]:
        return ["subfinder", "-d", domain, "-silent", "-json"]

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

    async def run(self, domain: str) -> dict:
        result = await self.runner.run_command(
            tool="subfinder",
            command=self.build_command(domain),
            targets=[domain],
        )

        if not result.success:
            return {"total": 0, "domains": [], "sources": {}, "error": result.error}

        entries = self.parse_output(result.output)
        domains = [e["host"] for e in entries if "host" in e]
        sources = Counter(e.get("source", "unknown") for e in entries)

        if domains:
            await self.db.add_subdomains_bulk(self.program, domains, "subfinder")

        return {
            "total": len(domains),
            "domains": domains,
            "sources": dict(sources),
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_tools_subfinder.py -v`

- [ ] **Step 5: Commit**

```bash
git add src/bba/tools/ tests/test_tools_subfinder.py
git commit -m "feat: subfinder tool wrapper with JSON parsing and DB storage"
```

---

### Task 2: Httpx Runner Wrapper

**Files:**
- Create: `src/bba/tools/httpx_runner.py`
- Create: `tests/test_tools_httpx.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_tools_httpx.py`:
```python
import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.httpx_runner import HttpxTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database


SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

HTTPX_OUTPUT = "\n".join([
    json.dumps({
        "input": "api.example.com",
        "url": "https://api.example.com",
        "status_code": 200,
        "title": "API Docs",
        "host": "1.2.3.4",
        "port": "443",
        "tech": ["nginx", "python"],
    }),
    json.dumps({
        "input": "shop.example.com",
        "url": "https://shop.example.com",
        "status_code": 301,
        "title": "Shop",
        "host": "5.6.7.8",
        "port": "443",
        "tech": ["apache", "php", "wordpress"],
    }),
]) + "\n"


@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))


@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(
        scope=scope,
        rate_limiter=MultiTargetRateLimiter(default_rps=100),
        sanitizer=Sanitizer(),
        output_dir=tmp_path / "output",
    )


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestHttpxTool:
    def test_builds_command_from_list(self, runner, db, tmp_path):
        tool = HttpxTool(runner=runner, db=db, program="test-corp")
        domains = ["api.example.com", "shop.example.com"]
        cmd = tool.build_command(domains, tmp_path)
        assert "httpx" in cmd
        assert "-silent" in cmd
        assert "-json" in cmd
        assert "-l" in cmd

    def test_parses_json_output(self, runner, db):
        tool = HttpxTool(runner=runner, db=db, program="test-corp")
        results = tool.parse_output(HTTPX_OUTPUT)
        assert len(results) == 2
        assert results[0]["status_code"] == 200
        assert "nginx" in results[0]["tech"]

    async def test_run_stores_services_in_db(self, runner, db, tmp_path):
        tool = HttpxTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=HTTPX_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(
                ["api.example.com", "shop.example.com"],
                work_dir=tmp_path,
            )

        services = await db.get_services("test-corp")
        assert len(services) == 2
        assert summary["live"] == 2
        assert "wordpress" in summary["technologies"]

    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = HttpxTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="timeout")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["api.example.com"], work_dir=tmp_path)

        assert summary["live"] == 0
        assert summary["error"] == "timeout"

    async def test_summary_includes_tech_counts(self, runner, db, tmp_path):
        tool = HttpxTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=HTTPX_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["a.example.com"], work_dir=tmp_path)

        assert summary["technologies"]["nginx"] == 1
        assert summary["technologies"]["wordpress"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement httpx_runner.py**

`src/bba/tools/httpx_runner.py`:
```python
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from bba.db import Database
from bba.tool_runner import ToolRunner


class HttpxTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, domains: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "httpx_input.txt"
        input_file.write_text("\n".join(domains) + "\n")
        return ["httpx", "-l", str(input_file), "-silent", "-json"]

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

    async def run(self, domains: list[str], work_dir: Path) -> dict:
        result = await self.runner.run_command(
            tool="httpx",
            command=self.build_command(domains, work_dir),
            targets=domains,
        )

        if not result.success:
            return {"live": 0, "services": [], "technologies": {}, "error": result.error}

        entries = self.parse_output(result.output)
        tech_counter: Counter = Counter()

        for entry in entries:
            domain = entry.get("input", "")
            ip = entry.get("host", "")
            port = int(entry.get("port", 0))
            status_code = entry.get("status_code", 0)
            title = entry.get("title", "")
            techs = entry.get("tech", [])
            tech_str = ",".join(techs) if techs else ""

            for t in techs:
                tech_counter[t.lower()] += 1

            if domain:
                await self.db.add_service(
                    self.program, domain, ip, port, status_code, title, tech_str
                )

        return {
            "live": len(entries),
            "services": [e.get("input", "") for e in entries],
            "technologies": dict(tech_counter),
        }
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add src/bba/tools/httpx_runner.py tests/test_tools_httpx.py
git commit -m "feat: httpx tool wrapper with service probing and tech detection"
```

---

### Task 3: Katana and Gau Wrappers

**Files:**
- Create: `src/bba/tools/katana.py`
- Create: `src/bba/tools/gau.py`
- Create: `tests/test_tools_katana.py`
- Create: `tests/test_tools_gau.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_tools_katana.py`:
```python
import json
import pytest
from unittest.mock import patch
from pathlib import Path

from bba.tools.katana import KatanaTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database


SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

KATANA_OUTPUT = "\n".join([
    json.dumps({"request": {"endpoint": "https://shop.example.com/products"}}),
    json.dumps({"request": {"endpoint": "https://shop.example.com/cart"}}),
    json.dumps({"request": {"endpoint": "https://shop.example.com/api/v1/items"}}),
]) + "\n"


@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))


@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(
        scope=scope,
        rate_limiter=MultiTargetRateLimiter(default_rps=100),
        sanitizer=Sanitizer(),
        output_dir=tmp_path / "output",
    )


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestKatanaTool:
    def test_builds_command(self, runner, db, tmp_path):
        tool = KatanaTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command(["https://shop.example.com"], tmp_path)
        assert "katana" in cmd
        assert "-silent" in cmd
        assert "-json" in cmd

    def test_parses_json_output(self, runner, db):
        tool = KatanaTool(runner=runner, db=db, program="test-corp")
        urls = tool.parse_output(KATANA_OUTPUT)
        assert len(urls) == 3
        assert "https://shop.example.com/products" in urls

    async def test_run_returns_url_count(self, runner, db, tmp_path):
        tool = KatanaTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=KATANA_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["https://shop.example.com"], work_dir=tmp_path)

        assert summary["total"] == 3
        assert len(summary["urls"]) == 3

    async def test_run_handles_failure(self, runner, db, tmp_path):
        tool = KatanaTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="crash")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run(["https://shop.example.com"], work_dir=tmp_path)

        assert summary["total"] == 0
```

`tests/test_tools_gau.py`:
```python
import pytest
from unittest.mock import patch

from bba.tools.gau import GauTool
from bba.scope import ScopeConfig, ScopeValidator
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.tool_runner import ToolRunner, ToolResult
from bba.db import Database


SCOPE = {
    "program": "test-corp",
    "in_scope": {"domains": ["*.example.com", "example.com"]},
}

GAU_OUTPUT = "https://example.com/login\nhttps://example.com/api/users\nhttps://example.com/search?q=test\n"


@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig.from_dict(SCOPE))


@pytest.fixture
def runner(scope, tmp_path):
    return ToolRunner(
        scope=scope,
        rate_limiter=MultiTargetRateLimiter(default_rps=100),
        sanitizer=Sanitizer(),
        output_dir=tmp_path / "output",
    )


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestGauTool:
    def test_builds_command(self, runner, db):
        tool = GauTool(runner=runner, db=db, program="test-corp")
        cmd = tool.build_command("example.com")
        assert "gau" in cmd
        assert "example.com" in cmd

    def test_parses_plain_output(self, runner, db):
        tool = GauTool(runner=runner, db=db, program="test-corp")
        urls = tool.parse_output(GAU_OUTPUT)
        assert len(urls) == 3
        assert "https://example.com/login" in urls

    def test_parses_empty_output(self, runner, db):
        tool = GauTool(runner=runner, db=db, program="test-corp")
        urls = tool.parse_output("")
        assert urls == []

    async def test_run_returns_summary(self, runner, db):
        tool = GauTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=True, output=GAU_OUTPUT, raw_file=None)
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")

        assert summary["total"] == 3
        assert len(summary["urls"]) == 3

    async def test_run_handles_failure(self, runner, db):
        tool = GauTool(runner=runner, db=db, program="test-corp")
        mock_result = ToolResult(success=False, output="", error="err")
        with patch.object(runner, "run_command", return_value=mock_result):
            summary = await tool.run("example.com")

        assert summary["total"] == 0
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement katana.py and gau.py**

`src/bba/tools/katana.py`:
```python
from __future__ import annotations

import json
from pathlib import Path

from bba.db import Database
from bba.tool_runner import ToolRunner


class KatanaTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, targets: list[str], work_dir: Path) -> list[str]:
        input_file = work_dir / "katana_input.txt"
        input_file.write_text("\n".join(targets) + "\n")
        return ["katana", "-list", str(input_file), "-silent", "-json"]

    def parse_output(self, output: str) -> list[str]:
        urls = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                endpoint = data.get("request", {}).get("endpoint", "")
                if endpoint:
                    urls.append(endpoint)
            except json.JSONDecodeError:
                continue
        return urls

    async def run(self, targets: list[str], work_dir: Path) -> dict:
        # Extract domains from URLs for scope validation
        from urllib.parse import urlparse
        domains = []
        for t in targets:
            parsed = urlparse(t)
            if parsed.hostname:
                domains.append(parsed.hostname)

        result = await self.runner.run_command(
            tool="katana",
            command=self.build_command(targets, work_dir),
            targets=domains or targets,
        )

        if not result.success:
            return {"total": 0, "urls": [], "error": result.error}

        urls = self.parse_output(result.output)
        return {"total": len(urls), "urls": urls}
```

`src/bba/tools/gau.py`:
```python
from __future__ import annotations

from bba.db import Database
from bba.tool_runner import ToolRunner


class GauTool:
    def __init__(self, runner: ToolRunner, db: Database, program: str):
        self.runner = runner
        self.db = db
        self.program = program

    def build_command(self, domain: str) -> list[str]:
        return ["gau", domain]

    def parse_output(self, output: str) -> list[str]:
        urls = []
        for line in output.strip().splitlines():
            line = line.strip()
            if line:
                urls.append(line)
        return urls

    async def run(self, domain: str) -> dict:
        result = await self.runner.run_command(
            tool="gau",
            command=self.build_command(domain),
            targets=[domain],
        )

        if not result.success:
            return {"total": 0, "urls": [], "error": result.error}

        urls = self.parse_output(result.output)
        return {"total": len(urls), "urls": urls}
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add src/bba/tools/katana.py src/bba/tools/gau.py tests/test_tools_katana.py tests/test_tools_gau.py
git commit -m "feat: katana and gau tool wrappers for URL harvesting"
```

---

## Chunk 2: Pipeline Orchestrator

### Task 4: Recon Pipeline

**Files:**
- Create: `src/bba/tools/pipeline.py`
- Create: `tests/test_tools_pipeline.py`

The pipeline chains tools in sequence and produces a combined summary.

- [ ] **Step 1: Write the failing tests**

`tests/test_tools_pipeline.py`:
```python
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path

from bba.tools.pipeline import ReconPipeline
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
    return ToolRunner(
        scope=scope,
        rate_limiter=MultiTargetRateLimiter(default_rps=100),
        sanitizer=Sanitizer(),
        output_dir=tmp_path / "output",
    )


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


class TestReconPipeline:
    async def test_pipeline_runs_subfinder_then_httpx(self, runner, db, tmp_path):
        pipeline = ReconPipeline(
            runner=runner, db=db, program="test-corp", work_dir=tmp_path
        )

        subfinder_summary = {
            "total": 3,
            "domains": ["api.example.com", "shop.example.com", "mail.example.com"],
            "sources": {"crtsh": 2, "virustotal": 1},
        }
        httpx_summary = {
            "live": 2,
            "services": ["api.example.com", "shop.example.com"],
            "technologies": {"nginx": 1, "apache": 1},
        }
        katana_summary = {"total": 5, "urls": ["https://api.example.com/v1"] * 5}
        gau_summary = {"total": 10, "urls": ["https://example.com/page"] * 10}

        with patch.object(pipeline, "_run_subfinder", return_value=subfinder_summary), \
             patch.object(pipeline, "_run_httpx", return_value=httpx_summary), \
             patch.object(pipeline, "_run_katana", return_value=katana_summary), \
             patch.object(pipeline, "_run_gau", return_value=gau_summary):
            result = await pipeline.run("example.com")

        assert result["subdomains"]["total"] == 3
        assert result["services"]["live"] == 2
        assert result["urls"]["katana"] == 5
        assert result["urls"]["gau"] == 10

    async def test_pipeline_skips_httpx_when_no_subdomains(self, runner, db, tmp_path):
        pipeline = ReconPipeline(
            runner=runner, db=db, program="test-corp", work_dir=tmp_path
        )

        subfinder_summary = {"total": 0, "domains": [], "sources": {}}

        with patch.object(pipeline, "_run_subfinder", return_value=subfinder_summary) as sf_mock:
            result = await pipeline.run("example.com")

        assert result["subdomains"]["total"] == 0
        assert result["services"]["live"] == 0

    def test_format_summary_for_llm(self, runner, db, tmp_path):
        pipeline = ReconPipeline(
            runner=runner, db=db, program="test-corp", work_dir=tmp_path
        )
        result = {
            "subdomains": {"total": 100, "sources": {"crtsh": 60, "virustotal": 40}},
            "services": {"live": 45, "technologies": {"nginx": 20, "apache": 15, "wordpress": 10}},
            "urls": {"katana": 500, "gau": 1200},
        }
        text = pipeline.format_summary(result)
        assert "100 subdomains" in text
        assert "45 live" in text
        assert "nginx" in text
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement pipeline.py**

`src/bba/tools/pipeline.py`:
```python
from __future__ import annotations

from pathlib import Path

from bba.db import Database
from bba.tool_runner import ToolRunner
from bba.tools.subfinder import SubfinderTool
from bba.tools.httpx_runner import HttpxTool
from bba.tools.katana import KatanaTool
from bba.tools.gau import GauTool


class ReconPipeline:
    def __init__(
        self, runner: ToolRunner, db: Database, program: str, work_dir: Path
    ):
        self.runner = runner
        self.db = db
        self.program = program
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)

    async def _run_subfinder(self, domain: str) -> dict:
        tool = SubfinderTool(runner=self.runner, db=self.db, program=self.program)
        return await tool.run(domain)

    async def _run_httpx(self, domains: list[str]) -> dict:
        tool = HttpxTool(runner=self.runner, db=self.db, program=self.program)
        return await tool.run(domains, work_dir=self.work_dir)

    async def _run_katana(self, targets: list[str]) -> dict:
        tool = KatanaTool(runner=self.runner, db=self.db, program=self.program)
        return await tool.run(targets, work_dir=self.work_dir)

    async def _run_gau(self, domain: str) -> dict:
        tool = GauTool(runner=self.runner, db=self.db, program=self.program)
        return await tool.run(domain)

    async def run(self, domain: str) -> dict:
        # Step 1: Subdomain enumeration
        sub_summary = await self._run_subfinder(domain)

        # Step 2: HTTP probing (skip if no subdomains)
        domains = sub_summary.get("domains", [])
        if domains:
            httpx_summary = await self._run_httpx(domains)
        else:
            httpx_summary = {"live": 0, "services": [], "technologies": {}}

        # Step 3: URL harvesting (only on live services)
        live_services = httpx_summary.get("services", [])
        if live_services:
            live_urls = [f"https://{s}" for s in live_services]
            katana_summary = await self._run_katana(live_urls)
        else:
            katana_summary = {"total": 0, "urls": []}

        gau_summary = await self._run_gau(domain)

        return {
            "subdomains": {
                "total": sub_summary.get("total", 0),
                "sources": sub_summary.get("sources", {}),
            },
            "services": {
                "live": httpx_summary.get("live", 0),
                "technologies": httpx_summary.get("technologies", {}),
            },
            "urls": {
                "katana": katana_summary.get("total", 0),
                "gau": gau_summary.get("total", 0),
            },
        }

    def format_summary(self, result: dict) -> str:
        lines = []
        sub = result["subdomains"]
        lines.append(f"Found {sub['total']} subdomains")
        if sub.get("sources"):
            src_parts = [f"{k}: {v}" for k, v in sub["sources"].items()]
            lines.append(f"  Sources: {', '.join(src_parts)}")

        svc = result["services"]
        lines.append(f"{svc['live']} live HTTP services")
        if svc.get("technologies"):
            tech_parts = [f"{k}: {v}" for k, v in svc["technologies"].items()]
            lines.append(f"  Technologies: {', '.join(tech_parts)}")

        urls = result["urls"]
        lines.append(f"URLs harvested: {urls['katana']} (katana), {urls['gau']} (gau)")

        return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add src/bba/tools/pipeline.py tests/test_tools_pipeline.py
git commit -m "feat: recon pipeline orchestrator chaining subfinder → httpx → katana/gau"
```

---

## What Phase 2 Produces

After completing all tasks, you have:
- **4 tool wrappers** — subfinder, httpx, katana, gau with JSON parsing and DB storage
- **1 pipeline orchestrator** — chains tools in sequence with conditional logic
- **LLM-friendly summaries** — format_summary() produces concise text for agent context
- **~25 new tests** covering all wrappers and pipeline

## What Comes Next (Phase 3)

Phase 3 builds the scanning pipeline: nuclei wrapper with template selection, ffuf for directory fuzzing, and specialized wrappers for sqlmap/dalfox. The scanner sub-agent gets wired to these tools.
