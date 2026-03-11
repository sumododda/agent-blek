"""Fixtures for integration tests against a live Juice Shop instance."""
from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError

import pytest
import pytest_asyncio

from bba.db import Database
from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.scope import ScopeConfig, ScopeValidator
from bba.tool_runner import ToolRunner

JUICESHOP_URL = "http://localhost:3000"
JUICESHOP_HOST = "localhost"
PROGRAM = "juiceshop"


def _juiceshop_is_running() -> bool:
    """Check if Juice Shop is reachable."""
    try:
        urlopen(JUICESHOP_URL, timeout=3)
        return True
    except (URLError, OSError):
        return False


def _tool_is_available(name: str) -> bool:
    """Check if a ProjectDiscovery/security tool binary is available on PATH.

    Distinguishes ProjectDiscovery's httpx from Python's httpx CLI by checking
    for the -silent flag support.
    """
    import shutil
    import subprocess

    path = shutil.which(name)
    if not path:
        return False

    # ProjectDiscovery httpx supports -version; Python httpx does not
    if name == "httpx":
        try:
            result = subprocess.run(
                [path, "-version"], capture_output=True, timeout=5
            )
            # PD httpx prints "Current Version: ..." to stdout
            output = result.stdout.decode() + result.stderr.decode()
            return "version" in output.lower() and "projectdiscovery" in output.lower()
        except (subprocess.TimeoutExpired, OSError):
            return False

    return True


# Skip entire module if Juice Shop isn't running
pytestmark = pytest.mark.integration


@pytest.fixture(scope="session")
def juiceshop_available():
    """Gate: skip all integration tests if Juice Shop is not running."""
    if not _juiceshop_is_running():
        pytest.skip("Juice Shop not running on localhost:3000")


@pytest.fixture(scope="session")
def scope_config() -> ScopeConfig:
    return ScopeConfig(
        program=PROGRAM,
        platform="local-testing",
        in_scope_domains=["localhost", "127.0.0.1"],
        in_scope_cidrs=["127.0.0.0/8"],
    )


@pytest.fixture(scope="session")
def scope_validator(scope_config) -> ScopeValidator:
    return ScopeValidator(scope_config)


@pytest_asyncio.fixture
async def db(tmp_path):
    """Fresh database per test."""
    database = Database(tmp_path / "test.db")
    await database.initialize()
    yield database
    await database.close()


@pytest.fixture
def tool_runner(scope_validator, tmp_path) -> ToolRunner:
    """Real tool runner with scope enforcement."""
    return ToolRunner(
        scope=scope_validator,
        rate_limiter=MultiTargetRateLimiter(default_rps=10.0),
        sanitizer=Sanitizer(),
        output_dir=tmp_path / "output",
    )


def requires_tool(name: str):
    """Decorator to skip tests when a specific tool is not installed."""
    return pytest.mark.skipif(
        not _tool_is_available(name),
        reason=f"{name} not found on PATH",
    )
