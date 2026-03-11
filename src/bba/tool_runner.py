from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path

from bba.rate_limiter import MultiTargetRateLimiter
from bba.sanitizer import Sanitizer
from bba.scope import ScopeValidator


@dataclass
class ToolResult:
    success: bool
    output: str
    raw_file: Path | None = None
    error: str | None = None
    duration: float = 0.0


class ToolRunner:
    def __init__(
        self,
        scope: ScopeValidator,
        rate_limiter: MultiTargetRateLimiter,
        sanitizer: Sanitizer,
        output_dir: Path,
        dry_run: bool = False,
    ):
        self.scope = scope
        self.rate_limiter = rate_limiter
        self.sanitizer = sanitizer
        self.output_dir = output_dir
        self.dry_run = dry_run

    def validate_targets(self, targets: list[str]) -> None:
        for target in targets:
            if not self.scope.validate_target(target):
                raise ValueError(f"Target '{target}' is out of scope")

    def _ensure_output_dir(self, tool: str) -> Path:
        tool_dir = self.output_dir / tool
        tool_dir.mkdir(parents=True, exist_ok=True)
        return tool_dir

    async def run_command(
        self,
        tool: str,
        command: list[str],
        targets: list[str],
        timeout: int = 600,
    ) -> ToolResult:
        self.validate_targets(targets)

        if self.dry_run:
            cmd_str = " ".join(str(c) for c in command)
            return ToolResult(
                success=True,
                output=f"[DRY-RUN] Would execute: {cmd_str}",
                duration=0.0,
            )

        for target in targets:
            await self.rate_limiter.wait(target)

        tool_dir = self._ensure_output_dir(tool)
        timestamp = time.monotonic_ns()
        raw_file = tool_dir / f"{timestamp}.txt"

        start = time.monotonic()
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            duration = time.monotonic() - start

            raw_output = stdout.decode(errors="replace")
            raw_file.write_text(raw_output)

            sanitized = self.sanitizer.sanitize(raw_output)

            if proc.returncode == 0:
                return ToolResult(
                    success=True,
                    output=sanitized,
                    raw_file=raw_file,
                    duration=duration,
                )
            else:
                return ToolResult(
                    success=False,
                    output=sanitized,
                    raw_file=raw_file,
                    error=stderr.decode(errors="replace"),
                    duration=duration,
                )

        except asyncio.TimeoutError:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except ProcessLookupError:
                    pass
            return ToolResult(
                success=False,
                output="",
                error=f"Command timed out after {timeout}s",
                duration=time.monotonic() - start,
            )

    async def run_http_request(
        self,
        tool: str,
        url: str,
        targets: list[str],
        timeout: int = 30,
        headers: dict[str, str] | None = None,
    ) -> ToolResult:
        """Execute an HTTP GET request with scope validation and rate limiting."""
        self.validate_targets(targets)
        for target in targets:
            await self.rate_limiter.wait(target)

        tool_dir = self._ensure_output_dir(tool)
        timestamp = time.monotonic_ns()
        raw_file = tool_dir / f"{timestamp}.txt"

        start = time.monotonic()
        try:
            import ssl
            import urllib.request

            req = urllib.request.Request(url, headers=headers or {})
            ctx = ssl.create_default_context()
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, lambda: urllib.request.urlopen(req, timeout=timeout, context=ctx)
            )
            raw_output = response.read().decode(errors="replace")
            duration = time.monotonic() - start
            raw_file.write_text(raw_output)
            sanitized = self.sanitizer.sanitize(raw_output)
            return ToolResult(success=True, output=sanitized, raw_file=raw_file, duration=duration)
        except Exception as e:
            return ToolResult(
                success=False, output="", error=str(e), duration=time.monotonic() - start,
            )
