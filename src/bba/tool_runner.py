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
    ):
        self.scope = scope
        self.rate_limiter = rate_limiter
        self.sanitizer = sanitizer
        self.output_dir = output_dir

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

        for target in targets:
            await self.rate_limiter.wait(target)

        tool_dir = self._ensure_output_dir(tool)
        timestamp = int(time.time())
        raw_file = tool_dir / f"{timestamp}.txt"

        start = time.monotonic()
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
            return ToolResult(
                success=False,
                output="",
                error=f"Command timed out after {timeout}s",
                duration=time.monotonic() - start,
            )
