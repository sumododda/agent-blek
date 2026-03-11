from __future__ import annotations

import asyncio
import time


class RateLimiter:
    def __init__(self, max_rps: int):
        self.max_rps = max_rps
        self._tokens = float(max_rps)
        self._last_refill = time.monotonic()

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.max_rps, self._tokens + elapsed * self.max_rps)
        self._last_refill = now

    def try_acquire(self) -> bool:
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    async def wait(self):
        while not self.try_acquire():
            await asyncio.sleep(1.0 / self.max_rps)


class MultiTargetRateLimiter:
    def __init__(self, default_rps: int = 20, global_rps: int | None = None):
        self.default_rps = default_rps
        self.global_rps = global_rps
        self._limiters: dict[str, RateLimiter] = {}
        self._custom_rps: dict[str, int] = {}
        self._original_rps: dict[str, int] = {}
        self._success_count: dict[str, int] = {}
        self._global_limiter: RateLimiter | None = (
            RateLimiter(global_rps) if global_rps else None
        )

    def set_target_rps(self, target: str, rps: int):
        self._custom_rps[target] = rps
        self._original_rps[target] = rps
        if target in self._limiters:
            self._limiters[target] = RateLimiter(rps)

    def _get_limiter(self, target: str) -> RateLimiter:
        if target not in self._limiters:
            rps = self._custom_rps.get(target, self.default_rps)
            self._limiters[target] = RateLimiter(rps)
            if target not in self._original_rps:
                self._original_rps[target] = rps
        return self._limiters[target]

    def report_status(self, target: str, http_status: int):
        """Adapt rate based on HTTP response status."""
        limiter = self._get_limiter(target)
        if http_status in (429, 503):
            # Halve the rate, minimum 2
            new_rps = max(2, limiter.max_rps // 2)
            limiter.max_rps = new_rps
            self._success_count[target] = 0
        elif 200 <= http_status < 400:
            self._success_count[target] = self._success_count.get(target, 0) + 1
            if self._success_count[target] >= 10:
                original = self._original_rps.get(target, self.default_rps)
                if limiter.max_rps < original:
                    limiter.max_rps = min(original, limiter.max_rps + 1)
                self._success_count[target] = 0

    def try_acquire(self, target: str) -> bool:
        if self._global_limiter and not self._global_limiter.try_acquire():
            return False
        return self._get_limiter(target).try_acquire()

    async def wait(self, target: str):
        if self._global_limiter:
            await self._global_limiter.wait()
        await self._get_limiter(target).wait()
