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
    def __init__(self, default_rps: int = 50):
        self.default_rps = default_rps
        self._limiters: dict[str, RateLimiter] = {}
        self._custom_rps: dict[str, int] = {}

    def set_target_rps(self, target: str, rps: int):
        self._custom_rps[target] = rps
        if target in self._limiters:
            self._limiters[target] = RateLimiter(rps)

    def _get_limiter(self, target: str) -> RateLimiter:
        if target not in self._limiters:
            rps = self._custom_rps.get(target, self.default_rps)
            self._limiters[target] = RateLimiter(rps)
        return self._limiters[target]

    def try_acquire(self, target: str) -> bool:
        return self._get_limiter(target).try_acquire()

    async def wait(self, target: str):
        await self._get_limiter(target).wait()
