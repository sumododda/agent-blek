import asyncio
import time

import pytest
from bba.rate_limiter import RateLimiter


class TestRateLimiter:
    def test_allows_within_rate(self):
        limiter = RateLimiter(max_rps=10)
        for _ in range(10):
            assert limiter.try_acquire() is True

    def test_blocks_over_rate(self):
        limiter = RateLimiter(max_rps=2)
        assert limiter.try_acquire() is True
        assert limiter.try_acquire() is True
        assert limiter.try_acquire() is False

    def test_refills_over_time(self):
        limiter = RateLimiter(max_rps=10)
        for _ in range(10):
            limiter.try_acquire()
        assert limiter.try_acquire() is False
        limiter._last_refill = time.monotonic() - 1.0
        limiter._refill()
        assert limiter.try_acquire() is True

    async def test_wait_for_token(self):
        limiter = RateLimiter(max_rps=100)
        for _ in range(100):
            limiter.try_acquire()
        start = time.monotonic()
        await limiter.wait()
        elapsed = time.monotonic() - start
        assert elapsed < 2.0


class TestMultiTargetRateLimiter:
    def test_independent_targets(self):
        from bba.rate_limiter import MultiTargetRateLimiter
        limiter = MultiTargetRateLimiter(default_rps=2)
        assert limiter.try_acquire("target-a") is True
        assert limiter.try_acquire("target-a") is True
        assert limiter.try_acquire("target-a") is False
        assert limiter.try_acquire("target-b") is True

    def test_custom_per_target_rps(self):
        from bba.rate_limiter import MultiTargetRateLimiter
        limiter = MultiTargetRateLimiter(default_rps=5)
        limiter.set_target_rps("slow-target", 1)
        assert limiter.try_acquire("slow-target") is True
        assert limiter.try_acquire("slow-target") is False
