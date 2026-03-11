from __future__ import annotations

import asyncio
import time

import pytest

from bba.rate_limiter import MultiTargetRateLimiter, RateLimiter


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
        limiter = MultiTargetRateLimiter(default_rps=2)
        assert limiter.try_acquire("target-a") is True
        assert limiter.try_acquire("target-a") is True
        assert limiter.try_acquire("target-a") is False
        assert limiter.try_acquire("target-b") is True

    def test_custom_per_target_rps(self):
        limiter = MultiTargetRateLimiter(default_rps=5)
        limiter.set_target_rps("slow-target", 1)
        assert limiter.try_acquire("slow-target") is True
        assert limiter.try_acquire("slow-target") is False


class TestRateLimiterDefault:
    def test_default_rps_is_20(self):
        limiter = MultiTargetRateLimiter()
        assert limiter.default_rps == 20

    def test_custom_default_rps(self):
        limiter = MultiTargetRateLimiter(default_rps=30)
        assert limiter.default_rps == 30


class TestAdaptiveBackoff:
    def test_backoff_on_429(self):
        limiter = MultiTargetRateLimiter(default_rps=20)
        limiter._get_limiter("example.com")  # initialize
        limiter.report_status("example.com", 429)
        rl = limiter._get_limiter("example.com")
        assert rl.max_rps == 10  # halved

    def test_backoff_on_503(self):
        limiter = MultiTargetRateLimiter(default_rps=20)
        limiter._get_limiter("example.com")
        limiter.report_status("example.com", 503)
        assert limiter._get_limiter("example.com").max_rps == 10

    def test_backoff_minimum_is_2(self):
        limiter = MultiTargetRateLimiter(default_rps=4)
        limiter._get_limiter("example.com")
        limiter.report_status("example.com", 429)  # 4 -> 2
        limiter.report_status("example.com", 429)  # 2 -> 2 (min)
        assert limiter._get_limiter("example.com").max_rps == 2

    def test_success_restores_rate(self):
        limiter = MultiTargetRateLimiter(default_rps=20)
        limiter._get_limiter("example.com")
        limiter.report_status("example.com", 429)  # 20 -> 10
        assert limiter._get_limiter("example.com").max_rps == 10
        for _ in range(10):
            limiter.report_status("example.com", 200)
        assert limiter._get_limiter("example.com").max_rps == 11  # +1

    def test_success_does_not_exceed_original(self):
        limiter = MultiTargetRateLimiter(default_rps=20)
        limiter._get_limiter("example.com")
        # Never backed off, already at original
        for _ in range(100):
            limiter.report_status("example.com", 200)
        assert limiter._get_limiter("example.com").max_rps == 20

    def test_multiple_backoff_then_restore(self):
        limiter = MultiTargetRateLimiter(default_rps=20)
        limiter._get_limiter("example.com")
        limiter.report_status("example.com", 429)  # 20 -> 10
        limiter.report_status("example.com", 429)  # 10 -> 5
        assert limiter._get_limiter("example.com").max_rps == 5
        # 10 successes -> 5 + 1 = 6
        for _ in range(10):
            limiter.report_status("example.com", 200)
        assert limiter._get_limiter("example.com").max_rps == 6

    def test_success_counter_resets_on_backoff(self):
        limiter = MultiTargetRateLimiter(default_rps=20)
        limiter._get_limiter("example.com")
        limiter.report_status("example.com", 429)  # 20 -> 10
        # 9 successes (not enough for restore)
        for _ in range(9):
            limiter.report_status("example.com", 200)
        assert limiter._get_limiter("example.com").max_rps == 10
        # Another 429 resets counter
        limiter.report_status("example.com", 429)  # 10 -> 5
        assert limiter._success_count["example.com"] == 0


class TestGlobalRateLimit:
    def test_global_limiter_created(self):
        limiter = MultiTargetRateLimiter(default_rps=20, global_rps=50)
        assert limiter.global_rps == 50
        assert limiter._global_limiter is not None

    def test_no_global_limiter_by_default(self):
        limiter = MultiTargetRateLimiter()
        assert limiter._global_limiter is None

    @pytest.mark.asyncio
    async def test_global_wait_called(self):
        limiter = MultiTargetRateLimiter(default_rps=20, global_rps=100)
        await limiter.wait("example.com")  # Should not raise


class TestOriginalRpsTracking:
    def test_original_rps_tracked_on_init(self):
        limiter = MultiTargetRateLimiter(default_rps=20)
        limiter._get_limiter("example.com")
        assert limiter._original_rps["example.com"] == 20

    def test_original_rps_tracked_on_set_target(self):
        limiter = MultiTargetRateLimiter(default_rps=20)
        limiter.set_target_rps("example.com", 30)
        assert limiter._original_rps["example.com"] == 30

    def test_set_target_rps_updates_limiter(self):
        limiter = MultiTargetRateLimiter(default_rps=20)
        limiter._get_limiter("example.com")  # creates at 20
        limiter.set_target_rps("example.com", 30)
        assert limiter._get_limiter("example.com").max_rps == 30
