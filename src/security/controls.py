"""Process-local intake rate limiting."""

from collections import defaultdict


class InMemoryRateLimiter:
    """Local-only limiter. Production requires a shared durable backend."""

    def __init__(self, limit: int = 5) -> None:
        self.limit = limit
        self._counts: dict[str, int] = defaultdict(int)

    def check(self, subject: str) -> None:
        self._counts[subject] += 1
        if self._counts[subject] > self.limit:
            raise PermissionError("Rate limit exceeded")
