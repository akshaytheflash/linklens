import time
from collections import defaultdict, deque
from typing import Deque, Dict


class RateLimiter:
    """Sliding-window rate limiter, keyed by client IP."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._ip_to_events: Dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, ip: str) -> bool:
        now = time.time()
        events = self._ip_to_events[ip]
        while events and now - events[0] > self.window_seconds:
            events.popleft()
        if len(events) >= self.max_requests:
            return False
        events.append(now)
        return True
