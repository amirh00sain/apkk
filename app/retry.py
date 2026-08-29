"""Retry policy with capped exponential backoff.  No infinite retries."""

from __future__ import annotations

from typing import Any, Callable, TypeVar

T = TypeVar("T")

DEFAULT_BACKOFFS = [0.5, 1.0, 2.0, 4.0, 8.0]


def retry(
    func: Callable[[], T],
    *,
    max_retries: int = 5,
    backoffs: list[float] | None = None,
    exceptions: tuple[type[Exception], ...] = (Exception,),
) -> T:
    """Retry `func` with capped exponential backoff.  Raises after max_retries."""
    backoffs = backoffs or DEFAULT_BACKOFFS
    last_exc: Exception | None = None
    for attempt in range(max_retries):
        try:
            return func()
        except exceptions as exc:  # noqa: PERF203
            last_exc = exc
            if attempt < max_retries - 1:
                # Sleep for the configured backoff (or last available).
                import time
                idx = min(attempt, len(backoffs) - 1)
                time.sleep(backoffs[idx])
    assert last_exc is not None
    raise last_exc


async def retry_async(
    func: Callable[[], Any],
    *,
    max_retries: int = 5,
    backoffs: list[float] | None = None,
    exceptions: tuple[type[Exception], ...] = (Exception,),
) -> Any:
    """Async variant of retry().  func must be an async callable."""
    import asyncio
    backoffs = backoffs or DEFAULT_BACKOFFS
    last_exc: Exception | None = None
    for attempt in range(max_retries):
        try:
            return await func()
        except exceptions as exc:  # noqa: PERF203
            last_exc = exc
            if attempt < max_retries - 1:
                idx = min(attempt, len(backoffs) - 1)
                await asyncio.sleep(backoffs[idx])
    assert last_exc is not None
    raise last_exc
