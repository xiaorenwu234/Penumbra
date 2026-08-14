#!/usr/bin/env python3
"""High-resolution timing utilities for RQ3 experiments.

Uses time.perf_counter_ns() for nanosecond-resolution monotonic timing.
"""

import time


def time_ns() -> int:
    """Return current time in nanoseconds (monotonic, high-resolution)."""
    return time.perf_counter_ns()


class Timer:
    """Context manager for measuring elapsed time in nanoseconds.

    Usage:
        with Timer() as t:
            do_work()
        elapsed_ns = t.elapsed_ns
        elapsed_us = t.elapsed_us
        elapsed_ms = t.elapsed_ms
    """

    def __init__(self):
        self.start_ns: int = 0
        self.end_ns: int = 0
        self.elapsed_ns: int = 0

    def __enter__(self):
        self.start_ns = time.perf_counter_ns()
        return self

    def __exit__(self, *args):
        self.end_ns = time.perf_counter_ns()
        self.elapsed_ns = self.end_ns - self.start_ns

    @property
    def elapsed_us(self) -> float:
        """Elapsed time in microseconds."""
        return self.elapsed_ns / 1000.0

    @property
    def elapsed_ms(self) -> float:
        """Elapsed time in milliseconds."""
        return self.elapsed_ns / 1_000_000.0

    @property
    def elapsed_s(self) -> float:
        """Elapsed time in seconds."""
        return self.elapsed_ns / 1_000_000_000.0


def measure_call(fn, *args, **kwargs) -> tuple:
    """Call fn(*args, **kwargs) and return (result, elapsed_ns).

    Useful for one-off measurements without context manager overhead.
    """
    t0 = time.perf_counter_ns()
    result = fn(*args, **kwargs)
    elapsed = time.perf_counter_ns() - t0
    return result, elapsed
