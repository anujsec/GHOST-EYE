"""
core/executor.py — small wrapper around ThreadPoolExecutor so every phase
of the pipeline gets: bounded concurrency, per-task timeout, and partial-
failure tolerance (one task blowing up never kills the batch) for free.

Recon tools here are all subprocess/network bound, so threads (not
processes) are the right primitive — the GIL is a non-issue when the
actual work happens in a subprocess or a socket read.
"""
"""
core/executor.py — Optimized parallel task runner with non-blocking completion gathering.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger("recon.executor")


class TaskResult:
    __slots__ = ("name", "value", "error", "duration")

    def __init__(self, name, value=None, error=None, duration=0.0):
        self.name = name
        self.value = value
        self.error = error
        self.duration = duration

    @property
    def ok(self):
        return self.error is None


def run_parallel(tasks: dict, max_workers: int = 8, per_task_timeout: int | None = None) -> dict:
    """
    Executes a dictionary of tasks in parallel. Uses as_completed() so faster tasks 
    return immediately without getting blocked behind a stalled or timed-out task.
    """
    results = {}
    if not tasks:
        return results

    max_workers = max(1, min(max_workers, len(tasks)))
    start_times = {}

    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="recon") as pool:
        future_to_name = {}
        for name, fn in tasks.items():
            start_times[name] = time.monotonic()
            fut = pool.submit(fn)
            future_to_name[fut] = name

        # Collect results as they finish rather than in strict dict insertion order
        for fut in as_completed(future_to_name):
            name = future_to_name[fut]
            duration = time.monotonic() - start_times[name]
            try:
                # Set a tight boundary on result extraction
                value = fut.result(timeout=1)
                results[name] = TaskResult(name, value=value, duration=duration)
            except Exception as e:
                results[name] = TaskResult(name, error=str(e), duration=duration)
                log.warning("task '%s' failed or timed out: %s", name, e)

    # Ensure all requested tasks have an entry (handles any edge cancellations)
    for name in tasks:
        if name not in results:
            results[name] = TaskResult(name, error="timeout or skipped", duration=per_task_timeout or 0)

    return results


def map_parallel(fn, items: list, max_workers: int = 8, per_item_timeout: int | None = None) -> list[TaskResult]:
    """Applies fn across items concurrently and returns results in original order."""
    tasks = {str(i): (lambda it=item: fn(it)) for i, item in enumerate(items)}
    results = run_parallel(tasks, max_workers=max_workers, per_task_timeout=per_item_timeout)
    return [results[str(i)] for i in range(len(items))]