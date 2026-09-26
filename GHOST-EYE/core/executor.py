"""
core/executor.py — bounded concurrency, per-task timeout, and partial-failure
tolerance (one task blowing up never kills the batch) for every pipeline phase.

Recon tools here are all subprocess/network bound, so threads (not processes)
are the right primitive — the GIL is a non-issue when the actual work happens
in a subprocess or a socket read.

v2.1 fix — `per_task_timeout` was documented but never enforced:

    for fut in as_completed(future_to_name):     # <- no timeout
        value = fut.result(timeout=1)            # <- always already done

`as_completed()` without a timeout blocks forever waiting on the slowest
future, so a single wedged subprocess (a `puredns` that never returns, a
socket with no timeout) hung the entire run with no way out. The `timeout=1`
on `.result()` did nothing, because as_completed only yields futures that
have *already* finished. The fallback loop at the bottom that filled in
"timeout or skipped" entries was therefore unreachable in practice.

Now the wall-clock budget is passed to `as_completed()` itself, pending
futures are cancelled on expiry, and anything that never completed comes
back as a failed TaskResult rather than deadlocking the phase.

Caveat worth knowing: a thread already inside a blocking call cannot be
killed, so cancellation only stops tasks that haven't started. Every
tools.py wrapper passes a `timeout=` to subprocess.run / urlopen for exactly
this reason — this layer is the backstop, not the primary control.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout

log = logging.getLogger("recon.executor")

# how much slack beyond the per-task budget the whole batch gets before the
# collector gives up (tasks queue behind workers, so the batch legitimately
# takes longer than any single task)
_BATCH_GRACE = 30


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

    def __repr__(self):
        state = "ok" if self.ok else f"error={self.error!r}"
        return f"<TaskResult {self.name} {state} {self.duration:.1f}s>"


def _batch_budget(per_task_timeout, n_tasks, max_workers):
    """Wall-clock ceiling for the whole batch, derived from the per-task budget."""
    if not per_task_timeout:
        return None
    waves = -(-n_tasks // max(1, max_workers))  # ceil division
    return per_task_timeout * waves + _BATCH_GRACE


def run_parallel(tasks: dict, max_workers: int = 8, per_task_timeout: int | None = None) -> dict:
    """
    Run {name: callable} concurrently. Returns {name: TaskResult} with an entry
    for every requested task — failed, timed out, and cancelled ones included,
    so callers can always index by name without a KeyError.

    Results are gathered with as_completed(), so fast tasks are collected as
    soon as they land rather than in submission order.
    """
    results: dict[str, TaskResult] = {}
    if not tasks:
        return results

    max_workers = max(1, min(max_workers, len(tasks)))
    budget = _batch_budget(per_task_timeout, len(tasks), max_workers)
    start_times: dict[str, float] = {}

    # NOTE: deliberately not `with ThreadPoolExecutor(...)`. The context
    # manager's __exit__ calls shutdown(wait=True), which re-blocks on exactly
    # the wedged task the budget above just gave up on — the phase would still
    # take the full stall. shutdown(wait=False, cancel_futures=True) drops
    # queued work and lets the pipeline move on; the abandoned thread finishes
    # on its own subprocess/socket timeout (every tools.py wrapper sets one).
    pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ghosteye")
    try:
        future_to_name = {}
        submitted_at = time.monotonic()
        for name, fn in tasks.items():
            start_times[name] = submitted_at
            future_to_name[pool.submit(fn)] = name

        try:
            for fut in as_completed(future_to_name, timeout=budget):
                name = future_to_name[fut]
                duration = time.monotonic() - start_times[name]
                try:
                    results[name] = TaskResult(name, value=fut.result(), duration=duration)
                except Exception as e:
                    results[name] = TaskResult(name, error=f"{type(e).__name__}: {e}", duration=duration)
                    log.warning("task '%s' failed: %s", name, e)
        except FuturesTimeout:
            pending = [n for f, n in future_to_name.items() if n not in results]
            log.warning("batch budget of %ss exhausted — %d task(s) did not finish: %s",
                        budget, len(pending), ", ".join(pending[:5]))
            for name in pending:
                results[name] = TaskResult(name, error="timeout", duration=time.monotonic() - start_times[name])

        elapsed = time.monotonic() - submitted_at
        for name in tasks:
            if name not in results:
                results[name] = TaskResult(name, error="timeout" if per_task_timeout else "timed out or cancelled", duration=elapsed)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    return results


def map_parallel(fn, items: list, max_workers: int = 8, per_item_timeout: int | None = None) -> list[TaskResult]:
    """Apply fn across items concurrently; results come back in original order."""
    if not items:
        return []
    tasks = {str(i): (lambda it=item: fn(it)) for i, item in enumerate(items)}
    results = run_parallel(tasks, max_workers=max_workers, per_task_timeout=per_item_timeout)
    return [results[str(i)] for i in range(len(items))]
