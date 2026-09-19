import unittest
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.executor import run_parallel, map_parallel


class TestRunParallel(unittest.TestCase):
    def test_empty_tasks(self):
        self.assertEqual(run_parallel({}), {})

    def test_all_succeed(self):
        tasks = {"a": lambda: 1, "b": lambda: 2, "c": lambda: 3}
        results = run_parallel(tasks, max_workers=3)
        self.assertEqual({k: r.value for k, r in results.items()}, {"a": 1, "b": 2, "c": 3})
        self.assertTrue(all(r.ok for r in results.values()))

    def test_one_failure_does_not_kill_others(self):
        def boom():
            raise ValueError("boom")

        tasks = {"good": lambda: 42, "bad": boom}
        results = run_parallel(tasks, max_workers=2)
        self.assertTrue(results["good"].ok)
        self.assertEqual(results["good"].value, 42)
        self.assertFalse(results["bad"].ok)
        self.assertIn("boom", results["bad"].error)

    def test_timeout_reported_independently_per_task(self):
        # Threads can't be force-killed, so this checks that a slow task is
        # correctly *reported* as timed out (not that wall time is cut short) —
        # the real kill-switch for subprocess-backed tasks is the timeout
        # passed to subprocess.run() itself, inside tools.py.
        def slow():
            time.sleep(1)
            return "done"

        tasks = {"slow": slow, "fast": lambda: "quick"}
        results = run_parallel(tasks, max_workers=2, per_task_timeout=0.1)
        self.assertFalse(results["slow"].ok)
        self.assertEqual(results["slow"].error, "timeout")
        self.assertTrue(results["fast"].ok)
        self.assertEqual(results["fast"].value, "quick")

    def test_max_workers_bounded_not_unlimited(self):
        # more tasks than workers should still all complete correctly
        tasks = {str(i): (lambda i=i: i) for i in range(50)}
        results = run_parallel(tasks, max_workers=4)
        self.assertEqual(len(results), 50)
        self.assertTrue(all(r.ok for r in results.values()))


class TestMapParallel(unittest.TestCase):
    def test_preserves_order(self):
        items = [3, 1, 4, 1, 5, 9]
        results = map_parallel(lambda x: x * 10, items, max_workers=3)
        self.assertEqual([r.value for r in results], [30, 10, 40, 10, 50, 90])

    def test_empty_items(self):
        self.assertEqual(map_parallel(lambda x: x, []), [])


if __name__ == "__main__":
    unittest.main()
