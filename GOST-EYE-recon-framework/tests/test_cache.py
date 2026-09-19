import unittest
import tempfile
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import core.cache as cache_mod


class TestCache(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig_path = cache_mod.CACHE_PATH
        cache_mod.CACHE_PATH = Path(self._tmpdir.name) / "cache.db"

    def tearDown(self):
        cache_mod.CACHE_PATH = self._orig_path
        self._tmpdir.cleanup()

    def test_set_get_roundtrip(self):
        cache_mod.set("k1", {"a": 1, "b": [1, 2, 3]}, ttl_seconds=60)
        self.assertEqual(cache_mod.get("k1"), {"a": 1, "b": [1, 2, 3]})

    def test_missing_key_returns_default(self):
        self.assertIsNone(cache_mod.get("does-not-exist"))
        self.assertEqual(cache_mod.get("does-not-exist", default="fallback"), "fallback")

    def test_expired_key_returns_default(self):
        cache_mod.set("expiring", "value", ttl_seconds=0)
        time.sleep(0.05)
        self.assertIsNone(cache_mod.get("expiring"))

    def test_overwrite(self):
        cache_mod.set("k2", "first", ttl_seconds=60)
        cache_mod.set("k2", "second", ttl_seconds=60)
        self.assertEqual(cache_mod.get("k2"), "second")

    def test_cached_decorator_skips_second_call(self):
        calls = []

        @cache_mod.cached("ns", ttl_seconds=60)
        def expensive(x):
            calls.append(x)
            return x * 2

        self.assertEqual(expensive(5), 10)
        self.assertEqual(expensive(5), 10)
        self.assertEqual(calls, [5])  # second call hit cache, function body only ran once

    def test_cached_decorator_disabled_always_calls(self):
        calls = []

        @cache_mod.cached("ns2", ttl_seconds=60, enabled=False)
        def expensive(x):
            calls.append(x)
            return x * 2

        expensive(5)
        expensive(5)
        self.assertEqual(calls, [5, 5])


if __name__ == "__main__":
    unittest.main()
