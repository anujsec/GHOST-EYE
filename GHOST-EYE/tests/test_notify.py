import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import notify


class TestFormatDiffMessage(unittest.TestCase):
    def test_empty_diff_returns_empty_string(self):
        diff = {"new": [], "removed": [], "changed": []}
        self.assertEqual(notify.format_diff_message("acme", "layer", "table", diff), "")

    def test_new_items_included(self):
        diff = {"new": [("a.acme.com", {})], "removed": [], "changed": []}
        msg = notify.format_diff_message("acme", "subdomain_enum", "subdomains", diff)
        self.assertIn("a.acme.com", msg)
        self.assertIn("1 new", msg)

    def test_truncates_long_lists(self):
        diff = {"new": [(f"h{i}.acme.com", {}) for i in range(30)], "removed": [], "changed": []}
        msg = notify.format_diff_message("acme", "layer", "table", diff)
        self.assertIn("...and 10 more", msg)


class TestSend(unittest.TestCase):
    def test_no_webhooks_configured_does_not_raise(self):
        notify.send({}, "hello")  # should just log, not raise
        notify.send(None, "hello")  # cfg=None should also be handled gracefully

    def test_empty_text_is_noop(self):
        notify.send({"slack_webhook": "http://example.invalid"}, "")  # should return early, no HTTP call


if __name__ == "__main__":
    unittest.main()
