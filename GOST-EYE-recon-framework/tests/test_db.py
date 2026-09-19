import unittest
import tempfile
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import db


class TestDB(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig_path = db.DB_PATH
        db.DB_PATH = Path(self._tmpdir.name) / "recon.db"

    def tearDown(self):
        db.DB_PATH = self._orig_path
        self._tmpdir.cleanup()

    def test_start_and_finish_run(self):
        run_id = db.start_run("acme", "subdomain_enum")
        self.assertIsInstance(run_id, int)
        db.finish_run(run_id)  # should not raise

    def test_first_run_everything_is_new(self):
        run_id = db.start_run("acme", "subdomain_enum")
        items = {"a.acme.com": {"x": 1}, "b.acme.com": {"x": 2}}
        db.upsert_assets("acme", "subdomains", run_id, items)
        diff = db.diff_since_last("acme", "subdomains", run_id)
        self.assertEqual(len(diff["new"]), 2)
        self.assertEqual(diff["removed"], [])
        self.assertEqual(diff["changed"], [])

    def test_second_run_no_changes_means_empty_diff(self):
        run1 = db.start_run("acme", "subdomain_enum")
        items = {"a.acme.com": {"x": 1}}
        db.upsert_assets("acme", "subdomains", run1, items)

        run2 = db.start_run("acme", "subdomain_enum")
        db.upsert_assets("acme", "subdomains", run2, items)  # identical
        diff = db.diff_since_last("acme", "subdomains", run2)
        self.assertEqual(diff["new"], [])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(diff["changed"], [])

    def test_new_asset_detected(self):
        run1 = db.start_run("acme", "subdomain_enum")
        db.upsert_assets("acme", "subdomains", run1, {"a.acme.com": {}})

        run2 = db.start_run("acme", "subdomain_enum")
        db.upsert_assets("acme", "subdomains", run2, {"a.acme.com": {}, "b.acme.com": {}})
        diff = db.diff_since_last("acme", "subdomains", run2)
        self.assertEqual([k for k, _ in diff["new"]], ["b.acme.com"])

    def test_removed_asset_detected(self):
        run1 = db.start_run("acme", "subdomain_enum")
        db.upsert_assets("acme", "subdomains", run1, {"a.acme.com": {}, "b.acme.com": {}})

        run2 = db.start_run("acme", "subdomain_enum")
        db.upsert_assets("acme", "subdomains", run2, {"a.acme.com": {}})
        diff = db.diff_since_last("acme", "subdomains", run2)
        self.assertEqual([k for k, _ in diff["removed"]], ["b.acme.com"])

        active = db.get_active_assets("acme", "subdomains")
        self.assertNotIn("b.acme.com", active)
        self.assertIn("a.acme.com", active)

    def test_changed_attrs_detected(self):
        run1 = db.start_run("acme", "subdomain_enum")
        db.upsert_assets("acme", "http_probes", run1, {"a.acme.com": {"status_code": 200}})

        run2 = db.start_run("acme", "subdomain_enum")
        db.upsert_assets("acme", "http_probes", run2, {"a.acme.com": {"status_code": 403}})
        diff = db.diff_since_last("acme", "http_probes", run2)
        self.assertEqual(len(diff["changed"]), 1)
        key, before, after = diff["changed"][0]
        self.assertEqual(key, "a.acme.com")
        self.assertEqual(before["status_code"], 200)
        self.assertEqual(after["status_code"], 403)

    def test_diff_correct_across_three_runs(self):
        """
        Regression test for the v1 bug: `assets` only stored current state,
        so diffing against "the previous run" broke down once an asset had
        been touched more than twice. This exercises exactly that case.
        """
        run1 = db.start_run("acme", "subdomain_enum")
        db.upsert_assets("acme", "subdomains", run1, {"a.acme.com": {}})

        run2 = db.start_run("acme", "subdomain_enum")
        db.upsert_assets("acme", "subdomains", run2, {"a.acme.com": {}, "b.acme.com": {}})
        diff2 = db.diff_since_last("acme", "subdomains", run2)
        self.assertEqual([k for k, _ in diff2["new"]], ["b.acme.com"])

        run3 = db.start_run("acme", "subdomain_enum")
        db.upsert_assets("acme", "subdomains", run3, {"a.acme.com": {}, "b.acme.com": {}, "c.acme.com": {}})
        diff3 = db.diff_since_last("acme", "subdomains", run3)
        # only 'c' should be new in run3 — 'b' was already established in run2's history
        self.assertEqual([k for k, _ in diff3["new"]], ["c.acme.com"])

    def test_tables_are_independent(self):
        run1 = db.start_run("acme", "layer")
        db.upsert_assets("acme", "subdomains", run1, {"x.acme.com": {}})
        db.upsert_assets("acme", "http_probes", run1, {"y.acme.com": {}})
        subs_diff = db.diff_since_last("acme", "subdomains", run1)
        probes_diff = db.diff_since_last("acme", "http_probes", run1)
        self.assertEqual([k for k, _ in subs_diff["new"]], ["x.acme.com"])
        self.assertEqual([k for k, _ in probes_diff["new"]], ["y.acme.com"])

    def test_orgs_are_independent(self):
        run1 = db.start_run("acme", "subdomain_enum")
        db.upsert_assets("acme", "subdomains", run1, {"a.acme.com": {}})
        run2 = db.start_run("other-co", "subdomain_enum")
        db.upsert_assets("other-co", "subdomains", run2, {"z.other.com": {}})

        acme_active = db.get_active_assets("acme", "subdomains")
        other_active = db.get_active_assets("other-co", "subdomains")
        self.assertIn("a.acme.com", acme_active)
        self.assertNotIn("z.other.com", acme_active)
        self.assertIn("z.other.com", other_active)


if __name__ == "__main__":
    unittest.main()
