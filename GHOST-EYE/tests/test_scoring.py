import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scoring import score_host, tier_hosts


class TestScoreHost(unittest.TestCase):
    def test_interesting_label_scores_higher(self):
        self.assertGreater(score_host("api.example.com"), score_host("www.example.com"))
        self.assertGreater(score_host("admin.example.com"), score_host("blog.example.com"))
        self.assertGreater(score_host("staging.example.com"), score_host("shop.example.com"))

    def test_unusual_status_code_adds_score(self):
        plain = score_host("host.example.com", {"status_code": 200})
        unusual = score_host("host.example.com", {"status_code": 403})
        self.assertGreater(unusual, plain)

    def test_interesting_tech_adds_score(self):
        plain = score_host("host.example.com", {"tech": ["nginx"]})
        interesting = score_host("host.example.com", {"tech": ["Jenkins"]})
        self.assertGreater(interesting, plain)

    def test_new_host_adds_score(self):
        old = score_host("host.example.com", {}, is_new=False)
        new = score_host("host.example.com", {}, is_new=True)
        self.assertGreater(new, old)

    def test_never_returns_negative(self):
        self.assertGreaterEqual(score_host("plain.example.com"), 0)


class TestTierHosts(unittest.TestCase):
    def test_tier_sizes_respected(self):
        hosts = [f"h{i}.example.com" for i in range(100)]
        tiers = tier_hosts(hosts, {}, tier1_size=10, tier2_size=20)
        self.assertEqual(len(tiers["tier1"]), 10)
        self.assertEqual(len(tiers["tier2"]), 20)
        self.assertEqual(len(tiers["tier3"]), 70)

    def test_all_hosts_accounted_for(self):
        hosts = [f"h{i}.example.com" for i in range(15)]
        tiers = tier_hosts(hosts, {}, tier1_size=10, tier2_size=20)
        total = len(tiers["tier1"]) + len(tiers["tier2"]) + len(tiers["tier3"])
        self.assertEqual(total, 15)

    def test_interesting_hosts_land_in_tier1(self):
        hosts = ["api.example.com"] + [f"h{i}.example.com" for i in range(20)]
        tiers = tier_hosts(hosts, {}, tier1_size=5, tier2_size=10)
        self.assertIn("api.example.com", tiers["tier1"])


if __name__ == "__main__":
    unittest.main()
