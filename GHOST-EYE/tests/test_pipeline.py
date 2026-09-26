import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

import db
import core.cache as cache_mod
import core.pipeline as pipeline
import tools


FAKE_PROBE = [
    {"input": "api.example.test", "url": "https://api.example.test", "status_code": 200,
     "title": "API", "tech": ["nginx"], "webserver": "nginx", "content_length": 123},
    {"input": "www.example.test", "url": "https://www.example.test", "status_code": 200,
     "title": "Home", "tech": ["nginx"], "webserver": "nginx", "content_length": 456},
]


def _patch_all_tools():
    """Returns a dict of patch targets -> mock return values, used with patch.multiple-style application."""
    return {
        "crtsh": lambda domain: ["www.example.test", "api.example.test"],
        "subfinder": lambda domain: ["www.example.test"],
        "amass_passive": lambda domain: ["api.example.test"],
        "amass_intel_org": lambda org: [],
        "asnmap": lambda org: [],
        "puredns_bruteforce": lambda domain, wl, resolvers: [],
        "alterx_permutations": lambda subs: [],
        "puredns_resolve": lambda domains, resolvers: [],
        "dnsx": lambda hosts, timeout=300: [{"host": h, "a": ["1.2.3.4"]} for h in hosts],
        "httpx_probe": lambda hosts, mode="fast", timeout=900: FAKE_PROBE,
        "nuclei_takeovers": lambda hosts, timeout=300: [],
        "gowitness_screenshot": lambda urls, out_dir, timeout=600: None,
        "gau": lambda domain: ["https://www.example.test/app.js"],
        "waybackurls": lambda domain: [],
        "wamore": lambda domain, timeout=600: [],
        "katana_crawl": lambda urls, depth=1, timeout=600: [],
        "normalize_urls_batch": lambda urls, timeout=300: urls,
        "extract_api_endpoints": lambda urls: {},
        "analyze_js_url": lambda url, use_trufflehog=False, timeout=30: {
            "url": url, "endpoints": ["/api/v1/secret-endpoint"], "secrets": []
        },
        "jsluice_analyze": lambda url, timeout=30: {"url": url, "endpoints": [], "source_maps": []},
        "extract_source_maps": lambda urls: [],
        "arjun_params": lambda url, timeout=300: [],
        "feroxbuster": lambda url, wl, timeout=300: [],
        "ffuf": lambda url, wl, timeout=300: [],
        "naabu_scan": lambda targets, timeout=600: [{"host": host, "port": 443} for host in targets],
        "nmap_service_detect": lambda targets, timeout=600: [],
        "gitleaks_scan": lambda path, timeout=300: [],
        "s3scanner": lambda bucket_names_file, timeout=300: [],
        "validate_resolvers": lambda input_file, output_file, timeout=300: None,
        "nuclei_scan": lambda hosts, tags, rate_limit=50, concurrency=25, timeout=1800: [],
    }


class TestPipelineSmoke(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._base_dir = Path(self._tmpdir.name)

        self._orig_db_path = db.DB_PATH
        db.DB_PATH = self._base_dir / "recon.db"
        self._orig_cache_path = cache_mod.CACHE_PATH
        cache_mod.CACHE_PATH = self._base_dir / "cache.db"

        self._patchers = [patch.object(tools, name, side_effect=fn) for name, fn in _patch_all_tools().items()]
        self._mocks = {p.attribute: p.start() for p in self._patchers}

    def tearDown(self):
        for p in self._patchers:
            p.stop()
        db.DB_PATH = self._orig_db_path
        cache_mod.CACHE_PATH = self._orig_cache_path
        self._tmpdir.cleanup()

    def test_fast_mode_runs_and_returns_summary(self):
        cfg = pipeline.merge_defaults({})
        summary = pipeline.run_pipeline(
            target="example.test", org="Example", cfg=cfg, base_dir=self._base_dir,
            reporter=pipeline.Reporter(),
        )
        self.assertEqual(summary["mode"], "fast")
        self.assertEqual(summary["org"], "Example")
        self.assertGreaterEqual(summary["counts"]["subdomains"], 2)
        self.assertGreaterEqual(summary["counts"]["live_hosts"], 2)
        self.assertIn("endpoints", summary["counts"])
        self.assertTrue(Path(summary["run_dir"]).exists())
        self.assertTrue((Path(summary["run_dir"]) / "summary.json").exists())
        for name in ("naabu_scan", "arjun_params", "jsluice_analyze", "gitleaks_scan", "s3scanner"):
            self._mocks[name].assert_not_called()

    def test_configured_tools_run_in_pipeline(self):
        cfg = pipeline.merge_defaults({
            "url_discovery": {"historical_sources": ["gau", "waybackurls", "wamore"]},
            "javascript": {"jsluice": True, "trufflehog": True, "source_maps": True},
            "parameter_discovery": {"enabled": True, "max_urls": 2, "timeout": 10},
            "content_discovery": {"enabled": True, "tool": "ffuf", "max_hosts": 1},
            "port_discovery": {"enabled": True, "service_detection": True},
            "wordlists": {"content": "/fake/content.txt"},
            "resolvers": {"raw": "/fake/raw-resolvers.txt", "validated": "/fake/valid-resolvers.txt",
                          "validate_on_run": True},
            "local_scans": {"gitleaks_path": "/fake/repository",
                            "s3_bucket_names_file": "/fake/buckets.txt"},
        })

        summary = pipeline.run_pipeline(
            target="example.test", org="Example", cfg=cfg, base_dir=self._base_dir,
            reporter=pipeline.Reporter(),
        )

        for name in ("wamore", "jsluice_analyze", "extract_source_maps", "arjun_params", "ffuf",
                     "naabu_scan", "nmap_service_detect", "validate_resolvers", "gitleaks_scan", "s3scanner"):
            self.assertTrue(self._mocks[name].called, name)
        self._mocks["feroxbuster"].assert_not_called()
        self.assertTrue((Path(summary["run_dir"]) / "api_endpoints.json").exists())
        self.assertEqual(summary["counts"]["open_ports"], 2)

    def test_fast_mode_skips_brute_force(self):
        cfg = pipeline.merge_defaults({})
        pipeline.run_pipeline(
            target="example.test", org="Example", cfg=cfg, base_dir=self._base_dir,
            reporter=pipeline.Reporter(),
        )
        self._mocks["puredns_bruteforce"].assert_not_called()

    def test_deep_flag_enables_brute_force_path_when_configured(self):
        cfg = pipeline.merge_defaults({
            "wordlists": {"subdomains": "/fake/wordlist.txt"},
            "resolvers": {"validated": "/fake/resolvers.txt"},
        })
        pipeline.run_pipeline(
            target="example.test", org="Example", cfg=cfg, base_dir=self._base_dir,
            reporter=pipeline.Reporter(), deep=True,
        )
        self._mocks["puredns_bruteforce"].assert_called()
        self._mocks["asnmap"].assert_called()
        self._mocks["amass_intel_org"].assert_called()

    def test_no_nuclei_flag_disables_nuclei(self):
        cfg = pipeline.merge_defaults({})
        pipeline.run_pipeline(
            target="example.test", org="Example", cfg=cfg, base_dir=self._base_dir,
            reporter=pipeline.Reporter(), no_nuclei=True,
        )
        self._mocks["nuclei_scan"].assert_not_called()

    def test_nuclei_runs_by_default(self):
        cfg = pipeline.merge_defaults({})
        pipeline.run_pipeline(
            target="example.test", org="Example", cfg=cfg, base_dir=self._base_dir,
            reporter=pipeline.Reporter(),
        )
        self._mocks["nuclei_scan"].assert_called()

    def test_screenshots_flag_triggers_background_screenshot(self):
        cfg = pipeline.merge_defaults({})
        pipeline.run_pipeline(
            target="example.test", org="Example", cfg=cfg, base_dir=self._base_dir,
            reporter=pipeline.Reporter(), screenshots=True,
        )
        self._mocks["gowitness_screenshot"].assert_called()

    def test_screenshots_disabled_by_default(self):
        cfg = pipeline.merge_defaults({})
        pipeline.run_pipeline(
            target="example.test", org="Example", cfg=cfg, base_dir=self._base_dir,
            reporter=pipeline.Reporter(),
        )
        self._mocks["gowitness_screenshot"].assert_not_called()

    def test_second_run_reports_no_new_subdomains(self):
        cfg = pipeline.merge_defaults({})
        pipeline.run_pipeline(target="example.test", org="Example", cfg=cfg,
                               base_dir=self._base_dir, reporter=pipeline.Reporter())
        summary2 = pipeline.run_pipeline(target="example.test", org="Example", cfg=cfg,
                                          base_dir=self._base_dir, reporter=pipeline.Reporter())
        self.assertEqual(summary2["changes"]["new_subdomains"], 0)

    def test_partial_tool_failure_recorded_as_warning_not_crash(self):
        self._mocks["subfinder"].side_effect = RuntimeError("subfinder exploded")
        cfg = pipeline.merge_defaults({})
        summary = pipeline.run_pipeline(
            target="example.test", org="Example", cfg=cfg, base_dir=self._base_dir,
            reporter=pipeline.Reporter(),
        )
        self.assertTrue(any("subfinder" in w for w in summary["warnings"]))
        # pipeline still completed and produced a summary despite the failure
        self.assertIn("counts", summary)


if __name__ == "__main__":
    unittest.main()
