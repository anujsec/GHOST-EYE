import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.target import normalize_target, normalize_targets, derive_org, InvalidTargetError


class TestNormalizeTarget(unittest.TestCase):
    def test_bare_domain(self):
        self.assertEqual(normalize_target("example.com"), "example.com")

    def test_https_scheme(self):
        self.assertEqual(normalize_target("https://example.com"), "example.com")

    def test_http_scheme(self):
        self.assertEqual(normalize_target("http://example.com"), "example.com")

    def test_trailing_slash(self):
        self.assertEqual(normalize_target("https://example.com/"), "example.com")

    def test_path_and_query(self):
        self.assertEqual(normalize_target("https://example.com/some/path?x=1"), "example.com")

    def test_uppercase_and_www(self):
        self.assertEqual(normalize_target("HTTPS://WWW.Example.COM/"), "www.example.com")

    def test_port(self):
        self.assertEqual(normalize_target("example.com:8443"), "example.com")

    def test_trailing_dot_fqdn(self):
        self.assertEqual(normalize_target("example.com."), "example.com")

    def test_whitespace(self):
        self.assertEqual(normalize_target("  example.com  "), "example.com")

    def test_empty_raises(self):
        with self.assertRaises(InvalidTargetError):
            normalize_target("")

    def test_garbage_raises(self):
        with self.assertRaises(InvalidTargetError):
            normalize_target("not a domain at all!!")

    def test_localhost_allowed(self):
        self.assertEqual(normalize_target("localhost"), "localhost")

    def test_ip_allowed(self):
        self.assertEqual(normalize_target("http://127.0.0.1/"), "127.0.0.1")


class TestNormalizeTargets(unittest.TestCase):
    def test_comma_separated_string(self):
        result = normalize_targets("example.com, https://example.io/, example.com")
        self.assertEqual(result, ["example.com", "example.io"])  # deduped, order preserved

    def test_list_input(self):
        result = normalize_targets(["example.com", "https://example.com/"])
        self.assertEqual(result, ["example.com"])


class TestDeriveOrg(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(derive_org("example.com"), "Example")

    def test_subdomain(self):
        self.assertEqual(derive_org("api.example.com"), "Example")

    def test_two_part_tld(self):
        self.assertEqual(derive_org("example.co.uk"), "Example")


if __name__ == "__main__":
    unittest.main()
