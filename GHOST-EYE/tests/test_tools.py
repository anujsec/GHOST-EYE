import unittest
import sys
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import tools


class TestRun(unittest.TestCase):
    def test_invalid_output_bytes_are_replaced(self):
        output = tools.run([
            sys.executable,
            "-c",
            "import os; os.write(1, b'valid\\x81tail')",
        ])
        self.assertEqual(output, "valid\ufffdtail")

    def test_missing_stdout_returns_empty_string(self):
        with patch("tools.subprocess.run", return_value=SimpleNamespace(
            returncode=0, stderr="", stdout=None
        )):
            self.assertEqual(tools.run(["fake-tool"]), "")


class TestExtractEndpoints(unittest.TestCase):
    def test_finds_relative_paths(self):
        body = 'fetch("/api/v1/users"); axios.get("/internal/config")'
        endpoints = tools.extract_endpoints_from_js(body)
        self.assertIn("/api/v1/users", endpoints)
        self.assertIn("/internal/config", endpoints)

    def test_finds_absolute_urls(self):
        body = "const x = 'https://api.example.com/v2/data';"
        endpoints = tools.extract_endpoints_from_js(body)
        self.assertIn("https://api.example.com/v2/data", endpoints)

    def test_ignores_huge_base64_looking_blobs(self):
        blob = "/" + ("A" * 600)
        body = f'var x = "{blob}";'
        endpoints = tools.extract_endpoints_from_js(body)
        self.assertNotIn(blob, endpoints)

    def test_empty_body(self):
        self.assertEqual(tools.extract_endpoints_from_js(""), [])


class TestSecretScanning(unittest.TestCase):
    def test_detects_aws_key(self):
        body = 'const key = "AKIAABCDEFGHIJKLMNOP";'
        hits = tools.scan_js_for_secrets(body)
        types = [h["type"] for h in hits]
        self.assertIn("aws_access_key_id", types)

    def test_detects_google_api_key(self):
        body = 'apiKey: "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"'
        hits = tools.scan_js_for_secrets(body)
        types = [h["type"] for h in hits]
        self.assertIn("google_api_key", types)

    def test_clean_js_has_no_hits(self):
        body = "function add(a, b) { return a + b; } console.log(add(1,2));"
        hits = tools.scan_js_for_secrets(body)
        self.assertEqual(hits, [])

    def test_match_preview_is_truncated(self):
        body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        hits = tools.scan_js_for_secrets(body)
        self.assertTrue(any(h["type"] == "private_key_block" for h in hits))


class TestNormalizeUrl(unittest.TestCase):
    def test_strips_fragment(self):
        self.assertEqual(tools.normalize_url("https://example.com/page#section"), "https://example.com/page")

    def test_strips_trailing_slash(self):
        self.assertEqual(tools.normalize_url("https://example.com/page/"), "https://example.com/page")


class TestDedupe(unittest.TestCase):
    def test_dedupes_and_sorts(self):
        self.assertEqual(tools.dedupe(["b", "a", "a", "", "  ", "c"]), ["a", "b", "c"])


class TestWhichOrWarn(unittest.TestCase):
    def test_missing_binary_returns_false(self):
        self.assertFalse(tools.which_or_warn("definitely-not-a-real-binary-xyz"))

    def test_present_binary_returns_true(self):
        self.assertTrue(tools.which_or_warn("python3"))


if __name__ == "__main__":
    unittest.main()
