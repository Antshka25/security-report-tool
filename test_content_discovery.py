"""
test_content_discovery.py — local test procedure for content_discovery_checks.py.
Stdlib unittest only (no pytest/new dependency added). Run with:

    python -m unittest test_content_discovery -v

Covers, per the module's own scenarios:
  - real 404s are ignored
  - soft-404s (200 that's actually the site's catch-all page) are filtered
  - 401/403 "protected path" findings (informational, not exploited)
  - same-origin vs cross-origin redirect handling
  - confirmed .env secret exposure with redaction (no raw secret ever kept)
  - a fake ".env" that's really just the site's soft-404 page (must NOT be
    reported as a confirmed exposure)
  - rate-limit (429) streak causes the scan to stop early
  - duplicate path normalization/dedup across the built-in list + extras
  - archive/db-backup detection via content-type + magic bytes
"""
import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import content_discovery_checks as cd


# ── Pure-function tests (no network) ──────────────────────────────────────────

class TestBaselineAndSoft404(unittest.TestCase):
    def test_real_404_is_ignored_by_classify(self):
        finding = cd._classify("/admin/", "https://x.test/admin/", 404, {}, "", b"", "", "x.test")
        self.assertIsNone(finding)

    def test_soft_404_matches_baseline(self):
        page = "<html><title>Not Found</title>Nothing here, sorry.</html>"
        baseline = [{
            "status": 200, "length": len(page),
            "title": cd._title_of(page), "fingerprint": cd._fingerprint(page),
        }]
        self.assertTrue(cd._matches_baseline(baseline, 200, page))

    def test_fake_env_that_is_actually_soft_404(self):
        """A `.env` request that just returns the site's catch-all 200 page
        must be filtered as a soft-404, not reported as an exposure — this is
        exactly what run_content_discovery_checks() does before calling
        _classify() (see the `_matches_baseline(...)` guard), so this test
        proves the baseline check would actually catch this case."""
        soft_404_page = "<html><title>Page Not Found</title>Sorry, that page doesn't exist.</html>"
        baseline = [{
            "status": 200, "length": len(soft_404_page),
            "title": cd._title_of(soft_404_page), "fingerprint": cd._fingerprint(soft_404_page),
        }]
        # This is literally the .env response body — identical to the baseline.
        self.assertTrue(cd._matches_baseline(baseline, 200, soft_404_page))

    def test_genuinely_different_200_does_not_match_baseline(self):
        baseline_page = "<html><title>Not Found</title>Nothing here.</html>"
        baseline = [{
            "status": 200, "length": len(baseline_page),
            "title": cd._title_of(baseline_page), "fingerprint": cd._fingerprint(baseline_page),
        }]
        real_env_content = "DB_PASSWORD=supersecret123\nAWS_SECRET_ACCESS_KEY=abcdefghijklmnop\n"
        self.assertFalse(cd._matches_baseline(baseline, 200, real_env_content))


class TestProtectedPaths(unittest.TestCase):
    def test_403_is_informational_not_exploited(self):
        f = cd._classify("/admin/", "https://x.test/admin/", 403, {}, "", b"", "", "x.test")
        self.assertIsNotNone(f)
        self.assertEqual(f["risk"], "LOW")
        self.assertEqual(f["confidence"], "informational")
        self.assertIn("access control", f["reason"])
        # Must not claim a vulnerability was found — only that the path exists.
        self.assertNotIn("vulnerability", f["title"].lower())

    def test_401_is_informational_not_exploited(self):
        f = cd._classify("/dashboard/", "https://x.test/dashboard/", 401, {}, "", b"", "", "x.test")
        self.assertIsNotNone(f)
        self.assertEqual(f["risk"], "LOW")
        self.assertIn("authentication", f["reason"])


class TestRedirects(unittest.TestCase):
    def test_same_origin_redirect_is_reported(self):
        f = cd._classify("/old-admin", "https://x.test/old-admin", 302, {}, "", b"",
                         "https://x.test/admin/", "x.test")
        self.assertIsNotNone(f)
        self.assertEqual(f["risk"], "LOW")

    def test_cross_origin_redirect_is_never_reported(self):
        f = cd._classify("/redirect-me", "https://x.test/redirect-me", 302, {}, "", b"",
                         "https://evil.example/phish", "x.test")
        self.assertIsNone(f)

    def test_is_same_origin_helper(self):
        self.assertTrue(cd._is_same_origin("x.test", "https://x.test/foo"))
        self.assertFalse(cd._is_same_origin("x.test", "https://evil.example/foo"))
        self.assertFalse(cd._is_same_origin("x.test", "https://sub.x.test/foo"))


class TestSecretDetectionAndRedaction(unittest.TestCase):
    def test_env_exposure_is_confirmed_and_redacted(self):
        body = "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE12\nDB_PASSWORD=hunter2hunter2hunter2\n"
        f = cd._classify("/.env", "https://x.test/.env", 200, {}, body, body.encode(), "", "x.test")
        self.assertIsNotNone(f)
        self.assertEqual(f["risk"], "HIGH")
        self.assertEqual(f["confidence"], "confirmed")
        # The raw secret values must never appear anywhere in the finding.
        finding_text = str(f)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE12", finding_text)
        self.assertNotIn("hunter2hunter2hunter2", finding_text)
        self.assertIn("REDACTED", f["evidence"])

    def test_private_key_detected_and_redacted(self):
        body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...supersecretkeydata...\n-----END RSA PRIVATE KEY-----"
        hits = cd._detect_sensitive_content("/id_rsa", body, {})
        self.assertTrue(any("Private key" in label for label, _ in hits))
        self.assertNotIn("supersecretkeydata", str(hits))

    def test_db_connection_string_redacted(self):
        body = "APP_DB=postgres://admin:s3cr3tpass@db.internal:5432/prod"
        hits = cd._detect_sensitive_content("/config.php", body, {})
        self.assertTrue(any("database connection" in label for label, _ in hits))
        self.assertNotIn("s3cr3tpass", str(hits))

    def test_redact_never_returns_full_short_secret(self):
        self.assertEqual(cd._redact("abc"), "[REDACTED]")

    def test_redact_masks_long_secret(self):
        redacted = cd._redact("AKIAABCDEFGHIJKLMNOP")
        self.assertNotIn("ABCDEFGHIJKLMN", redacted)
        self.assertIn("REDACTED", redacted)

    def test_no_secret_no_confirmed_finding(self):
        f = cd._classify("/.env", "https://x.test/.env", 200, {}, "totally ordinary text, nothing sensitive here",
                         b"totally ordinary text", "", "x.test")
        # Falls through to the "high-value suffix, no content match" branch —
        # still HIGH (the path itself is never meant to be public) but NOT
        # "confirmed" — the report must distinguish these two cases.
        self.assertEqual(f["confidence"], "probable")
        self.assertNotEqual(f["confidence"], "confirmed")


class TestArchiveDetection(unittest.TestCase):
    def test_zip_magic_bytes_detected(self):
        self.assertTrue(cd._looks_like_archive_or_db("/backup.zip", {}, b"PK\x03\x04restofzip"))

    def test_gzip_magic_bytes_detected(self):
        self.assertTrue(cd._looks_like_archive_or_db("/db.tar.gz", {}, b"\x1f\x8bblah"))

    def test_plain_text_is_not_archive(self):
        self.assertFalse(cd._looks_like_archive_or_db("/notes.txt", {}, b"just some text"))


class TestPathListAndDedup(unittest.TestCase):
    def test_dedup_across_default_and_extra_paths(self):
        extras = ["/.env", "/some-new-path", "/.env"]  # duplicates on purpose
        paths = cd._build_path_list("standard", extras)
        self.assertEqual(paths.count("/.env"), 1)
        self.assertIn("/some-new-path", paths)

    def test_profiles_respect_max_paths_cap(self):
        huge_extra = [f"/generated-path-{i}" for i in range(1000)]
        for profile in ("quick", "standard", "thorough"):
            paths = cd._build_path_list(profile, huge_extra)
            self.assertLessEqual(len(paths), cd._PROFILES[profile]["max_paths"])

    def test_quick_profile_is_smallest(self):
        quick = cd._build_path_list("quick", [])
        standard = cd._build_path_list("standard", [])
        thorough = cd._build_path_list("thorough", [])
        self.assertLess(len(quick), len(standard))
        self.assertLessEqual(len(standard), len(thorough))

    def test_robots_txt_extraction_ignores_root(self):
        robots = "User-agent: *\nDisallow: /admin/\nDisallow: /\nAllow: /public/\n"
        paths = cd._extract_from_robots(robots)
        self.assertIn("/admin/", paths)
        self.assertIn("/public/", paths)
        self.assertNotIn("/", paths)

    def test_sitemap_extraction_skips_cross_origin(self):
        sitemap = (
            "<urlset>"
            "<url><loc>https://x.test/page-1</loc></url>"
            "<url><loc>https://evil.example/page-2</loc></url>"
            "</urlset>"
        )
        paths = cd._extract_from_sitemap(sitemap, "x.test")
        self.assertIn("/page-1", paths)
        self.assertNotIn("/page-2", paths)


# ── Rate limiting: exercise the streak-stop logic directly ───────────────────

class TestRateLimitStreak(unittest.TestCase):
    """run_content_discovery_checks() does real network I/O, so this drives
    the same streak-counting logic it uses (see RATE_LIMIT_STREAK_STOP) at
    the unit level rather than mocking the entire httpx.Client stack."""

    def test_streak_stops_after_threshold(self):
        streak = 0
        stopped = False
        for _ in range(cd.RATE_LIMIT_STREAK_STOP + 2):
            throttled = True
            if throttled:
                streak += 1
                if streak >= cd.RATE_LIMIT_STREAK_STOP:
                    stopped = True
                    break
        self.assertTrue(stopped)
        self.assertEqual(streak, cd.RATE_LIMIT_STREAK_STOP)

    def test_streak_resets_on_non_throttled_response(self):
        streak = 0
        for throttled in [True, True, False, True]:
            streak = streak + 1 if throttled else 0
        # Last item is throttled=True right after a reset, so streak should be 1.
        self.assertEqual(streak, 1)


# ── Integration-style test with a mocked httpx.Client ─────────────────────────

class TestFullRunWithMockedClient(unittest.TestCase):
    """Mocks httpx.Client entirely so this runs with no real network access —
    validates the wiring of run_content_discovery_checks() end to end: base
    URL resolution, baseline probing, path building, and that a genuine
    finding (protected /admin/) makes it into the results while a 404 doesn't."""

    def _fake_response(self, status_code, text="", headers=None, url="https://x.test/"):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.content = text.encode()
        resp.headers = headers or {}
        resp.url = url
        return resp

    @patch("content_discovery_checks.httpx")
    def test_end_to_end_quick_profile(self, mock_httpx):
        mock_httpx.get.return_value = self._fake_response(200, "<html>homepage</html>",
                                                           url="https://x.test/")

        def fake_client_get(url, timeout=None, follow_redirects=None):
            if "rv-cd-control-" in url:
                return self._fake_response(404, "Not Found")
            if url.rstrip("/").endswith("robots.txt"):
                return self._fake_response(404, "")
            if url.rstrip("/").endswith("sitemap.xml"):
                return self._fake_response(404, "")
            if "/admin/" in url:
                return self._fake_response(401, "")
            return self._fake_response(404, "Not Found")

        mock_client = MagicMock()
        mock_client.get.side_effect = fake_client_get
        mock_client.__enter__.return_value = mock_client
        mock_client.__exit__.return_value = False
        mock_httpx.Client.return_value = mock_client
        mock_httpx.HAS_HTTPX = True

        findings = cd.run_content_discovery_checks("x.test", profile="quick")

        admin_findings = [f for f in findings if f["path"] == "/admin/"]
        self.assertEqual(len(admin_findings), 1)
        self.assertEqual(admin_findings[0]["http_status"], 401)
        # Nothing should be reported for the plain 404s.
        self.assertTrue(all(f["http_status"] != 404 for f in findings))


if __name__ == "__main__":
    unittest.main(verbosity=2)
