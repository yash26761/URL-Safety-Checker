"""
Unit tests for url_checker.py.

Run from the project folder with:
    python -m unittest discover -s tests -v
(pytest also works:  pytest)

No test opens a website. Only harmless example URLs are used.
"""

import os
import sys
import unittest

# Make url_checker.py (in the project folder) importable from the tests folder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import url_checker as uc


def status_of(result, check_name):
    """Return the PASS/WARNING status of one check by name."""
    return next(c.status for c in result.checks if c.name == check_name)


class TestUrlChecker(unittest.TestCase):

    # 1. Valid HTTPS URL
    def test_valid_https_url(self):
        result = uc.analyze_url("https://example.com")
        self.assertTrue(result.is_valid)
        self.assertEqual(status_of(result, "HTTPS"), "PASS")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.risk_level, "LOW RISK")

    # 2. HTTP URL
    def test_http_url(self):
        result = uc.analyze_url("http://example.com")
        self.assertEqual(status_of(result, "HTTPS"), "WARNING")
        self.assertEqual(result.score, uc.POINTS_NO_HTTPS)
        self.assertEqual(result.risk_level, "LOW RISK")  # HTTP alone is not "malicious"

    # 3. IP address URL
    def test_ip_address_url(self):
        result = uc.analyze_url("https://192.168.1.10/home")
        self.assertEqual(status_of(result, "IP Address"), "WARNING")
        self.assertEqual(result.score, uc.POINTS_IP_ADDRESS)

    def test_domain_is_not_ip_address(self):
        result = uc.analyze_url("https://example.com")
        self.assertEqual(status_of(result, "IP Address"), "PASS")

    # 4. Suspicious keyword
    def test_suspicious_keyword(self):
        result = uc.analyze_url("https://example.com/login")
        self.assertEqual(status_of(result, "Suspicious Keywords"), "WARNING")
        self.assertEqual(result.score, uc.POINTS_PER_KEYWORD)

    def test_keyword_points_are_capped(self):
        result = uc.analyze_url("https://example.com/login/verify/account/password")
        self.assertEqual(result.score, uc.POINTS_KEYWORDS_MAX)

    def test_no_keyword(self):
        result = uc.analyze_url("https://example.com/products")
        self.assertEqual(status_of(result, "Suspicious Keywords"), "PASS")

    # 5. Long URL
    def test_long_url(self):
        url = "https://example.com/" + "a" * uc.LONG_URL_THRESHOLD
        result = uc.analyze_url(url)
        self.assertEqual(status_of(result, "URL Length"), "WARNING")
        self.assertEqual(result.score, uc.POINTS_LONG_URL)

    def test_url_exactly_at_threshold_passes(self):
        base = "https://example.com/"
        url = base + "a" * (uc.LONG_URL_THRESHOLD - len(base))
        self.assertEqual(len(url), uc.LONG_URL_THRESHOLD)
        self.assertEqual(status_of(uc.analyze_url(url), "URL Length"), "PASS")

    # 6. Multiple subdomains
    def test_multiple_subdomains(self):
        result = uc.analyze_url("https://a.b.c.example.com")
        self.assertEqual(status_of(result, "Subdomain Complexity"), "WARNING")
        self.assertEqual(result.score, uc.POINTS_MANY_SUBDOMAINS)

    def test_normal_subdomain(self):
        result = uc.analyze_url("https://www.example.com")
        self.assertEqual(status_of(result, "Subdomain Complexity"), "PASS")

    def test_count_subdomains(self):
        self.assertEqual(uc.count_subdomains("example.com"), 0)
        self.assertEqual(uc.count_subdomains("www.example.com"), 1)
        self.assertEqual(uc.count_subdomains("login.account.security.example.com"), 3)
        self.assertEqual(uc.count_subdomains("192.168.1.10"), 0)

    # 7. Invalid URL
    def test_invalid_urls_do_not_crash(self):
        bad_inputs = [
            "", "   ", None, "hello", "example.com", "ftp://example.com",
            "https://", "http://a b.com", "http://999.1.1.1",
            "http://localhost", "https://example.com:99999",
        ]
        for text in bad_inputs:
            with self.subTest(text=text):
                result = uc.analyze_url(text)
                self.assertFalse(result.is_valid)
                self.assertTrue(result.error_message)
                self.assertEqual(result.checks, [])  # no normal analysis

    # 8. Combined indicators
    def test_combined_indicators(self):
        result = uc.analyze_url("http://192.168.1.10/login/verify-account")
        # no HTTPS 20 + IP 30 + keywords capped 20 = 70
        self.assertEqual(result.score, 70)
        self.assertEqual(result.risk_level, "HIGH RISK")
        self.assertEqual(len(result.reasons), 3)

    def test_many_indicators_with_subdomains(self):
        url = ("http://login.account.security.example.com/verify/password/"
               "confirm/update?session=" + "x" * 40)
        result = uc.analyze_url(url)
        # no HTTPS 20 + keywords capped 20 + long URL 15 + subdomains 15 = 70
        self.assertEqual(result.score, 70)
        self.assertEqual(result.risk_level, "HIGH RISK")

    def test_highest_realistic_score(self):
        # An IP address has no subdomains, so the practical maximum is 85
        url = "http://192.168.1.10/login/verify/account/" + "x" * 50
        result = uc.analyze_url(url)
        self.assertEqual(result.score, 85)  # 20 + 30 + 20 + 15
        self.assertEqual(result.risk_level, "HIGH RISK")

    # 9. Score boundaries
    def test_score_is_always_between_0_and_100(self):
        urls = ["https://example.com", "http://192.168.1.10/login",
                "http://a.b.c.d.example.com/login/verify/" + "z" * 100]
        for url in urls:
            with self.subTest(url=url):
                self.assertTrue(0 <= uc.analyze_url(url).score <= 100)

    # 10. Risk classification
    def test_risk_classification_boundaries(self):
        self.assertEqual(uc.classify_risk(0), "LOW RISK")
        self.assertEqual(uc.classify_risk(30), "LOW RISK")
        self.assertEqual(uc.classify_risk(31), "MEDIUM RISK")
        self.assertEqual(uc.classify_risk(60), "MEDIUM RISK")
        self.assertEqual(uc.classify_risk(61), "HIGH RISK")
        self.assertEqual(uc.classify_risk(100), "HIGH RISK")

    # Extra: results always include explanation and advice
    def test_reasons_and_recommendations_present(self):
        for url in ["https://example.com", "http://192.168.1.10/login"]:
            result = uc.analyze_url(url)
            self.assertTrue(result.reasons)
            self.assertTrue(result.recommendations)


if __name__ == "__main__":
    unittest.main()
