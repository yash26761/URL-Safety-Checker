"""
url_checker.py - core logic of the URL Safety Checker.

This module contains ONLY the analysis logic (no Streamlit code), so it can be
tested on its own. It never opens, visits or downloads the URL it analyses.
It only looks at the text of the URL.

Educational tool: the score is NOT a probability of malware and does NOT
prove that a website is safe or malicious.
"""

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# SETTINGS - change these values to tune the tool
# ---------------------------------------------------------------------------

# A URL longer than this many characters gets a WARNING.
LONG_URL_THRESHOLD = 75

# More than this many subdomain parts gets a WARNING.
# Example: login.account.security.example.com has 3 subdomains (login, account, security).
MAX_NORMAL_SUBDOMAINS = 2

# Words that are often used in phishing URLs (but also in many safe URLs).
SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "account",
    "password",
    "security",
    "update",
    "confirm",
]

# ---------------------------------------------------------------------------
# RISK SCORE WEIGHTS - how many points each indicator adds
# Weights add up to 100 in total. In practice the highest score is 85, because an
# IP-address hostname has no subdomains (20 + 30 + 20 + 15).
# ---------------------------------------------------------------------------
POINTS_NO_HTTPS = 20
POINTS_IP_ADDRESS = 30
POINTS_PER_KEYWORD = 10
POINTS_KEYWORDS_MAX = 20      # keyword points are capped at this value
POINTS_LONG_URL = 15
POINTS_MANY_SUBDOMAINS = 15

# Risk level boundaries (inclusive)
LOW_RISK_MAX = 30       # 0-30   -> LOW RISK
MEDIUM_RISK_MAX = 60    # 31-60  -> MEDIUM RISK, 61-100 -> HIGH RISK

PASS = "PASS"
WARNING = "WARNING"

# A single label (part between dots) of a hostname: letters, digits, hyphens.
_HOST_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
# Anything that looks like four dotted numbers, e.g. 192.168.1.10
_LOOKS_LIKE_IPV4 = re.compile(r"^\d+(\.\d+){3}$")


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------
@dataclass
class CheckResult:
    """Result of one security check."""
    name: str       # e.g. "HTTPS"
    status: str     # PASS or WARNING
    points: int     # points added to the risk score
    message: str    # short explanation shown to the user


@dataclass
class AnalysisResult:
    """Everything the UI needs to display."""
    url: str
    is_valid: bool
    error_message: str = ""
    checks: list = field(default_factory=list)
    score: int = 0
    risk_level: str = ""
    reasons: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def is_ipv4_address(hostname):
    """Return True if hostname is a valid IPv4 address such as 192.168.1.10."""
    if not _LOOKS_LIKE_IPV4.match(hostname):
        return False
    return all(0 <= int(part) <= 255 for part in hostname.split("."))


def validate_url(url):
    """
    Check that the input is reasonably formatted as an http/https URL.
    Returns (True, "") if valid, otherwise (False, "reason").
    """
    if url is None or not url.strip():
        return False, "Please enter a URL."

    url = url.strip()

    if re.search(r"\s", url):
        return False, "A URL cannot contain spaces."

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        _ = parsed.port  # raises ValueError if the port is invalid
    except ValueError:
        return False, "The URL is not correctly formatted."

    if parsed.scheme.lower() not in ("http", "https"):
        return False, "The URL must start with http:// or https://"

    if not hostname:
        return False, "The URL does not contain a website name (hostname)."

    hostname = hostname.lower()

    if _LOOKS_LIKE_IPV4.match(hostname):
        if is_ipv4_address(hostname):
            return True, ""
        return False, "The IP address in the URL is not valid."

    labels = hostname.split(".")
    if len(labels) < 2:
        return False, "The hostname must contain a dot, e.g. example.com"
    if not all(_HOST_LABEL.match(label) for label in labels):
        return False, "The hostname contains invalid characters."
    if labels[-1].isdigit():
        return False, "The domain ending (e.g. .com) cannot be only numbers."

    return True, ""


def get_hostname(url):
    """Return the lower-case hostname of a URL (empty string if none)."""
    return (urlparse(url.strip()).hostname or "").lower()


def count_subdomains(hostname):
    """
    Count subdomain parts: everything before the last two labels.
    www.example.com -> 1, login.account.security.example.com -> 3.
    IP addresses have no subdomains.
    (Simplification: multi-part endings like .co.uk are not handled.)
    """
    if is_ipv4_address(hostname):
        return 0
    return max(0, len(hostname.split(".")) - 2)


def classify_risk(score):
    """Convert a 0-100 score into LOW RISK / MEDIUM RISK / HIGH RISK."""
    score = max(0, min(100, score))
    if score <= LOW_RISK_MAX:
        return "LOW RISK"
    if score <= MEDIUM_RISK_MAX:
        return "MEDIUM RISK"
    return "HIGH RISK"


# ---------------------------------------------------------------------------
# The five security checks
# ---------------------------------------------------------------------------
def check_https(url):
    """Check 1 - does the URL use HTTPS?"""
    if urlparse(url).scheme.lower() == "https":
        return CheckResult("HTTPS", PASS, 0, "The URL uses HTTPS.")
    return CheckResult(
        "HTTPS", WARNING, POINTS_NO_HTTPS,
        "URL does not use HTTPS (the connection is not encrypted).",
    )


def check_ip_address(hostname):
    """Check 2 - is the hostname an IPv4 address instead of a domain name?"""
    if is_ipv4_address(hostname):
        return CheckResult(
            "IP Address", WARNING, POINTS_IP_ADDRESS,
            "IP address detected in hostname instead of a domain name.",
        )
    return CheckResult("IP Address", PASS, 0, "The hostname is a domain name, not an IP address.")


def check_keywords(url):
    """Check 3 - does the URL contain any word from SUSPICIOUS_KEYWORDS?"""
    lowered = url.lower()
    found = [word for word in SUSPICIOUS_KEYWORDS if word in lowered]
    if not found:
        return CheckResult("Suspicious Keywords", PASS, 0, "No suspicious keywords found.")
    points = min(len(found) * POINTS_PER_KEYWORD, POINTS_KEYWORDS_MAX)
    return CheckResult(
        "Suspicious Keywords", WARNING, points,
        "Suspicious keyword(s) detected: " + ", ".join(found) + ".",
    )


def check_url_length(url):
    """Check 4 - is the URL longer than LONG_URL_THRESHOLD characters?"""
    length = len(url)
    if length > LONG_URL_THRESHOLD:
        return CheckResult(
            "URL Length", WARNING, POINTS_LONG_URL,
            f"URL is unusually long ({length} characters; limit is {LONG_URL_THRESHOLD}).",
        )
    return CheckResult("URL Length", PASS, 0, f"URL length is normal ({length} characters).")


def check_subdomains(hostname):
    """Check 5 - does the hostname have more than MAX_NORMAL_SUBDOMAINS subdomains?"""
    count = count_subdomains(hostname)
    if count > MAX_NORMAL_SUBDOMAINS:
        return CheckResult(
            "Subdomain Complexity", WARNING, POINTS_MANY_SUBDOMAINS,
            f"Hostname has many subdomains ({count}; limit is {MAX_NORMAL_SUBDOMAINS}).",
        )
    return CheckResult("Subdomain Complexity", PASS, 0, f"Subdomain count is normal ({count}).")


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------
def build_recommendations(checks):
    """Return safe-browsing advice based on which checks raised a WARNING."""
    warned = {check.name for check in checks if check.status == WARNING}
    tips = []

    if "HTTPS" in warned:
        tips.append("Prefer HTTPS websites, especially when entering personal information.")
    if "IP Address" in warned:
        tips.append("Be careful with links that use a raw IP address instead of a website name.")
    if "Suspicious Keywords" in warned:
        tips.append("Avoid entering passwords on suspicious pages. Verify the website's domain "
                    "before entering credentials.")
    if "URL Length" in warned:
        tips.append("Long URLs can hide the real destination. Check the main domain carefully.")
    if "Subdomain Complexity" in warned:
        tips.append("Read the hostname from right to left: the real website is the last two "
                    "parts (e.g. example.com), not the words in front of them.")

    # General advice shown for every URL
    tips.append("Be cautious with links received through unexpected messages or emails.")
    tips.append("Do not assume that HTTPS alone guarantees that a website is trustworthy.")
    return tips


# ---------------------------------------------------------------------------
# Main function used by the UI
# ---------------------------------------------------------------------------
def analyze_url(url):
    """
    Validate the URL, run the five checks and build the full result.
    Never raises an error for bad input: an invalid URL gives is_valid=False.
    """
    url = (url or "").strip()
    valid, error = validate_url(url)
    if not valid:
        return AnalysisResult(url=url, is_valid=False, error_message=error)

    hostname = get_hostname(url)
    checks = [
        check_https(url),
        check_ip_address(hostname),
        check_keywords(url),
        check_url_length(url),
        check_subdomains(hostname),
    ]

    # Risk score = sum of the points from all checks (kept between 0 and 100)
    score = max(0, min(100, sum(check.points for check in checks)))

    reasons = [check.message for check in checks if check.status == WARNING]
    if not reasons:
        reasons = ["None of the five basic indicators were triggered."]

    return AnalysisResult(
        url=url,
        is_valid=True,
        checks=checks,
        score=score,
        risk_level=classify_risk(score),
        reasons=reasons,
        recommendations=build_recommendations(checks),
    )
