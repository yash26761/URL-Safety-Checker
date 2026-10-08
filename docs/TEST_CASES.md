# Test Cases

Run all tests: `python -m unittest discover -s tests -v` (19 tests). Only harmless example URLs are used and no website is opened.

| # | Test | Input | Expected result |
|---|---|---|---|
| 1 | Valid HTTPS URL | `https://example.com` | HTTPS PASS, score 0, LOW RISK |
| 2 | HTTP URL | `http://example.com` | HTTPS WARNING, score 20, LOW RISK |
| 3 | IP address URL | `https://192.168.1.10/home` | IP Address WARNING, score 30 |
| 3b | Domain is not an IP | `https://example.com` | IP Address PASS |
| 4 | Suspicious keyword | `https://example.com/login` | Keywords WARNING, score 10 |
| 4b | Keyword points capped | `.../login/verify/account/password` | score 20 (cap) |
| 4c | No keyword | `https://example.com/products` | Keywords PASS |
| 5 | Long URL | 75+ characters of path | URL Length WARNING, score 15 |
| 5b | Exactly at threshold | URL of exactly 75 characters | URL Length PASS |
| 6 | Multiple subdomains | `https://a.b.c.example.com` | Subdomain WARNING, score 15 |
| 6b | Normal subdomain | `https://www.example.com` | Subdomain PASS |
| 6c | Subdomain counting | several hostnames | 0, 1, 3 and 0 (IP) |
| 7 | Invalid URLs | empty, spaces, `None`, `hello`, `example.com`, `ftp://...`, `https://`, `http://999.1.1.1`, `http://localhost`, bad port | `is_valid = False`, error message, no checks run, no crash |
| 8 | Combined indicators | `http://192.168.1.10/login/verify-account` | score 70, HIGH RISK, 3 reasons |
| 8b | Many indicators with subdomains | `http://login.account.security.example.com/...` (long) | score 70, HIGH RISK |
| 8c | Highest realistic score | IP + keywords + long URL over HTTP | score 85, HIGH RISK |
| 9 | Score boundaries | several URLs | score always between 0 and 100 |
| 10 | Risk classification | 0, 30, 31, 60, 61, 100 | LOW, LOW, MEDIUM, MEDIUM, HIGH, HIGH |
| 11 | Reasons and advice present | safe and risky URLs | reasons and recommendations are never empty |
