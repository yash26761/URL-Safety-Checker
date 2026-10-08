# Demonstration and Viva Guide

## Demonstration Sequence
1. Run `streamlit run app.py` and explain the flow: INPUT → ANALYSIS → SCORE → REASONS → RECOMMENDATIONS.
2. Enter the example inputs below one by one and click **Check URL**.
3. For each, point out the five checks, the score, the reasons and the recommendations.
4. Open "Show how the score was calculated" to show that the score is just added points.
5. Run the tests: `python -m unittest discover -s tests -v`.

## Example Inputs and Expected Outputs
| Input | Score | Level | Main reasons |
|---|---|---|---|
| `https://example.com` | 0 / 100 | LOW RISK | no warnings |
| `http://example.com` | 20 / 100 | LOW RISK | no HTTPS |
| `https://login.account.security.example.com` | 35 / 100 | MEDIUM RISK | keywords (login, account, security), 3 subdomains |
| `http://192.168.1.10/login` | 60 / 100 | MEDIUM RISK | no HTTPS, IP address, keyword "login" |
| `http://192.168.1.10/login/verify-account` | 70 / 100 | HIGH RISK | no HTTPS, IP address, keywords (login, verify, account) |
| `hello` | — | — | error: must start with http:// or https:// |

Tip: `http://example.com` scores only 20 — this shows that HTTP alone is not treated as "malicious".

## Short Project Explanation
"This project is a URL Safety Checker. The user enters a URL and my Python program checks five simple things: HTTPS, an IP address instead of a domain, suspicious words, URL length and the number of subdomains. Each warning adds points to a score from 0 to 100, which is classified as low, medium or high risk. The tool explains the reasons and gives safe-browsing tips. It only reads the URL text, never visits the site, and is for learning, not a guarantee."

## Limitations
- URL text only; no page content, certificates, domain age or blacklists
- Simple rules cause false positives and false negatives
- IPv4 only; basic subdomain counting
- Score is educational, not a probability

## Important Cybersecurity Concepts Demonstrated
- Phishing and suspicious URL characteristics
- HTTPS and encryption in transit (and its limits)
- Domain, subdomain and hostname structure
- Rule-based risk assessment and transparent scoring
- Input validation and safe error handling
- Defensive security and safe-browsing habits
- Responsible, ethical tool design (no scanning, no exploitation)
