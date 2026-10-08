# System Design

## System Flow
```
User enters URL  ->  app.py calls analyze_url()  ->  validate_url()
        invalid -> error message shown, stop
        valid   -> 5 checks -> add points -> risk score -> risk level
                -> reasons + recommendations -> displayed in app.py
```
INPUT → ANALYSIS → SCORE → REASONS → RECOMMENDATIONS

## Components
| Component | File | Job |
|---|---|---|
| User interface | `app.py` | Input box, button, shows results (no analysis logic) |
| Analysis logic | `url_checker.py` | Validation, five checks, scoring, classification, recommendations |
| Tests | `tests/test_url_checker.py` | Unit tests for the logic |

Main functions in `url_checker.py`: `validate_url`, `check_https`, `check_ip_address`, `check_keywords`, `check_url_length`, `check_subdomains`, `classify_risk`, `build_recommendations`, `analyze_url`. Results are returned in the `AnalysisResult` and `CheckResult` dataclasses.

## URL Analysis Checks
1. **HTTPS** — scheme is `https` → PASS, otherwise WARNING.
2. **IP Address** — hostname is a valid IPv4 address → WARNING.
3. **Suspicious Keywords** — any of 7 keywords found in the URL (case-insensitive) → WARNING.
4. **URL Length** — more than `LONG_URL_THRESHOLD` (75) characters → WARNING.
5. **Subdomain Complexity** — more than `MAX_NORMAL_SUBDOMAINS` (2) subdomains → WARNING. Subdomains = labels before the last two (`login.account.security.example.com` → 3).

Each result is only an *indicator*, never proof.

## Risk Scoring
Score = sum of points of all WARNING checks, kept between 0 and 100.

| Indicator | Points |
|---|---|
| No HTTPS | 20 |
| IP address hostname | 30 |
| Suspicious keywords | 10 each, max 20 |
| Long URL | 15 |
| Many subdomains | 15 |

Weights total 100; the highest practical score is 85 (an IP hostname has no subdomains).

## Risk Classification
- 0–30 → LOW RISK
- 31–60 → MEDIUM RISK
- 61–100 → HIGH RISK

## Important Limitations
- Only the URL text is examined; the website is never visited.
- The score is an educational estimate, not a probability of malware.
- Keyword and length rules can be wrong in both directions.
- No port scanning, exploitation, malware execution or unauthorized testing is included.
