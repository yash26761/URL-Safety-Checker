URL Safety Checker — Basic URL Risk Analysis Tool

A beginner-friendly cybersecurity mini project built with Python and Streamlit.
The user enters a URL and the tool runs five simple, rule-based checks on the text of the URL,
then shows a risk score, a risk level, the reasons, and safe-browsing recommendations.

> Educational tool only. The score is not a probability of malware. It does not guarantee
that a website is safe, and it does not guarantee that a website is malicious.

Live Demo

Streamlit App: https://url-safety-checker.streamlit.app/

Objectives

- Understand common warning signs found in phishing-style URLs.
- Apply simple rule-based analysis using Python.
- Explain a security decision with clear reasons instead of just "safe / dangerous".
- Practise safe-browsing habits.

Features

- URL input box and Check URL button (Streamlit)
- URL validation (invalid input shows an error and never crashes the app)
- 5 checks: HTTPS, IP address in hostname, suspicious keywords, URL length, subdomain complexity
- Risk score (0–100) and risk level (LOW / MEDIUM / HIGH)
- Reasons for the score and a "how the score was calculated" table
- Defensive safe-browsing recommendations
- 19 unit tests that never open any website

Screenshots

High Risk URL Analysis

The following screenshots show the analysis of the example URL:

http://192.168.1.10/login/verify-account

![URL Input](screenshots/url-input.png)

![High Risk Result](screenshots/high-risk-result.png)

![Detected Reasons](screenshots/detected-reasons.png)

![Score Calculation](screenshots/score-calculation.png)

![Safe Browsing Recommendations](screenshots/recommendations.png)

Technology Used

Python 3.x, Streamlit, and the standard library (re, urllib.parse, dataclasses, unittest).

Project Structure

URL-Safety-Checker/
├── app.py                 # Streamlit user interface
├── url_checker.py         # All analysis and scoring logic
├── requirements.txt       # streamlit>=1.30
├── README.md
├── screenshots/
│   ├── 01-url-input.png
│   ├── 02-high-risk-result.png
│   ├── 03-detected-reasons.png
│   ├── 04-score-calculation.png
│   └── 05-recommendations.png
├── docs/
│   ├── PROJECT_PROPOSAL.md
│   ├── PROJECT_REQUIREMENTS.md
│   ├── SYSTEM_DESIGN.md
│   ├── TEST_CASES.md
│   └── DEMONSTRATION
└── tests/
└── test_url_checker.py

Installation

python -m venv .venv

Activate the virtual environment:

- Windows: .venv\Scripts\activate
- macOS / Linux: source .venv/bin/activate

Install the requirement:

pip install -r requirements.txt

How to Run

streamlit run app.py

Your browser opens the app (usually at http://localhost:8501).

How the Risk Score Works

Each warning adds points. The total is limited to 0–100. All values are constants at the top of url_checker.py and are easy to change.

Check	Condition for WARNING	Points

HTTPS	URL does not use https	20
IP Address	Hostname is an IPv4 address	30
Suspicious Keywords	Contains login, verify, account, password, security, update, confirm	10 per keyword, max 20
URL Length	More than 75 characters (LONG_URL_THRESHOLD)	15
Subdomain Complexity	More than 2 subdomains (MAX_NORMAL_SUBDOMAINS)	15

Score	Risk level

0–30	LOW RISK
31–60	MEDIUM RISK
61–100	HIGH RISK

The weights add up to 100, but the highest score you can actually reach is 85, because an IP-address hostname has no subdomains.

Example Demonstration

URL	Score	Level

https://example.com	0	LOW RISK
http://example.com	20	LOW RISK
https://login.account.security.example.com	35	MEDIUM RISK
http://192.168.1.10/login	60	MEDIUM RISK
http://192.168.1.10/login/verify-account	70	HIGH RISK

See docs/DEMONSTRATION_AND_VIVA.md for the full demonstration sequence.

Testing

python -m unittest discover -s tests -v

(pytest also works if you have it installed.) The tests check the logic only and never visit a website.

Limitations

- Looks only at the text of the URL. It does not check page content, certificates, domain age or blacklists.
- Keyword matching is simple: a safe URL containing "login" gets points, and a malicious URL with none gets none.
- Subdomains are counted naively (multi-part endings such as .co.uk are not handled).
- Only IPv4 is detected (not IPv6 or number-encoded IPs).
- Only http:// and https:// URLs are accepted; hostnames like localhost are rejected as invalid.
- The score is educational, not a real-world probability.

This project does not exploit websites, scan ports, execute malware, attempt unauthorized access, or visit the URLs it analyses.

Future Improvements

- Detect IPv6 addresses and handle multi-part domain endings
- Add more checks (e.g. @ symbol, many hyphens, look-alike characters)
- Let the user edit the keyword list in the interface
- Save a history of checked URLs
