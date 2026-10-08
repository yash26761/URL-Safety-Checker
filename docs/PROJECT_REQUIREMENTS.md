# Project Requirements

## Functional Requirements
- FR1: The user can enter a URL and press **Check URL**.
- FR2: The system validates the URL (must be http/https with a proper hostname). Invalid input shows an error and no analysis.
- FR3: The system checks whether the URL uses HTTPS.
- FR4: The system detects an IPv4 address as the hostname.
- FR5: The system detects suspicious keywords (login, verify, account, password, security, update, confirm).
- FR6: The system checks whether the URL is longer than 75 characters.
- FR7: The system checks whether the hostname has more than 2 subdomains.
- FR8: The system calculates a risk score from 0 to 100 and a risk level (LOW / MEDIUM / HIGH).
- FR9: The system lists the reasons for the score.
- FR10: The system shows recommendations based on the detected indicators.
- FR11: The interface states that the tool is educational and not a guarantee.

## Non-Functional Requirements
- Simple, readable, beginner-friendly code
- Clear separation: `url_checker.py` (logic) and `app.py` (UI)
- Fast response (instant, no network access)
- Does not crash on invalid input
- Easy to change thresholds, keywords and weights (constants at the top of `url_checker.py`)
- Works fully offline

## Software Requirements
- Python 3.x (3.9 or newer recommended)
- Streamlit 1.30 or newer (`pip install -r requirements.txt`)
- Any code editor (e.g. VS Code) and a web browser

## Hardware Requirements
- Any ordinary computer able to run Python and a web browser (about 4 GB RAM is plenty)
- No internet needed to run the analysis (internet is only needed once to install Streamlit)

## Limitations
- Only analyses the URL text, never the website itself
- Simple keyword and length rules cause false positives and false negatives
- Basic subdomain counting; IPv4 only
- The score is educational, not a real probability
- Does not exploit websites, scan ports, run malware or access anything without permission
