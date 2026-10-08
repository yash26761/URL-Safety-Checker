"""
app.py - Streamlit user interface for the URL Safety Checker.

Flow shown to the user:  INPUT -> ANALYSIS -> SCORE -> REASONS -> RECOMMENDATIONS
All analysis logic lives in url_checker.py; this file only displays results.
"""

import streamlit as st

from url_checker import PASS, analyze_url

st.set_page_config(page_title="URL Safety Checker", page_icon="🔗", layout="centered")

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.title("🔗 URL Safety Checker")
st.caption("Basic URL Risk Analysis Tool - Cybersecurity Mini Project")
st.write(
    "Enter a URL and the tool will look at the **text of the URL only** and "
    "show a few basic warning signs, a risk score and some safe-browsing advice."
)
st.info(
    "**Educational tool only.** The score is a simple rule-based estimate. It does "
    "not prove that a website is safe or malicious, and it never visits the website."
)

# ---------------------------------------------------------------------------
# Step 1 - Input
# ---------------------------------------------------------------------------
st.header("1. Enter a URL")
url_input = st.text_input("URL to check", placeholder="https://example.com")
check_clicked = st.button("Check URL", type="primary")

if check_clicked:
    result = analyze_url(url_input)

    if not result.is_valid:
        # Invalid input: show an error and stop (no normal analysis)
        st.error(f"Invalid URL: {result.error_message}")
    else:
        # -------------------------------------------------------------------
        # Step 2 - Individual checks
        # -------------------------------------------------------------------
        st.header("2. Security Analysis")
        for check in result.checks:
            with st.container(border=True):
                left, right = st.columns([3, 1])
                left.markdown(f"**{check.name}**")
                left.caption(check.message)
                if check.status == PASS:
                    right.success("PASS")
                else:
                    right.warning("WARNING")

        # -------------------------------------------------------------------
        # Step 3 - Score and level
        # -------------------------------------------------------------------
        st.header("3. Risk Score")
        score_col, level_col = st.columns(2)
        score_col.metric("Risk Score", f"{result.score} / 100")
        level_col.metric("Risk Level", result.risk_level)
        st.progress(result.score / 100)

        if result.risk_level == "LOW RISK":
            st.success("LOW RISK - few warning signs were found.")
        elif result.risk_level == "MEDIUM RISK":
            st.warning("MEDIUM RISK - some warning signs were found. Be careful.")
        else:
            st.error("HIGH RISK - several warning signs were found. Be very careful.")

        # -------------------------------------------------------------------
        # Step 4 - Reasons
        # -------------------------------------------------------------------
        st.header("4. Why this score?")
        for reason in result.reasons:
            st.markdown(f"- {reason}")

        with st.expander("Show how the score was calculated"):
            rows = [
                {"Check": c.name, "Result": c.status, "Points added": c.points}
                for c in result.checks
            ]
            st.table(rows)
            st.write(f"**Total: {result.score} / 100**")
            st.caption("Bands: 0-30 LOW, 31-60 MEDIUM, 61-100 HIGH.")

        # -------------------------------------------------------------------
        # Step 5 - Recommendations
        # -------------------------------------------------------------------
        st.header("5. Recommendations")
        for tip in result.recommendations:
            st.markdown(f"- {tip}")

st.divider()
st.caption(
    "This tool does not exploit websites, scan ports, run malware or guarantee "
    "that any URL is safe or malicious. For learning purposes only."
)
