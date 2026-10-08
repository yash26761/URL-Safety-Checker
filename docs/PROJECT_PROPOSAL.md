# Project Proposal

## Project Title
URL Safety Checker — Basic URL Risk Analysis Tool

## Project Overview
A small web application (Python + Streamlit) where a user enters a URL. The program analyses only the text of the URL using five simple rules and displays a risk score, risk level, reasons and safe-browsing recommendations.

## Problem Statement
Phishing links are a common way to trick people into giving away passwords. Many users cannot tell whether a link looks suspicious. Beginners need a simple tool that shows *which characteristics* of a URL are warning signs and *why*, so they learn to spot them.

## Objectives
- Validate the format of an entered URL.
- Run five rule-based checks (HTTPS, IP address, keywords, length, subdomains).
- Calculate a transparent risk score from 0 to 100 and classify it.
- Explain the reasons behind the score.
- Give basic defensive recommendations.
- Test the logic with unit tests.

## Proposed Technology
Python 3.x, Streamlit (interface), standard library only: `re`, `urllib.parse`, `dataclasses`, `unittest`. Runs locally with no database or external services.

## Scope
**Included:** URL text analysis, scoring, explanation, recommendations, unit tests, documentation.

**Not included:** visiting websites, scanning ports, malware analysis, vulnerability scanning, machine learning, databases, paid or AI APIs, real-time threat intelligence.

## Expected Output
A working Streamlit app that shows INPUT → ANALYSIS → SCORE → REASONS → RECOMMENDATIONS, a passing test suite, and complete documentation.
