# PhishGuard — Rule-Based Phishing URL Analyzer

A simple, terminal-based Python program that analyzes a URL and flags common
phishing warning signs using a transparent, rule-based scoring system.

Built as an individual project for the **Cyber Security Fundamentals (CSF)**
course.

---

## Disclaimer

PhishGuard is an **educational, rule-based analyzer**. It does **not** use
AI/ML and it does **not** guarantee detection of every phishing website. It
demonstrates how a small set of well-known, human-defined rules can flag
common technical warning signs in a URL.

---

## Features

- Fully terminal-based — no GUI, web server, or database
- Checks a URL against 8 simple, explainable phishing indicators:
  1. HTTPS usage
  2. IP address used instead of a domain name
  3. Suspicious keywords (`login`, `verify`, `account`, `password`,
     `update`, `security`, `banking`, `confirm`)
  4. `@` symbol in the URL
  5. Punycode domains (`xn--`)
  6. Excessive subdomains
  7. Suspicious characters (excessive hyphens)
  8. Unusually long URLs
- Produces a transparent point-based **risk score** (0–100)
- Classifies the result as **LOW RISK / MEDIUM RISK / HIGH RISK**
- Handles empty, malformed, and scheme-less input without crashing
- Uses only Python's standard library — no installation required

---

## Requirements

- Python 3.x
- No third-party packages. Only standard-library modules are used:
  - `re`
  - `urllib.parse`
  - `ipaddress`

---

## Project Structure

```
PhishGuard/
└── phishguard.py
```

---

## How to Run

```bash
python phishguard.py
```

If `python` doesn't work on your system, try:

```bash
py phishguard.py
```

Then type a URL when prompted, or type `exit` to quit:

```
Enter URL (or type 'exit' to quit): http://example-login-security.com/verify
```

---

## Example Output

```
==================================================
                    PHISHGUARD
         Rule-Based Phishing URL Analyzer
==================================================

Note: This is an educational tool. It does not guarantee
detection of every phishing website.

Enter URL (or type 'exit' to quit): http://example-login-security.com/verify

Analyzing...

--------------------------------------------------
                SECURITY ANALYSIS
--------------------------------------------------
URL Analyzed          : http://example-login-security.com/verify
HTTPS Used             : NO
IP Address Used        : NO
URL Length             : 40
Suspicious Keywords    : YES
'@' Symbol Present     : NO
Punycode Domain        : NO
Excessive Subdomains   : NO

--------------------------------------------------
                 RISK ASSESSMENT
--------------------------------------------------
Risk Score              : 35 / 100
Risk Level              : MEDIUM RISK

Reasons:
  - HTTPS is not used
  - Suspicious keyword(s) found: login, verify, security

Recommendation:
  Be cautious. Verify the website independently before trusting it.
--------------------------------------------------
```

---

## How the Risk Score Works

Each detected warning sign adds points to a running score. This is a simple
educational scoring system defined for this project — it is **not** an
industry-standard formula.

| Warning Sign | Points |
|---|---|
| HTTPS not used | 20 |
| IP address used instead of domain | 25 |
| URL unusually long (> 75 characters) | 10 |
| Suspicious keyword found (5 pts each, capped) | up to 20 |
| Excessive subdomains (3 or more) | 15 |
| Suspicious characters (3+ hyphens in domain) | 10 |
| `@` symbol present | 20 |
| Punycode domain (`xn--`) | 20 |

**Risk levels:**

| Score Range | Risk Level |
|---|---|
| 0 – 25 | LOW RISK |
| 26 – 50 | MEDIUM RISK |
| 51 – 100 | HIGH RISK |

---

## Limitations

- Cannot detect phishing sites that avoid every listed pattern (e.g., a
  clean HTTPS domain with a convincing but non-suspicious name)
- Can flag legitimate sites that happen to trigger one or more rules
  (false positives)
- Does not visit, render, or verify the actual website content — it only
  analyzes the URL text
- Not a replacement for real-world phishing detection tools or browser
  security features

---

## Project Info

- **Type:** Individual academic project
- **Subject:** Cyber Security Fundamentals
- **Category:** Rule-based security tool (no AI/ML)