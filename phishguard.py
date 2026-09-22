"""
PHISHGUARD
Rule-Based Phishing URL Analyzer
-----------------------------------------------------------------------
A simple, terminal-based Python program built for the Cyber Security
Fundamentals (CSF) college project.

WHAT THIS PROGRAM DOES:
The user enters a URL. The program checks it against a small set of
well-known, easy-to-explain phishing warning signs (no HTTPS, IP address
used instead of a domain, suspicious keywords, the '@' symbol, punycode
domains, excessive subdomains, suspicious characters, and unusual URL
length). Each warning sign adds points to a simple risk score, and the
final score is classified as LOW / MEDIUM / HIGH RISK.

IMPORTANT (for viva and documentation):
This is an educational, RULE-BASED analyzer. It does NOT use AI/ML and
it does NOT guarantee detection of every phishing website. It simply
demonstrates how basic, transparent rules can flag common warning signs.

HOW TO RUN:
    python phishguard.py
"""

import re
import urllib.parse
import ipaddress


# -----------------------------------------------------------------------
# Keywords attackers commonly use in phishing URLs to look trustworthy
# -----------------------------------------------------------------------
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "password",
    "update", "security", "banking", "confirm",
]

# -----------------------------------------------------------------------
# Points added to the risk score when a check is triggered.
# This is our own simple educational scoring system, not an industry
# standard -- the point values are chosen only to keep the demo clear.
# -----------------------------------------------------------------------
POINTS_NOT_HTTPS = 20
POINTS_IP_ADDRESS = 25
POINTS_LONG_URL = 10
POINTS_PER_KEYWORD = 5
POINTS_KEYWORD_CAP = 20
POINTS_EXCESSIVE_SUBDOMAINS = 15
POINTS_SUSPICIOUS_CHARS = 10
POINTS_AT_SYMBOL = 20
POINTS_PUNYCODE = 20

LONG_URL_THRESHOLD = 75      # characters
SUBDOMAIN_THRESHOLD = 3      # number of subdomains counted before flagging
HYPHEN_THRESHOLD = 3         # hyphens in the hostname before flagging


# =========================================================================
# STEP 1: GET AND CLEAN UP USER INPUT
# =========================================================================
def get_url_input():
    """
    Keeps asking the user for a URL until something is typed.
    Typing 'exit' or 'quit' closes the program.
    """
    while True:
        try:
            url = input("\nEnter URL (or type 'exit' to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\nExiting PhishGuard. Goodbye!")
            raise SystemExit

        if url.lower() in ("exit", "quit"):
            print("\nExiting PhishGuard. Goodbye!")
            raise SystemExit

        if url == "":
            print("Error: URL cannot be empty. Please try again.")
            continue

        return url


def normalize_url(url):
    """
    If the user typed a URL without http:// or https:// in front of it,
    add http:// so that urllib.parse can correctly split it into parts.
    Example: 'www.example.com'  ->  'http://www.example.com'
    """
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        url = "http://" + url
    return url


def parse_url_safe(url):
    """
    Safely parses the URL using urllib.parse.
    Returns the parsed object, or None if the URL is too broken to
    analyze (for example, it has no hostname at all).
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return None

    if not parsed.hostname:
        return None

    return parsed


# =========================================================================
# STEP 2: INDIVIDUAL SECURITY CHECKS
# =========================================================================
def check_https(parsed):
    """Returns True if the URL uses the HTTPS scheme."""
    return parsed.scheme.lower() == "https"


def check_ip_address(hostname):
    """Returns True if the hostname is a raw IP address instead of a
    normal domain name (e.g. 192.168.1.1 instead of example.com)."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def check_suspicious_keywords(url):
    """Returns the list of suspicious keywords found in the URL."""
    url_lower = url.lower()
    return [word for word in SUSPICIOUS_KEYWORDS if word in url_lower]


def check_at_symbol(url):
    """Returns True if '@' appears in the URL. Browsers ignore everything
    before '@' in the address, so attackers use it to hide the real
    destination, e.g. http://real-bank.com@fake-site.com"""
    return "@" in url


def check_punycode(hostname):
    """Returns True if the hostname is a punycode domain (xn--...),
    which can be used to imitate real brand names using look-alike
    characters."""
    return "xn--" in hostname.lower()


def check_excessive_subdomains(hostname, is_ip):
    """Returns how many subdomains are in front of the main domain.
    Example: 'secure.login.example.com' -> 2 subdomains
    (secure, login) in front of 'example.com'."""
    if is_ip:
        return 0
    parts = hostname.split(".")
    return max(0, len(parts) - 2)


def check_suspicious_characters(hostname):
    """Counts hyphens in the hostname. Phishing domains often chain many
    words together with hyphens to look convincing, e.g.
    'paypal-account-verify-secure.com'."""
    return hostname.count("-")


# =========================================================================
# STEP 3: RISK SCORING
# =========================================================================
def calculate_risk(url, parsed):
    """
    Runs every check, builds the risk score and the list of reasons,
    and classifies the final score as LOW / MEDIUM / HIGH RISK.
    """
    hostname = parsed.hostname
    is_https = check_https(parsed)
    is_ip = check_ip_address(hostname)
    url_length = len(url)
    keywords_found = check_suspicious_keywords(url)
    has_at_symbol = check_at_symbol(url)
    is_punycode = check_punycode(hostname)
    subdomain_count = check_excessive_subdomains(hostname, is_ip)
    hyphen_count = check_suspicious_characters(hostname)

    score = 0
    reasons = []

    if not is_https:
        score += POINTS_NOT_HTTPS
        reasons.append("HTTPS is not used")

    if is_ip:
        score += POINTS_IP_ADDRESS
        reasons.append("An IP address is used instead of a domain name")

    if url_length > LONG_URL_THRESHOLD:
        score += POINTS_LONG_URL
        reasons.append(f"URL is unusually long ({url_length} characters)")

    if keywords_found:
        keyword_score = min(
            len(keywords_found) * POINTS_PER_KEYWORD, POINTS_KEYWORD_CAP
        )
        score += keyword_score
        reasons.append(
            "Suspicious keyword(s) found: " + ", ".join(keywords_found)
        )

    if subdomain_count >= SUBDOMAIN_THRESHOLD:
        score += POINTS_EXCESSIVE_SUBDOMAINS
        reasons.append(f"Excessive subdomains detected ({subdomain_count})")

    if hyphen_count >= HYPHEN_THRESHOLD:
        score += POINTS_SUSPICIOUS_CHARS
        reasons.append(
            f"Suspicious characters detected ({hyphen_count} hyphens in domain)"
        )

    if has_at_symbol:
        score += POINTS_AT_SYMBOL
        reasons.append("'@' symbol found (can hide the real destination)")

    if is_punycode:
        score += POINTS_PUNYCODE
        reasons.append("Punycode domain detected (can imitate real brands)")

    score = min(score, 100)

    if score <= 25:
        risk_level = "LOW RISK"
    elif score <= 50:
        risk_level = "MEDIUM RISK"
    else:
        risk_level = "HIGH RISK"

    checks = {
        "https": is_https,
        "ip": is_ip,
        "length": url_length,
        "keywords": keywords_found,
        "at_symbol": has_at_symbol,
        "punycode": is_punycode,
        "subdomains": subdomain_count,
    }

    return checks, score, risk_level, reasons


def get_recommendation(risk_level):
    """Returns a plain-language safety recommendation for the risk level."""
    if risk_level == "LOW RISK":
        return "No major warning signs were found. Still stay alert online."
    if risk_level == "MEDIUM RISK":
        return "Be cautious. Verify the website independently before trusting it."
    return (
        "Avoid entering passwords or sensitive information until the "
        "website can be independently verified."
    )


# =========================================================================
# STEP 4: DISPLAY RESULTS
# =========================================================================
def display_results(url, checks, score, risk_level, reasons):
    label_width = 22

    print("\n" + "-" * 50)
    print("SECURITY ANALYSIS".center(50))
    print("-" * 50)
    print(f"{'URL Analyzed':<{label_width}}: {url}")
    print(f"{'HTTPS Used':<{label_width}}: {'YES' if checks['https'] else 'NO'}")
    print(f"{'IP Address Used':<{label_width}}: {'YES' if checks['ip'] else 'NO'}")
    print(f"{'URL Length':<{label_width}}: {checks['length']}")
    print(f"{'Suspicious Keywords':<{label_width}}: {'YES' if checks['keywords'] else 'NO'}")
    print(f"{chr(39)}@{chr(39)} Symbol Present".ljust(label_width) + f": {'YES' if checks['at_symbol'] else 'NO'}")
    print(f"{'Punycode Domain':<{label_width}}: {'YES' if checks['punycode'] else 'NO'}")
    excessive = checks["subdomains"] >= SUBDOMAIN_THRESHOLD
    print(f"{'Excessive Subdomains':<{label_width}}: {'YES' if excessive else 'NO'}")

    print("\n" + "-" * 50)
    print("RISK ASSESSMENT".center(50))
    print("-" * 50)
    print(f"{'Risk Score':<{label_width}}: {score} / 100")
    print(f"{'Risk Level':<{label_width}}: {risk_level}")

    print("\nReasons:")
    if reasons:
        for reason in reasons:
            print(f"  - {reason}")
    else:
        print("  - No suspicious indicators detected")

    print("\nRecommendation:")
    print(f"  {get_recommendation(risk_level)}")
    print("-" * 50)


# =========================================================================
# MAIN PROGRAM
# =========================================================================
def main():
    print("=" * 50)
    print("PHISHGUARD".center(50))
    print("Rule-Based Phishing URL Analyzer".center(50))
    print("=" * 50)
    print("\nNote: This is an educational tool. It does not guarantee")
    print("detection of every phishing website.")

    while True:
        raw_url = get_url_input()
        url = normalize_url(raw_url)
        parsed = parse_url_safe(url)

        if parsed is None:
            print("Error: This does not look like a valid URL. Please try again.")
            continue

        print("\nAnalyzing...")
        checks, score, risk_level, reasons = calculate_risk(url, parsed)
        display_results(url, checks, score, risk_level, reasons)


if __name__ == "__main__":
    main()