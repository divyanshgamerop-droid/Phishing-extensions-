from urllib.parse import urlparse
import re


def scan_url(url):

    risk_score = 0
    reasons = []

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # -----------------------------
    # 1. HTTPS CHECK
    # -----------------------------

    if parsed.scheme != "https":
        risk_score += 20
        reasons.append("Website is not using HTTPS")

    # -----------------------------
    # 2. URL LENGTH
    # -----------------------------

    if len(url) > 100:
        risk_score += 10
        reasons.append("URL is unusually long")

    # -----------------------------
    # 3. IP ADDRESS CHECK
    # -----------------------------

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):
        risk_score += 30
        reasons.append(
            "URL uses an IP address instead of a domain name"
        )

    # -----------------------------
    # 4. @ SYMBOL
    # -----------------------------

    if "@" in url:
        risk_score += 25
        reasons.append(
            "URL contains @ symbol"
        )

    # -----------------------------
    # 5. TOO MANY SUBDOMAINS
    # -----------------------------

    subdomain_count = hostname.count(".")

    if subdomain_count >= 4:
        risk_score += 15
        reasons.append(
            "URL contains an unusually large number of subdomains"
        )

    # -----------------------------
    # 6. SUSPICIOUS KEYWORDS
    # -----------------------------

    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "account",
        "password",
        "secure",
        "update",
        "bank",
        "payment",
        "signin",
        "confirm"
    ]

    url_lower = url.lower()

    found_keywords = []

    for keyword in suspicious_keywords:

        if keyword in url_lower:
            found_keywords.append(keyword)

    if found_keywords:

        risk_score += min(len(found_keywords) * 5, 20)

        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(found_keywords)
        )

    # -----------------------------
    # 7. URL ENCODING
    # -----------------------------

    if "%" in url:
        risk_score += 10
        reasons.append(
            "URL contains encoded characters"
        )

    # -----------------------------
    # 8. HYPHEN CHECK
    # -----------------------------

    if hostname.count("-") >= 3:
        risk_score += 10
        reasons.append(
            "Domain contains multiple hyphens"
        )

    # -----------------------------
    # FINAL RISK LEVEL
    # -----------------------------

    risk_score = min(risk_score, 100)

    if risk_score >= 60:

        risk_level = "DANGEROUS"

    elif risk_score >= 30:

        risk_level = "SUSPICIOUS"

    else:

        risk_level = "SAFE"

    # No reason found
    if not reasons:

        reasons.append(
            "No basic phishing indicators detected"
        )

    return {
        "url": url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons
    }