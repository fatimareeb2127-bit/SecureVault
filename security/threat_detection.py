import re
from urllib.parse import urlparse


SPAM_WORDS = {
    "winner",
    "won",
    "prize",
    "free",
    "cash",
    "bonus",
    "discount",
    "claim",
    "reward",
    "lottery",
    "congratulations",
    "selected",
    "gift",
    "profit",
    "loan",
    "click now",
    "limited time",
    "act now",
    "guaranteed"
}


PHISHING_WORDS = {
    "verify your account",
    "verify account",
    "confirm your identity",
    "account suspended",
    "account locked",
    "password expired",
    "security alert",
    "login immediately",
    "click the link",
    "update payment",
    "confirm payment",
    "reset your password",
    "unusual activity",
    "your account will be closed"
}


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "cutt.ly",
    "rb.gy"
}


SUSPICIOUS_TLDS = {
    ".zip",
    ".mov",
    ".click",
    ".top",
    ".xyz",
    ".work",
    ".gq",
    ".tk"
}


def extract_urls(text):

    return re.findall(
        r"(?:https?://|www\.)[^\s<>'\"]+",
        text,
        flags=re.IGNORECASE
    )


def clean_url(url):

    return url.rstrip(
        ".,;:!?)]}"
    )


def analyze_url(url):

    url = clean_url(url)

    original = url

    if url.lower().startswith("www."):

        url = "http://" + url

    parsed = urlparse(url)

    host = (
        parsed.hostname or ""
    ).lower()

    score = 0

    reasons = []

    if parsed.scheme == "http":

        score += 8

        reasons.append(
            "URL uses HTTP instead of HTTPS."
        )

    if host in SHORTENERS:

        score += 25

        reasons.append(
            "URL uses a shortening service."
        )

    if "@" in parsed.netloc:

        score += 30

        reasons.append(
            "URL contains @ in the network location."
        )

    if len(url) > 140:

        score += 12

        reasons.append(
            "URL is unusually long."
        )

    if host.count(".") >= 4:

        score += 12

        reasons.append(
            "URL contains many subdomains."
        )

    if re.search(
        r"\d{1,3}(?:\.\d{1,3}){3}",
        host
    ):

        score += 25

        reasons.append(
            "URL uses an IP address."
        )

    if any(
        host.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    ):

        score += 18

        reasons.append(
            "URL uses an unusual or higher risk TLD."
        )

    if re.search(
        r"(login|verify|secure|account|password|payment|wallet|bank)",
        host
    ):

        score += 10

        reasons.append(
            "Domain contains security or account keywords."
        )

    if "xn--" in host:

        score += 20

        reasons.append(
            "Domain uses punycode."
        )

    score = min(score, 100)

    if score >= 60:
        risk = "HIGH"

    elif score >= 30:
        risk = "MEDIUM"

    else:
        risk = "LOW"

    if not reasons:

        reasons.append(
            "No obvious URL risk indicators detected."
        )

    return {
        "url": original,
        "host": host,
        "score": score,
        "risk": risk,
        "reasons": reasons
    }


def analyze_message(
    message,
    subject="",
    sender=""
):

    combined = (
        sender +
        "\n" +
        subject +
        "\n" +
        message
    ).lower()

    spam_score = 0
    phishing_score = 0

    spam_reasons = []
    phishing_reasons = []

    for word in SPAM_WORDS:

        if word in combined:

            spam_score += 5

            spam_reasons.append(
                f"Spam phrase detected: {word}"
            )

    for word in PHISHING_WORDS:

        if word in combined:

            phishing_score += 12

            phishing_reasons.append(
                f"Phishing phrase detected: {word}"
            )

    urls = extract_urls(combined)

    url_reports = []

    for url in urls:

        report = analyze_url(url)

        url_reports.append(report)

        spam_score += report["score"] // 8

        phishing_score += report["score"] // 6

        if report["score"] >= 30:

            phishing_reasons.append(
                f"Suspicious URL: {report['host']}"
            )

    if re.search(
        r"\b(password|otp|one[- ]time code|cvv|credit card|bank details)\b",
        combined
    ):

        phishing_score += 20

        phishing_reasons.append(
            "Message requests sensitive credentials or financial information."
        )

    if re.search(
        r"\b(urgent|immediately|act now|within \d+ minutes)\b",
        combined
    ):

        phishing_score += 10

        phishing_reasons.append(
            "Message uses pressure or urgency."
        )

    if combined.count("!") >= 4:

        spam_score += 8

        spam_reasons.append(
            "Excessive exclamation marks."
        )

    spam_score = min(100, spam_score)

    phishing_score = min(100, phishing_score)

    if phishing_score >= 60:

        classification = "PHISHING RISK"
        risk = "HIGH"

    elif spam_score >= 55:

        classification = "SPAM"

        risk = (
            "HIGH"
            if spam_score >= 75
            else "MEDIUM"
        )

    elif (
        phishing_score >= 30
        or spam_score >= 30
    ):

        classification = "SUSPICIOUS"
        risk = "MEDIUM"

    else:

        classification = "LIKELY SAFE"
        risk = "LOW"

    return {
        "classification": classification,
        "risk": risk,
        "spam_score": spam_score,
        "phishing_score": phishing_score,
        "spam_reasons": (
            spam_reasons
            or ["No strong spam indicators detected."]
        ),
        "phishing_reasons": (
            phishing_reasons
            or ["No strong phishing indicators detected."]
        ),
        "urls": url_reports
    }