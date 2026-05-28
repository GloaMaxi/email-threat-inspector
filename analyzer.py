import re
from email import policy
from email.parser import BytesParser

PHISHING_WORDS = [
    "urgent",
    "verify your account",
    "account suspended",
    "immediately",
    "unusual activity",
    "limited access",
    "security alert",
    "confirm your identity",
    "permanent account suspension"
]

RISKY_DOMAINS = [".ru", ".tk", ".xyz", ".top", ".click"]
DANGEROUS_FILES = [".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".zip"]


def get_links(text):
    return re.findall(r"https?://[^\s]+", text)


def read_email(file_path):
    with open(file_path, "rb") as file:
        return BytesParser(policy=policy.default).parse(file)


def get_email_body(message):
    body_text = ""

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                body_text += part.get_content()
    else:
        body_text = message.get_content()

    return body_text


def check_email(file_path):
    message = read_email(file_path)

    sender = message.get("From", "")
    reply_to = message.get("Reply-To", "")
    subject = message.get("Subject", "")
    body = get_email_body(message)

    notes = []
    score = 0
    text_to_check = f"{subject} {body}".lower()

    # Check for common phishing wording
    for word in PHISHING_WORDS:
        if word in text_to_check:
            notes.append(f"Suspicious wording found: {word}")
            score += 10

    links = get_links(body)

    # Check links and risky top-level domains
    for link in links:
        notes.append(f"Link found: {link}")
        score += 10

        for domain in RISKY_DOMAINS:
            if domain in link:
                notes.append(f"Risky domain pattern found in link: {link}")
                score += 20

    # A different Reply-To can be suspicious in phishing emails
    if reply_to and reply_to not in sender:
        notes.append("Reply-To address does not match the sender")
        score += 20

    # Basic attachment indicators from email text
    for file_type in DANGEROUS_FILES:
        if file_type in body.lower():
            notes.append(f"Possible risky attachment mentioned: {file_type}")
            score += 20

    if score >= 70:
        risk = "High"
    elif score >= 40:
        risk = "Medium"
    else:
        risk = "Low"

    indicators = links.copy()

    if reply_to:
        indicators.append(reply_to)

    analyst_note = f"""
This email looks suspicious based on the indicators found during analysis.

Main observations:
- Risk level: {risk}
- Risk score: {score}
- Number of detected links: {len(links)}
- Number of findings: {len(notes)}

Suggested actions:
- Do not click the links.
- Do not open attachments.
- Check the sender and Reply-To address.
- Report or escalate the email if this was received in a real company inbox.
"""

    return {
        "sender": sender,
        "reply_to": reply_to,
        "subject": subject,
        "body": body,
        "links": links,
        "notes": notes,
        "score": score,
        "risk": risk,
        "indicators": indicators,
        "analyst_note": analyst_note
    }