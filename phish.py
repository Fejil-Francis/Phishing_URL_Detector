from flask import Flask, render_template, request
from urllib.parse import urlparse
import re

app = Flask(__name__)

keywords = [
    'account', 'login', 'verify', 'bank', 'secure', 'update',
    'password', 'confirm', 'alert', 'suspended', 'wallet',
    'urgent', 'credit','@'
]


def check_url(url):
    reasons = []

    # Split URL into words
    parts = re.split(r"[/:.?=&_-]+", url.lower())

    for part in parts:

        if part in keywords:
            reasons.append(f"Suspicious keyword: {part}")

        if any(ch.isdigit() for ch in part):
            reasons.append(f"Digits found: {part}")

        if len(part) > 20:
            reasons.append(f"Long token: {part}")

    # Whole URL checks
    if len(url) > 72:
        reasons.append("Long URL")

    if url.count("-") > 2:
        reasons.append("Too many hyphens")

    if url.count(".") > 3:
        reasons.append("Too many subdomains")

    if re.search(r"(\d+\.){3}\d+", url):
        reasons.append("IP address used")

    path = urlparse(url).path
    last = path.split("/")[-1]

    if "." in last:
        reasons.append("File in URL")

    if reasons:
        result = "🚨 Phishing URL"
    else:
        result = "✅ Safe URL"

    return result, reasons


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    reasons = []

    if request.method == "POST":
        url = request.form["url"]

        result, reasons = check_url(url)

    return render_template(
        "index.html",
        result=result,
        reasons=reasons
    )


if __name__ == "__main__":
    app.run(debug=True)
