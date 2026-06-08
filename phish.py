from flask import Flask, render_template, request
import requests
from urllib.parse import urlparse
import re

app = Flask(__name__)

keywords = [
    'account','login','verify','bank','secure','update','password',
    'confirm','alert','suspended','wallet','urgent','credit'
]

def check_url(url):
    score = 0
    reasons = []

    # length check
    if len(url) > 72:
        score += 1
        reasons.append("Long URL")

    # digits check
    if any(ch.isdigit() for ch in url):
        score += 1
        reasons.append("Digits in URL")

    # keyword check
    for word in keywords:
        if word in url.lower():
            score += 1
            reasons.append(f"Keyword found: {word}")
            break

    # subdomain check
    if url.count(".") > 3:
        score += 1
        reasons.append("Too many subdomains")

    # IP address check
    if re.search(r"(\d+\.){3}\d+", url):
        score += 1
        reasons.append("IP address used")

    # file check
    path = urlparse(url).path
    if "." in path.split("/")[-1]:
        score += 1
        reasons.append("File in URL")

    if score >= 3:
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

        try:
            r = requests.get(url, timeout=5)
        except:
            result = "❌ Website not reachable"
            return render_template("index.html", result=result)

        result, reasons = check_url(url)

    return render_template("index.html", result=result, reasons=reasons)


if __name__ == "__main__":
    app.run(debug=True)