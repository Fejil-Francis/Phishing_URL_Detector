from flask import Flask, render_template, request
from urllib.parse import urlparse
import re
import requests

app = Flask(__name__)

# Keywords suspicious in DOMAIN (not path)
domain_keywords = [
    'login', 'verify', 'bank', 'secure', 'update',
    'password', 'confirm', 'alert', 'suspended', 'wallet',
    'urgent', 'credit', 'account', 'signin', 'auth'
]

# Keywords suspicious anywhere
global_keywords = ['@']


def is_uuid(segment):
    """Check if a segment is a UUID"""
    uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    return bool(re.match(uuid_pattern, segment, re.IGNORECASE))


def is_hex_hash(segment):
    """Check if a segment looks like a hex hash (e.g., commit SHA)"""
    return bool(re.match(r'^[0-9a-f]{6,40}$', segment, re.IGNORECASE))


def check_url_reachable(url):
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return True, response.status_code
    except requests.ConnectionError:
        return False, "Connection refused"
    except requests.Timeout:
        return False, "Timeout (>5s)"
    except requests.exceptions.MissingSchema:
        return False, "Invalid URL format"
    except Exception as e:
        return False, str(e)


def check_url(url):
    signals = []
    info_messages = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query

    reachable, reachable_status = check_url_reachable(url)

    if '@' in url:
        signals.append("CRITICAL: '@' symbol found — everything before @ is a username, NOT the real domain")

    
    domain_parts = re.split(r"[.:\-]+", domain)
    for part in domain_parts:
        if part in domain_keywords:
            signals.append(f"Suspicious keyword '{part}' found in domain name")

    
    hyphen_count = domain.count('-')
    if hyphen_count > 4:
        signals.append(f"Excessive hyphens ({hyphen_count}) in domain — common in auto-generated phishing domains")
    elif hyphen_count > 2:
        info_messages.append(f"Multiple hyphens ({hyphen_count}) in domain")
    elif hyphen_count == 0:
        pass  # Clean domain

    
    subdomain_count = len(domain.split('.')) - 2
    if subdomain_count > 3:
        signals.append(f"Unusually many subdomains ({subdomain_count}) — possible phishing")
    elif subdomain_count > 1:
        info_messages.append(f"Multiple subdomains ({subdomain_count})")

    
    if re.search(r"(\d+\.){3}\d+", domain):
        signals.append("IP address used instead of domain name")

    
    path_segments = [s for s in path.split('/') if s]
    long_segments = 0
    for segment in path_segments:
        if is_uuid(segment):
            info_messages.append(f"UUID detected in path (legitimate): {segment[:8]}...")
            continue
        if is_hex_hash(segment):
            info_messages.append(f"Hex hash detected in path (legitimate): {segment[:8]}...")
            continue
        if segment.isdigit() and len(segment) < 10:
            continue
        if len(segment) > 30:
            long_segments += 1
            if long_segments <= 2:
                signals.append(f"Unusually long path segment ({len(segment)} chars): {segment[:40]}")

    # checking suspicious TLDs ---
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.date', '.men']
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            signals.append(f"Suspicious TLD '{tld}' commonly used in phishing")

   
    tunnel_domains = ['trycloudflare.com', 'ngrok.io', 'ngrok-free.app', 'serveo.net', 'localtunnel.me']
    for tunnel in tunnel_domains:
        if tunnel in domain:
            signals.append(f"Tunnel/proxy domain detected: {tunnel}")
            break

    
    brands = [
        'instagram', 'facebook', 'google', 'apple', 'microsoft',
        'netflix', 'paypal', 'amazon', 'linkedin', 'twitter',
        'whatsapp', 'telegram', 'discord', 'github', 'gmail',
        'outlook', 'yahoo', 'bank', 'chase', 'wellsfargo'
    ]
    domain_without_tld = domain.rsplit('.', 1)[0] if '.' in domain else domain
    for brand in brands:
        if brand in domain_without_tld:
            
            parts = domain.split('.')
            if len(parts) >= 2:
                actual_domain = '.'.join(parts[-2:])
                brand_domain = f"{brand}."
                
                if brand not in actual_domain and brand in domain:
                    signals.append(f"Brand impersonation: '{brand}' appears in subdomain but domain is '{actual_domain}'")
                    break

   
    if parsed.port and parsed.port not in [80, 443]:
        info_messages.append(f"Non-standard port in URL: {parsed.port}")


    if signals:
        critical = [s for s in signals if s.startswith("CRITICAL")]
        if critical:
            result = "🚨 CRITICAL: Phishing URL"
        else:
            result = "🚨 Phishing URL"
    else:
        result = "✅ Safe URL"

    
    reasons = []
    if not reachable:
        reasons.append(f"⚠️ Site unreachable: {reachable_status}")
    else:
        reasons.append(f"✓ Site reachable (HTTP {reachable_status})")

    reasons.extend(signals)
    reasons.extend(info_messages)

    return result, reasons


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    reasons = []
    url = ""

    if request.method == "POST":
        url = request.form["url"]

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        result, reasons = check_url(url)

    return render_template("index.html", result=result, reasons=reasons, url=url)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
