
from flask import Flask, render_template, request, jsonify
import re
from urllib.parse import urlparse
from difflib import SequenceMatcher

app = Flask(__name__)

def detect_phishing(url):
    # Ensure URL has scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    full_url = url.lower()
    score = 0
    reasons = []

    # 1. URL Length
    if len(full_url) > 100:
        score += 2
        reasons.append("🚩 Unusually long URL (phishing sites often use long obfuscated links)")

    # 2. IP Address instead of Domain
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        score += 3
        reasons.append("🚩 Uses raw IP address (legitimate sites rarely do this)")

    # 3. @ Symbol (credential phishing trick)
    if '@' in full_url:
        score += 3
        reasons.append("🚩 Contains '@' symbol (classic phishing obfuscation)")

    # 4. Excessive Subdomains
    parts = hostname.split('.')
    subdomains = len([p for p in parts[:-2] if p])  # exclude main domain + TLD
    if subdomains > 3:
        score += 2
        reasons.append(f"🚩 Excessive subdomains ({subdomains}) - typical of phishing kits")

    # 5. Suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.site', '.online', '.icu']
    if any(hostname.lower().endswith(tld) for tld in suspicious_tlds):
        score += 2
        reasons.append("🚩 Suspicious top-level domain (free/cheap TLDs popular with attackers)")

    # 6. HTTP instead of HTTPS
    if parsed.scheme != 'https':
        score += 1
        reasons.append("🚩 Not using secure HTTPS protocol")

    # 7. Typosquatting / Brand Impersonation
    common_brands = [
        'google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'ebay', 'netflix',
        'youtube', 'instagram', 'whatsapp', 'twitter', 'linkedin', 'bankofamerica',
        'wellsfargo', 'chase', 'citibank', 'hsbc', 'mastercard', 'visa'
    ]
    domain_part = parts[-2] if len(parts) > 1 else hostname  # second-level domain
    for brand in common_brands:
        similarity = SequenceMatcher(None, domain_part.lower(), brand.lower()).ratio()
        if 0.82 < similarity < 1.0 and domain_part.lower() != brand.lower():
            score += 3
            reasons.append(f"🚩 Typosquatting detected: '{domain_part}' is very similar to '{brand}' ({similarity:.2f})")
            break

    # 8. Suspicious Keywords
    suspicious_keywords = [
        'login', 'signin', 'account', 'verify', 'secure', 'bank', 'paypal', 'update',
        'password', 'admin', 'support', 'billing', 'confirm', 'recovery'
    ]
    if any(kw in full_url for kw in suspicious_keywords):
        score += 1
        reasons.append("🚩 Contains high-risk keywords commonly used in phishing")

    # 9. Multiple hyphens or suspicious patterns
    if hostname.count('-') > 4:
        score += 1
        reasons.append("🚩 Excessive hyphens in domain (typosquatting technique)")

    # 10. Double slash in path
    if '//' in parsed.path or full_url.count('//') > (2 if parsed.scheme else 1):
        score += 2
        reasons.append("🚩 Suspicious double slash '//' (redirect obfuscation)")

    # Final classification
    if score >= 6:
        status = "MALICIOUS"
        color = "rose"
        message = "HIGH RISK - DO NOT VISIT"
    elif score >= 3:
        status = "SUSPICIOUS"
        color = "amber"
        message = "Proceed with extreme caution"
    else:
        status = "SAFE"
        color = "emerald"
        message = "Appears legitimate"

    return {
        "status": status,
        "score": min(score * 10, 100),  # normalize to 0-100
        "reasons": reasons if reasons else ["✅ No red flags detected"],
        "color": color,
        "message": message,
        "raw_score": score
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/check', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    result = detect_phishing(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)