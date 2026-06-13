from flask import Flask, render_template, request, jsonify
import re
import os
from urllib.parse import urlparse
from difflib import SequenceMatcher

# Import your new modules safely
try:
    from core.ml_classifier import MLClassifier
    ml_engine = MLClassifier()
except ImportError:
    ml_engine = None

app = Flask(__name__)

def detect_phishing_v1(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    full_url = url.lower()
    
    score = 0
    
    # Track the detailed state for the 15-Class Registry map
    heuristics_detail = [
        {
            "name": "URL Length",
            "triggered": len(full_url) > 100,
            "evidence": "URL exceeds a typical safety length threshold (Obfuscation risk)."
        },
        {
            "name": "Raw IP Address",
            "triggered": bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname)),
            "evidence": "Uses an unmapped IP address instead of an authenticated domain registry."
        },
        {
            "name": "Credential Masking",
            "triggered": '@' in full_url,
            "evidence": "Contains a credential spoofing operator token ('@')."
        },
        {
            "name": "Subdomain Density",
            "triggered": len([p for p in hostname.split('.')[:-2] if p]) > 3,
            "evidence": "Deeply nested subdomain structure typical of automated phishing kits."
        },
        {
            "name": "Insecure Protocol",
            "triggered": parsed.scheme != 'https',
            "evidence": "Lacks safe transport layer encryption signatures (HTTP Mode)."
        },
        {
            "name": "Excessive Hyphens",
            "triggered": hostname.count('-') > 4,
            "evidence": "High hyphen counts intended to replicate legacy corporate subnets."
        },
        {
            "name": "Double Slash Obfuscation",
            "triggered": '//' in parsed.path or full_url.count('//') > (2 if parsed.scheme else 1),
            "evidence": "Suspicious internal path routing token ('//') caught inside route parameters."
        }
    ]

    # Calculate base rule score weights
    for h in heuristics_detail:
        if h["triggered"]:
            score += 2.5

    # Brand typosquatting check
    common_brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'youtube']
    parts = hostname.split('.')
    domain_part = parts[-2] if len(parts) > 1 else hostname
    
    brand_triggered = False
    brand_evidence = ""
    for brand in common_brands:
        similarity = SequenceMatcher(None, domain_part.lower(), brand.lower()).ratio()
        if 0.82 < similarity < 1.0 and domain_part.lower() != brand.lower():
            score += 4.0
            brand_triggered = True
            brand_evidence = f"Typosquatting detected: Target mimicking brand '{brand}' closely."
            break

    heuristics_detail.append({
        "name": "Brand Typosquatting",
        "triggered": brand_triggered,
        "evidence": brand_evidence if brand_triggered else "No brand alignments matched."
    })

    # Normalize system outputs
    final_score = min(score * 10, 100)
    
    if final_score >= 60:
        status = "MALICIOUS"
        color = "rose"
        message = "HIGH RISK - SYSTEM WARNING"
    elif final_score >= 30:
        status = "SUSPICIOUS"
        color = "amber"
        message = "Proceed with caution"
    else:
        status = "SAFE"
        color = "emerald"
        message = "Appears legitimate"

    # Gather Model data safely
    ml_output = {"score": 0, "top_features": ["Heuristic Engine Core Only"]}
    if ml_engine and ml_engine.model:
        ml_output = ml_engine.predict(url)

    return {
        "status": status,
        "score": final_score,
        "message": message,
        "color": color,
        "heuristics_detail": heuristics_detail,
        "ml_data": ml_output,
        "redirect_chain": [url]  # Default array tracking direct hop map
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/check', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "Missing standard target structural parameters"}), 400
            
        url = data.get('url', '').strip()
        if not url:
            return jsonify({"error": "Empty URL processing target dropped"}), 400
            
        result = detect_phishing_v1(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Internal Processing Fault: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)