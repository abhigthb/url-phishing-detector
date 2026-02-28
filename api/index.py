from flask import Flask, request, jsonify
from flask_cors import CORS
from detector.scanner import PhishingScanner

# Initialize the Flask App
app = Flask(__name__)
# Allow our frontend to communicate with this backend securely
CORS(app) 

# Initialize your scanner
scanner = PhishingScanner()

@app.route('/api/scan', methods=['POST'])
def scan_endpoint():
    data = request.json
    url_to_scan = data.get('url')

    if not url_to_scan:
        return jsonify({"error": "No URL provided"}), 400

    # Pass the URL to your existing scanner logic
    issues = scanner.scan_url(url_to_scan)

    # Return the results as JSON back to the frontend
    if not issues:
        return jsonify({"safe": True, "issues": []})
    else:
        return jsonify({"safe": False, "issues": issues})

# This is required for Vercel to find the app
if __name__ == '__main__':
    app.run()