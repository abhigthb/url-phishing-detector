# 🛡️ PHISHGUARD – URL Phishing Detector

Advanced **heuristic-based phishing URL scanner** with a cyberpunk / terminal-style interface.  
Detects suspicious patterns, typosquatting, malicious TLDs, credential phishing tricks, and more — **no external APIs required**.

Live demo-friendly deployment on **Vercel** (Flask + Python).

https://github.com/abhigthb/url-phishing-detector

## ✨ Features

- 10+ heuristic detection rules  
- Typosquatting detection (string similarity to popular brands)  
- Suspicious TLDs, IP-based domains, @ symbol tricks, subdomain abuse  
- HTTP vs HTTPS check, keyword analysis, double-slash obfuscation  
- Stunning cyber-security themed UI with Matrix rain, neon glow, glitch effects  
- Real-time results with threat score & detailed explanation  
- Fully responsive + mobile friendly  
- Zero external dependencies beyond Flask  
- One-click Vercel deployment


## 🛠️ Tech Stack

- **Backend**: Python 3 + Flask  
- **Frontend**: HTML + Tailwind CSS (via CDN) + Vanilla JavaScript  
- **Deployment**: Vercel (Python serverless functions)  
- **Styling**: Matrix rain canvas, neon text-shadow, glitch animation

## 🚀 Quick Start – Vercel (Recommended)

1. Fork or clone this repository
2. Push to your GitHub account
3. Go to https://vercel.com → **New Project** → Import Git Repository
4. Select your repository
5. **No configuration needed** — Vercel auto-detects Flask apps
6. Click **Deploy**

Your phishing detector will be live at:  
`https://url-phishing-detector-ab.vercel.app/`

## 🔧 Local Installation

### Prerequisites

- Python 3.8+
- pip
- git (optional)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/abhigthb/url-phishing-detector.git
cd url-phishing-detector

# 2. Create & activate virtual environment (recommended)
python -m venv venv
source venv/bin/activate    # Linux / macOS
venv\Scripts\activate       # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py

```
## 🎯 Usage

- Enter any URL (with or without http/https)
- Click SCAN
- View instant result:
- MALICIOUS (red) → high confidence phishing attempt
- SUSPICIOUS (amber) → proceed with caution
- SAFE (green) → no major red flags found


Note: This is a heuristic tool — always verify suspicious links manually. False positives and negatives are possible.

## ⚙️ Heuristics Currently Implemented

- Very long URLs
- Raw IP address instead of domain
- @ symbol in URL
- Excessive subdomains
- Free/suspicious TLDs (.tk, .ml, .ga, .cf, .xyz, ...)
- HTTP instead of HTTPS
- Typosquatting (similarity to google, paypal, amazon, etc.)
- High-risk keywords (login, verify, account, billing, ...)
- Excessive hyphens in domain
- Suspicious double-slash patterns

## 🤝 Contributing
Contributions are welcome!

### How to contribute

- Fork the repository
- Create a feature branch (git checkout -b feature/amazing-feature)
- Commit your changes (git commit -m 'Add some amazing feature')
- Push to the branch (git push origin feature/amazing-feature)
- Open a Pull Request

### Ideas for contributions

- Add more brand names for typosquatting detection
- Improve UI/UX (more animations, dark mode toggle, sound effects, ...)
- Add export report feature (PDF/JSON)
- Implement domain age / WHOIS lookup warning (if API becomes available)
- Add URL decoding / redirect following simulation
- Write tests (pytest)

## 📄 License

This project is licensed under the MIT License — see the LICENSE file for details.

```bash
MIT License

Copyright (c) 2026 Abhinav

Permission is hereby granted, free of charge, to any person obtaining a copy...
```

## ⚠️ Disclaimer
- This tool is provided for educational and demonstration purposes only.
- It should not be used as the sole method to determine whether a link is safe.
- Always use official security software, browser protections, and your own judgment.


### Built with ❤️ for cyber security enthusiasts
