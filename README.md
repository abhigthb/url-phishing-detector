# 🛡️ URL Phishing Detector (Hybrid Model)

[![GitHub stars](https://img.shields.io/github/stars/YOUR_USERNAME/url-phishing-detector?style=social)](https://github.com/YOUR_USERNAME/url-phishing-detector/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/YOUR_USERNAME/url-phishing-detector?style=social)](https://github.com/YOUR_USERNAME/url-phishing-detector/network/members)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)

A robust, modular Python-based tool for detecting potentially malicious URLs. This hybrid model combines **local heuristic pattern scanning** with real-time threat intelligence from **VirusTotal**, helping to identify both emerging zero-day phishing attempts and established threats.

Built with clean, maintainable code — perfect for cybersecurity enthusiasts, developers, and as a strong portfolio piece demonstrating API integration, modular design, and security thinking.

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)
- [Acknowledgments](#acknowledgments)

## Features

- **Heuristic-Based Analysis**  
  Detects modern phishing techniques:  
  • Brand typosquatting (`g00gle.com`, `faceb00k-support.net`)  
  • Raw IP address masking  
  • Suspicious URL length & structure  
  • URL encoding tricks & subdomain abuse

- **Real-Time Global Threat Intelligence**  
  Cross-references URLs against 70+ security vendors via **VirusTotal v3 API**

- **Modular & Extensible Architecture**  
  Clean separation between CLI interface and detection logic — easy to extend, test, or integrate

- **Smart Brand Protection**  
  Safely ignores official domains (`www.google.com`, `login.microsoftonline.com`)  
  Aggressively flags impersonators (`google-secure-login-update.com`, `micros0ft-login.net`)

- **Interactive Command-Line Interface**  
  Quick scanning without needing any GUI

- **Educational & Well-Documented**  
  Detailed code comments explaining both security concepts and implementation choices

## Project Structure
url-phishing-detector/
    ├── README.md              # This file — project documentation
    ├── main.py                # Entry point + interactive CLI
    └── detector/
        ├── init.py
        └── scanner.py         # Core detection logic (heuristics + VirusTotal)


## Installation

```bash
# 1. Clone the repository
git clone https://github.com/abhigthb/url-phishing-detector.git
cd url-phishing-detector

# 2. Install dependencies
pip install requests

# 3. Add your VirusTotal API key
#    → Go to https://www.virustotal.com/gui/my-apikey
#    → Copy your free/public API key
#    → Open detector/scanner.py
#    → Replace "YOUR_FREE_VIRUSTOTAL_KEY" with your real key

Security Note:
Never commit your real API key to GitHub.
Consider using environment variables + python-dotenv in future versions.

Usage
python main.py

Enter a URL to scan (or type 'quit' to exit):
> https://fakebank-login-secure.com

 Analyzing...
[Heuristics]
 • Suspicious domain length
 • Potential typosquatting / brand impersonation

[VirusTotal]
 • 7/72 engines flagged this URL as malicious

Verdict: HIGH RISK — Do NOT visit this link!

How It Works

Fast local heuristics — zero API calls, instant feedback
URL → VirusTotal hash lookup — privacy-friendly (doesn't send full URL in most cases)
Combines both signals → gives reasoned verdict with explainable red flags
Protects legitimate domains → reduces false positives on real banking / login pages

Contributing
Pull requests are welcome!

Fork the repo
Create your feature branch (git checkout -b feature/amazing-heuristic)
Commit your changes (git commit -m 'Add punycode detection')
Push to the branch (git push origin feature/amazing-heuristic)
Open a Pull Request

License
MIT License
Disclaimer
This tool is created for educational purposes, security awareness demonstrations, and portfolio showcase.
It is not a replacement for commercial security products, enterprise URL filtering gateways, endpoint protection, or professional threat intelligence platforms.
Use responsibly. Results should be treated as indicators — not final verdicts.
Acknowledgments

VirusTotal — for the excellent free API tier
Open-source cybersecurity & OSINT community
Everyone who has ever shared phishing indicators publicly

Happy (and safe) scanning! 🛡️

