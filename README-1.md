# 🛡️ Network Vulnerability Scanner

A professional web-based network vulnerability scanner built with Python, Flask, and Nmap.

## Features
- 🔍 Open Port Detection
- ⚙️ Service & Version Detection
- 🖥️ OS Fingerprinting
- ⚠️ CVE Vulnerability Lookup (via NIST NVD API)
- ⚡ Quick Scan & Deep Scan modes

## Tech Stack
- Python + Flask
- python-nmap (Nmap wrapper)
- NIST NVD API (CVE database)
- Vanilla JS + CSS

## Run Locally

```bash
pip install -r requirements.txt
python app.py
```

Visit: http://localhost:5000

## Deploy on Render

1. Push to GitHub
2. Create new Web Service on Render
3. Set Build Command: `pip install -r requirements.txt`
4. Set Start Command: `gunicorn app:app`

> ⚠️ **Note:** Nmap must be installed on the server. On Render, add a build command:
> `apt-get install -y nmap && pip install -r requirements.txt`

## Usage

Enter any IP address or hostname (e.g. `scanme.nmap.org`) and click Scan.

> ⚠️ Only scan systems you own or have explicit permission to scan.

## Author
**B Pavan** — Cybersecurity Enthusiast | CEH v13 (In Progress)
