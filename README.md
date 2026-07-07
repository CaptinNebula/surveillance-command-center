# Surveillance Command Center

A Flask-based network intelligence and OSINT investigation platform.

## Features

- **System Status** — View capabilities, installed tools, environment
- **LAN Monitor** — Port scanning, ARP scan, device discovery, camera detection
- **IP Intelligence** — Geolocation, ASN, WHOIS, reverse DNS, threat scoring
- **OSINT Toolkit** — Subdomain enumeration, DNS records, domain WHOIS
- **Camera Feeds** — RTSP/MJPEG stream viewer with multi-URL probing
- **Case Manager** — Track investigations, log entries, evidence
- **Activity Log** — Full audit trail of all actions

## Setup

```bash
# Install dependencies
pip3 install -r requirements.txt

# Optional: Set environment variables
echo "ABUSEIPDB_KEY=your_api_key_here" >> .env
echo "SHODAN_KEY=your_api_key_here" >> .env
echo "DASHBOARD_USER=admin1" >> .env
echo "DASHBOARD_PASS=SecurePassword" >> .env

# Run
python3 app.py