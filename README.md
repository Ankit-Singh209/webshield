# WebShield V2

Fresh Flask defensive website security analyzer.

## Included
- HTTPS/TLS and certificate expiry
- DNS records and DNSSEC/DNSKEY presence
- CAA
- SPF, DMARC, MTA-STS, TLS-RPT, BIMI
- HTTP status and redirect chain
- HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP
- Cookie Secure/HttpOnly/SameSite checks
- Common ports 80/443/8080/8443
- Passive edge/WAF indicators
- IP addresses
- Findings list and security score

## Windows
py -m venv .venv
.venv\Scripts\activate
py -m pip install -r requirements.txt
py app.py

Open http://127.0.0.1:5000

## GitHub
git init
git add .
git commit -m "Initial WebShield V2"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/WebShield.git
git push -u origin main

## Render
Build: pip install -r requirements.txt
Start: gunicorn app:app

Use only against systems you own or have permission to test.
