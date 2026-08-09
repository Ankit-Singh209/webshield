from flask import Flask, render_template, request, jsonify
import socket
import ssl
import ipaddress
import re
from urllib.parse import urlparse
from datetime import datetime, timezone

import requests

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

app = Flask(__name__)

TIMEOUT = 8
PORTS = [80, 443, 8080, 8443]
UA = "WebShield-V3-Authorized-Defensive-Scanner/1.0"


def R(name, status, evidence, severity="info"):
    return {
        "name": name,
        "status": status,
        "evidence": str(evidence),
        "severity": severity,
    }


def target(value):
    value = (value or "").strip()
    if not value:
        raise ValueError("Enter a website.")

    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value

    u = urlparse(value)

    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("Invalid HTTP/HTTPS URL.")

    host = u.hostname.rstrip(".").lower()

    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValueError("Private/local IP targets are not allowed.")
    except ValueError as e:
        if str(e) == "Private/local IP targets are not allowed.":
            raise
        if host == "localhost" or host.endswith(".local"):
            raise ValueError("Private/local IP targets are not allowed.")

    return u, host


def resolver():
    if not DNS_OK:
        return None
    r = dns.resolver.Resolver()
    r.timeout = 3
    r.lifetime = 5
    return r


def lookup(host, typ):
    r = resolver()
    if r is None:
        return []
    try:
        return [x.to_text().strip('"') for x in r.resolve(host, typ)]
    except Exception:
        return []


def txt(host):
    r = resolver()
    if r is None:
        return []
    try:
        answers = r.resolve(host, "TXT")
        return [
            b"".join(x.strings).decode("utf8", "replace")
            for x in answers
        ]
    except Exception:
        return []


def dns_scan(host):
    records = {
        x: lookup(host, x)
        for x in ["A", "AAAA", "MX", "TXT", "NS", "CAA", "SOA"]
    }

    dnskey = lookup(host, "DNSKEY")
    ds = lookup(host, "DS")
    records["DNSKEY"] = dnskey
    records["DS"] = ds

    ips = records["A"] + records["AAAA"]

    checks = [
        R(
            "DNS Resolution",
            "PASS" if ips else "WARNING",
            ", ".join(ips) if ips else "No A/AAAA record confirmed.",
            "info",
        ),
        R(
            "CAA",
            "PASS" if records["CAA"] else "WARNING",
            ", ".join(records["CAA"])
            if records["CAA"]
            else "No CAA record confirmed.",
            "info" if records["CAA"] else "low",
        ),
        R(
            "DNSSEC",
            "PASS" if dnskey and ds else "WARNING",
            "DNSKEY and DS records were found."
            if dnskey and ds
            else (
                "DNSKEY record found but DS was not confirmed."
                if dnskey
                else "DNSSEC records were not confirmed."
            ),
            "info" if dnskey and ds else "medium",
        ),
    ]

    return records, ips, checks


def email_scan(host):
    if not DNS_OK:
        return [
            R(x, "UNKNOWN", "DNS resolver unavailable.")
            for x in ["SPF", "DMARC", "MTA-STS", "TLS-RPT", "BIMI"]
        ]

    spf = next(
        (x for x in txt(host) if x.lower().startswith("v=spf1")),
        None,
    )

    dmarc = next(
        (x for x in txt("_dmarc." + host)
         if x.lower().startswith("v=dmarc1")),
        None,
    )

    mta_records = txt("_mta-sts." + host)
    rpt_records = txt("_smtp._tls." + host)
    bimi_records = txt("default._bimi." + host)

    mta = next(
        (x for x in mta_records if x.lower().startswith("v=stsv1")),
        None,
    )
    rpt = next(
        (x for x in rpt_records if "v=tlsrptv1" in x.lower()),
        None,
    )
    bimi = next(
        (x for x in bimi_records if x.lower().startswith("v=bimi1")),
        None,
    )

    results = [
        R(
            "SPF",
            "PASS" if spf else "WARNING",
            spf or "No SPF record confirmed.",
            "info" if spf else "medium",
        ),
        R(
            "DMARC",
            "PASS" if dmarc else "WARNING",
            dmarc or "No DMARC record confirmed.",
            "info" if dmarc else "high",
        ),
        R(
            "MTA-STS",
            "PASS" if mta else "WARNING",
            mta or "No MTA-STS record confirmed.",
            "info" if mta else "medium",
        ),
        R(
            "TLS-RPT",
            "PASS" if rpt else "WARNING",
            rpt or "No TLS-RPT record confirmed.",
            "info" if rpt else "low",
        ),
        R(
            "BIMI",
            "PASS" if bimi else "INFO",
            bimi or "No BIMI record confirmed.",
            "info",
        ),
    ]

    # MTA-STS also requires a policy file at a well-known HTTPS endpoint.
    if mta:
        try:
            policy_url = f"https://mta-sts.{host}/.well-known/mta-sts.txt"
            response = requests.get(
                policy_url,
                timeout=TIMEOUT,
                headers={"User-Agent": UA},
            )

            if response.status_code == 200:
                results.append(
                    R(
                        "MTA-STS Policy File",
                        "PASS",
                        "Policy file returned HTTP 200.",
                        "info",
                    )
                )
            else:
                results.append(
                    R(
                        "MTA-STS Policy File",
                        "WARNING",
                        f"Policy endpoint returned HTTP {response.status_code}.",
                        "medium",
                    )
                )
        except Exception as e:
            results.append(
                R(
                    "MTA-STS Policy File",
                    "WARNING",
                    f"Policy endpoint check failed: {e}",
                    "medium",
                )
            )
    else:
        results.append(
            R(
                "MTA-STS Policy File",
                "INFO",
                "Skipped because no MTA-STS DNS record was confirmed.",
                "info",
            )
        )

    return results


def tls_scan(host):
    try:
        ctx = ssl.create_default_context()

        with socket.create_connection(
            (host, 443), timeout=TIMEOUT
        ) as sock:
            with ctx.wrap_socket(
                sock, server_hostname=host
            ) as s:
                cert = s.getpeercert()
                version = s.version()
                cipher = (
                    s.cipher()[0]
                    if s.cipher()
                    else None
                )

        exp = cert.get("notAfter")
        days = None

        if exp:
            dt = datetime.strptime(
                exp,
                "%b %d %H:%M:%S %Y %Z",
            ).replace(tzinfo=timezone.utc)

            days = (
                dt - datetime.now(timezone.utc)
            ).days

        severity = (
            "critical"
            if days is not None and days < 0
            else "high"
            if days is not None and days < 30
            else "info"
        )

        return {
            "status": "PASS",
            "evidence": f"{version}, {cipher}.",
            "certificate": {
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "expires": exp,
                "days_remaining": days,
                "tls_version": version,
                "cipher": cipher,
            },
            "severity": severity,
        }

    except Exception as e:
        return {
            "status": "FAIL",
            "evidence": f"TLS connection or certificate validation failed: {e}",
            "certificate": {},
            "severity": "critical",
        }


def http_scan(url):
    try:
        session = requests.Session()
        session.headers["User-Agent"] = UA

        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
        )

        h = {
            k.lower(): v
            for k, v in response.headers.items()
        }

        specs = {
            "Strict-Transport-Security":
                "Forces HTTPS.",
            "Content-Security-Policy":
                "Reduces XSS/content injection risk.",
            "X-Frame-Options":
                "Helps prevent clickjacking.",
            "X-Content-Type-Options":
                "Reduces MIME sniffing.",
            "Referrer-Policy":
                "Controls referrer information.",
            "Permissions-Policy":
                "Controls browser feature access.",
            "Cross-Origin-Opener-Policy":
                "Helps isolate browsing contexts.",
            "Cross-Origin-Resource-Policy":
                "Controls cross-origin resource loading.",
        }

        headers = []

        for name, purpose in specs.items():
            present = name.lower() in h

            headers.append(
                R(
                    name,
                    "PASS" if present else "WARNING",
                    (
                        "Header is present."
                        if present
                        else "Header was not observed."
                    ),
                    (
                        "info"
                        if present
                        else (
                            "high"
                            if name in [
                                "Content-Security-Policy",
                                "Strict-Transport-Security",
                            ]
                            else "medium"
                        )
                    ),
                )
            )

        # get_all preserves multiple Set-Cookie headers where supported.
        try:
            cookies_raw = (
                response.raw.headers.get_all("Set-Cookie")
                or []
            )
        except Exception:
            cookies_raw = []

        if not cookies_raw and "Set-Cookie" in response.headers:
            cookies_raw = [response.headers["Set-Cookie"]]

        cookie_checks = []

        if cookies_raw:
            for cookie in cookies_raw:
                low = cookie.lower()

                for label, token in [
                    ("Secure Cookie Attribute", "secure"),
                    ("HttpOnly Cookie Attribute", "httponly"),
                    ("SameSite Cookie Attribute", "samesite"),
                ]:
                    cookie_checks.append(
                        R(
                            label,
                            "PASS" if token in low else "WARNING",
                            (
                                "Attribute observed."
                                if token in low
                                else "Attribute not observed."
                            ),
                            "info" if token in low else "medium",
                        )
                    )
        else:
            cookie_checks = [
                R(
                    "Cookies",
                    "INFO",
                    "No Set-Cookie header observed.",
                    "info",
                )
            ]

        history = [
            {
                "status": item.status_code,
                "url": item.url,
            }
            for item in response.history
        ]

        history.append(
            {
                "status": response.status_code,
                "url": response.url,
            }
        )

        edge = {
            k: v
            for k, v in h.items()
            if k in [
                "server",
                "via",
                "cf-ray",
                "cf-cache-status",
                "x-amz-cf-id",
                "x-cache",
                "x-sucuri-id",
            ]
        }

        return {
            "ok": True,
            "status_code": response.status_code,
            "final_url": response.url,
            "redirects": history,
            "headers": headers,
            "cookies": cookie_checks,
            "edge": edge,
        }

    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "headers": [],
            "cookies": [],
            "redirects": [],
            "edge": {},
        }


def ports(host):
    results = []

    for port in PORTS:
        try:
            with socket.create_connection(
                (host, port),
                timeout=1.2,
            ):
                results.append(
                    {
                        "port": port,
                        "status": "OPEN",
                    }
                )
        except Exception:
            results.append(
                {
                    "port": port,
                    "status": "CLOSED/FILTERED",
                }
            )

    return results


def score(groups):
    points = 100
    findings = []

    for group in groups:
        for check in group:
            if check["status"] == "FAIL":
                points -= {
                    "critical": 30,
                    "high": 18,
                    "medium": 10,
                    "low": 4,
                    "info": 0,
                }.get(check.get("severity", "medium"), 10)
                findings.append(check)

            elif check["status"] == "WARNING":
                points -= {
                    "critical": 30,
                    "high": 18,
                    "medium": 10,
                    "low": 4,
                    "info": 0,
                }.get(check.get("severity", "low"), 4)
                findings.append(check)

    return max(0, min(100, points)), findings


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/api/scan")
def scan():
    try:
        body = request.get_json(silent=True) or {}
        u, host = target(body.get("url") or body.get("target"))

        records, ips, dns = dns_scan(host)
        email = email_scan(host)

        if u.scheme == "https":
            tls = tls_scan(host)
        else:
            tls = {
                "status": "FAIL",
                "evidence": "Target uses HTTP.",
                "certificate": {},
                "severity": "critical",
            }

        http = http_scan(u.geturl())

        core = [
            R(
                "HTTPS",
                "PASS" if u.scheme == "https" else "FAIL",
                (
                    "HTTPS is enabled."
                    if u.scheme == "https"
                    else "Target uses HTTP."
                ),
                "info" if u.scheme == "https" else "critical",
            ),
            R(
                "TLS / SSL",
                tls["status"],
                tls["evidence"],
                tls.get("severity", "info"),
            ),
            R(
                "HTTP Reachability",
                "PASS" if http["ok"] else "FAIL",
                (
                    "HTTP response received."
                    if http["ok"]
                    else "HTTP request failed."
                ),
                "info" if http["ok"] else "high",
            ),
        ]

        groups = [
            core,
            dns,
            email,
            http.get("headers", []),
            http.get("cookies", []),
        ]

        final_score, findings = score(groups)

        if final_score >= 90:
            risk = "EXCELLENT"
        elif final_score >= 75:
            risk = "LOW RISK"
        elif final_score >= 50:
            risk = "MEDIUM RISK"
        elif final_score >= 25:
            risk = "HIGH RISK"
        else:
            risk = "CRITICAL"

        return jsonify(
            {
                "ok": True,
                "target": {
                    "url": u.geturl(),
                    "hostname": host,
                    "protocol": u.scheme.upper(),
                },
                "score": final_score,
                "risk": risk,
                "core": core,
                "dns": dns,
                "email": email,
                "headers": http.get("headers", []),
                "cookies": http.get("cookies", []),
                "tls": tls,
                "http": http,
                "ports": ports(host),
                "ips": ips,
                "dns_records": records,
                "findings": findings,
                "scan_time": datetime.now(timezone.utc).isoformat(),
                "notes": [
                    "Authorized defensive testing only.",
                    "Common-port checks are limited to 80, 443, 8080 and 8443.",
                    "A warning means the control was not confirmed; it is not proof of exploitation.",
                ],
            }
        )

    except ValueError as e:
        return jsonify(
            {
                "ok": False,
                "error": str(e),
            }
        ), 400

    except Exception as e:
        return jsonify(
            {
                "ok": False,
                "error": f"Scanner error: {e}",
            }
        ), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
    )
