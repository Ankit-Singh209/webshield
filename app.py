from flask import Flask, render_template, request, jsonify, send_file
import socket, ssl, ipaddress, re, io, json
from urllib.parse import urlparse
from datetime import datetime, timezone
import requests

try:
    import dns.resolver
    DNS_OK=True
except ImportError:
    DNS_OK=False

app=Flask(__name__)
TIMEOUT=8
PORTS=[80,443,8080,8443]
UA="WebShield-V2-Authorized-Defensive-Scanner/1.0"

def R(name,status,evidence,severity="info"):
    return {"name":name,"status":status,"evidence":evidence,"severity":severity}

def target(value):
    value=(value or "").strip()
    if not value: raise ValueError("Enter a website.")
    if not re.match(r"^https?://",value,re.I): value="https://"+value
    u=urlparse(value)
    if u.scheme not in ("http","https") or not u.hostname: raise ValueError("Invalid HTTP/HTTPS URL.")
    host=u.hostname.rstrip(".")
    try:
        ip=ipaddress.ip_address(host)
        if not ip.is_global: raise ValueError("Private/local IP targets are not allowed.")
    except ValueError as e:
        if str(e)=="Private/local IP targets are not allowed.": raise
    return u,host

def lookup(host,typ):
    if not DNS_OK:return []
    try:
        r=dns.resolver.Resolver();r.timeout=3;r.lifetime=5
        return [x.to_text().strip('"') for x in r.resolve(host,typ)]
    except Exception:return []

def txt(host):
    if not DNS_OK:return []
    try:
        a=dns.resolver.resolve(host,"TXT")
        return [b"".join(x.strings).decode("utf8","replace") for x in a]
    except Exception:return []

def dns_scan(host):
    records={x:lookup(host,x) for x in ["A","AAAA","MX","TXT","NS","CAA","SOA"]}
    ips=records["A"]+records["AAAA"]
    checks=[
        R("DNS Resolution","PASS" if ips else "WARNING",", ".join(ips) if ips else "No A/AAAA record confirmed.","info"),
        R("CAA","PASS" if records["CAA"] else "WARNING",", ".join(records["CAA"]) if records["CAA"] else "No CAA record confirmed.","low"),
        R("DNSSEC","PASS" if lookup(host,"DNSKEY") else "WARNING",
          "DNSKEY records found." if lookup(host,"DNSKEY") else "DNSKEY records were not confirmed.","medium")
    ]
    return records,ips,checks

def email_scan(host):
    if not DNS_OK:return [R(x,"UNKNOWN","DNS resolver unavailable.") for x in ["SPF","DMARC","MTA-STS","TLS-RPT","BIMI"]]
    spf=next((x for x in txt(host) if x.lower().startswith("v=spf1")),None)
    dmarc=next((x for x in txt("_dmarc."+host) if x.lower().startswith("v=dmarc1")),None)
    mta=any(x.lower().startswith("v=stsv1") for x in txt("_mta-sts."+host))
    rpt=any("v=tlsrptv1" in x.lower() for x in txt("_smtp._tls."+host))
    bimi=any(x.lower().startswith("v=bimi1") for x in txt("default._bimi."+host))
    return [
        R("SPF","PASS" if spf else "WARNING",spf or "No SPF record confirmed.","low"),
        R("DMARC","PASS" if dmarc else "WARNING",dmarc or "No DMARC record confirmed.","medium"),
        R("MTA-STS","PASS" if mta else "WARNING","Record found." if mta else "No MTA-STS record confirmed.","low"),
        R("TLS-RPT","PASS" if rpt else "WARNING","Record found." if rpt else "No TLS-RPT record confirmed.","low"),
        R("BIMI","PASS" if bimi else "INFO","Record found." if bimi else "No BIMI record confirmed.","info")
    ]

def tls_scan(host):
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,443),timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock,server_hostname=host) as s:
                cert=s.getpeercert(); version=s.version(); cipher=s.cipher()[0] if s.cipher() else None
        exp=cert.get("notAfter");days=None
        if exp:
            dt=datetime.strptime(exp,"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days=(dt-datetime.now(timezone.utc)).days
        sev="critical" if days is not None and days<0 else ("high" if days is not None and days<30 else "info")
        return {"status":"PASS","evidence":f"{version}, {cipher}.","certificate":{"subject":cert.get("subject"),"issuer":cert.get("issuer"),"expires":exp,"days_remaining":days,"tls_version":version,"cipher":cipher},"severity":sev}
    except Exception:return {"status":"FAIL","evidence":"TLS connection or certificate validation failed.","certificate":{},"severity":"critical"}

def http_scan(url):
    try:
        s=requests.Session();s.headers["User-Agent"]=UA
        r=s.get(url,timeout=TIMEOUT,allow_redirects=True)
        h={k.lower():v for k,v in r.headers.items()}
        specs={
          "Strict-Transport-Security":"Forces HTTPS.",
          "Content-Security-Policy":"Reduces XSS/content injection risk.",
          "X-Frame-Options":"Helps prevent clickjacking.",
          "X-Content-Type-Options":"Reduces MIME sniffing.",
          "Referrer-Policy":"Controls referrer information.",
          "Permissions-Policy":"Controls browser feature access.",
          "Cross-Origin-Opener-Policy":"Helps isolate browsing contexts.",
          "Cross-Origin-Resource-Policy":"Controls cross-origin resource loading."
        }
        headers=[]
        for name,purpose in specs.items():
            present=name.lower() in h
            headers.append(R(name,"PASS" if present else "WARNING",
                             "Header is present." if present else "Header was not observed.",
                             "info" if present else ("high" if name in ["Content-Security-Policy","Strict-Transport-Security"] else "medium")))
        cookies=r.headers.get("Set-Cookie","").lower()
        cookie_checks=[]
        if cookies:
            for label,token in [("Secure Cookie Attribute","secure"),("HttpOnly Cookie Attribute","httponly"),("SameSite Cookie Attribute","samesite")]:
                cookie_checks.append(R(label,"PASS" if token in cookies else "WARNING","Attribute observed." if token in cookies else "Attribute not observed.","medium" if token not in cookies else "info"))
        else: cookie_checks=[R("Cookies","INFO","No Set-Cookie header observed.","info")]
        hist=[{"status":x.status_code,"url":x.url} for x in r.history]+[{"status":r.status_code,"url":r.url}]
        edge={k:v for k,v in h.items() if k in ["server","via","cf-ray","x-amz-cf-id","x-cache","x-sucuri-id"]}
        return {"ok":True,"status_code":r.status_code,"final_url":r.url,"redirects":hist,"headers":headers,"cookies":cookie_checks,"edge":edge}
    except Exception as e:return {"ok":False,"error":str(e),"headers":[],"cookies":[],"redirects":[],"edge":{}}

def ports(host):
    out=[]
    for p in PORTS:
        try:
            with socket.create_connection((host,p),timeout=1.2):out.append({"port":p,"status":"OPEN"})
        except Exception:out.append({"port":p,"status":"CLOSED/FILTERED"})
    return out

def score(groups):
    score=100;findings=[]
    for group in groups:
        for c in group:
            if c["status"]=="FAIL":
                score-=15;findings.append(c)
            elif c["status"]=="WARNING":
                score-=3;findings.append(c)
    return max(0,min(100,score)),findings

@app.get("/")
def home():return render_template("index.html")

@app.post("/api/scan")
def scan():
    try:
        u,host=target(request.json.get("url"))
        records,ips,dns=dns_scan(host);email=email_scan(host)
        tls=tls_scan(host) if u.scheme=="https" else {"status":"FAIL","evidence":"Target uses HTTP.","certificate":{},"severity":"critical"}
        http=http_scan(u.geturl())
        core=[
            R("HTTPS","PASS" if u.scheme=="https" else "FAIL","HTTPS is enabled." if u.scheme=="https" else "Target uses HTTP.","info" if u.scheme=="https" else "critical"),
            R("TLS / SSL",tls["status"],tls["evidence"],tls.get("severity","info")),
            R("HTTP Reachability","PASS" if http["ok"] else "FAIL","HTTP response received." if http["ok"] else "HTTP request failed.","info" if http["ok"] else "high")
        ]
        s,findings=score([core,dns,email,http.get("headers",[]),http.get("cookies",[])])
        risk="EXCELLENT" if s>=90 else "LOW RISK" if s>=75 else "MEDIUM RISK" if s>=50 else "HIGH RISK" if s>=25 else "CRITICAL"
        return jsonify({"ok":True,"target":{"url":u.geturl(),"hostname":host,"protocol":u.scheme.upper()},
          "score":s,"risk":risk,"core":core,"dns":dns,"email":email,"headers":http.get("headers",[]),"cookies":http.get("cookies",[]),
          "tls":tls,"http":http,"ports":ports(host),"ips":ips,"dns_records":records,"findings":findings,
          "scan_time":datetime.now().isoformat(),"notes":["Authorized defensive testing only.","Common-port checks are limited to 80, 443, 8080 and 8443.","A warning means the control was not confirmed; it is not proof of exploitation."]})
    except ValueError as e:return jsonify({"ok":False,"error":str(e)}),400
    except Exception:return jsonify({"ok":False,"error":"Scanner error."}),500

if __name__=="__main__":app.run(host="127.0.0.1",port=5000,debug=True)
