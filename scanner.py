#!/usr/bin/env python3
"""
Automated Web Scanner
=====================
Audits websites for missing/weak security headers, insecure cookies,
information-leaking headers and CORS misconfigurations.

Only scan sites you own or have written permission to test.

Usage:
    python scanner.py https://example.com
    python scanner.py https://a.com https://b.com --json out.json --html report.html
    python scanner.py -f targets.txt --html report.html
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from html import escape
from urllib.parse import urlparse

import requests

requests.packages.urllib3.disable_warnings()  # self-signed certs on lab targets

TIMEOUT = 10
UA = "AutoWebScanner/1.0 (educational security audit)"
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_POINTS = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 4, "INFO": 0}


@dataclass
class Finding:
    category: str
    title: str
    severity: str
    detail: str
    fix: str = ""


@dataclass
class ScanResult:
    target: str
    final_url: str = ""
    status: int = 0
    error: str = ""
    score: int = 100
    grade: str = "A"
    findings: list = field(default_factory=list)


# ---------------------------------------------------------------- helpers
def normalize(url: str) -> str:
    if not urlparse(url).scheme:
        url = "https://" + url
    return url


def fetch(url, headers=None, allow_redirects=True):
    return requests.get(
        url,
        headers={"User-Agent": UA, **(headers or {})},
        timeout=TIMEOUT,
        allow_redirects=allow_redirects,
        verify=False,
    )


# ------------------------------------------------------- header analysis
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "HIGH",
        "Missing HSTS: browsers may connect over plain HTTP.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    ),
    "Content-Security-Policy": (
        "HIGH",
        "Missing CSP: no browser-side defence against XSS/data injection.",
        "Define a CSP, e.g. \"default-src 'self'\", and avoid 'unsafe-inline'.",
    ),
    "X-Content-Type-Options": (
        "MEDIUM",
        "Missing X-Content-Type-Options: MIME sniffing is possible.",
        "Add 'X-Content-Type-Options: nosniff'.",
    ),
    "X-Frame-Options": (
        "MEDIUM",
        "Missing clickjacking protection (X-Frame-Options / frame-ancestors).",
        "Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors'.",
    ),
    "Referrer-Policy": (
        "LOW",
        "Missing Referrer-Policy: full URLs may leak to third parties.",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
    ),
    "Permissions-Policy": (
        "LOW",
        "Missing Permissions-Policy: browser features are not restricted.",
        "Add a Permissions-Policy limiting camera, microphone, geolocation.",
    ),
}

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def check_headers(resp, findings):
    h = resp.headers
    is_https = resp.url.startswith("https://")

    for name, (sev, detail, fix) in SECURITY_HEADERS.items():
        if name == "Strict-Transport-Security" and not is_https:
            continue
        if name == "X-Frame-Options":
            csp = h.get("Content-Security-Policy", "")
            if name in h or "frame-ancestors" in csp.lower():
                continue
        if name not in h:
            findings.append(Finding("Headers", f"{name} missing", sev, detail, fix))

    # weak values
    hsts = h.get("Strict-Transport-Security", "")
    if hsts:
        try:
            age = int(
                next(p.split("=")[1] for p in hsts.replace(" ", "").split(";")
                     if p.lower().startswith("max-age"))
            )
            if age < 15552000:
                findings.append(Finding(
                    "Headers", "HSTS max-age too short", "LOW",
                    f"max-age={age} (< 6 months).",
                    "Use at least max-age=31536000."))
        except (StopIteration, ValueError, IndexError):
            findings.append(Finding("Headers", "HSTS malformed", "LOW", hsts,
                                    "Use 'max-age=31536000; includeSubDomains'."))

    csp = h.get("Content-Security-Policy", "")
    if csp:
        low = csp.lower()
        if "unsafe-inline" in low or "unsafe-eval" in low:
            findings.append(Finding(
                "Headers", "CSP allows unsafe-inline/unsafe-eval", "MEDIUM",
                "Weakens XSS protection.", "Use nonces/hashes instead."))
        if " * " in f" {low} " or "default-src *" in low:
            findings.append(Finding(
                "Headers", "CSP wildcard source", "MEDIUM",
                "A wildcard source defeats most of the policy.",
                "List explicit trusted origins."))

    xcto = h.get("X-Content-Type-Options", "")
    if xcto and xcto.lower() != "nosniff":
        findings.append(Finding("Headers", "Invalid X-Content-Type-Options", "LOW",
                                xcto, "Set to 'nosniff'."))

    # information disclosure
    for name in LEAKY_HEADERS:
        if name in h:
            val = h[name]
            has_version = any(c.isdigit() for c in val)
            findings.append(Finding(
                "Info Leak", f"{name} header exposes technology",
                "LOW" if has_version else "INFO",
                f"{name}: {val}",
                f"Remove or genericise the {name} header."))


# ------------------------------------------------------------- cookies
def check_cookies(resp, findings):
    raw = []
    try:
        raw = resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        pass
    if not raw and "Set-Cookie" in resp.headers:
        raw = [resp.headers["Set-Cookie"]]

    for c in raw:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        problems = []
        if resp.url.startswith("https://") and "secure" not in low:
            problems.append("Secure")
        if "httponly" not in low:
            problems.append("HttpOnly")
        if "samesite" not in low:
            problems.append("SameSite")
        if problems:
            sev = "MEDIUM" if ("Secure" in problems or "HttpOnly" in problems) else "LOW"
            findings.append(Finding(
                "Cookies", f"Cookie '{name}' missing {', '.join(problems)}", sev,
                c[:120], "Set Secure; HttpOnly; SameSite=Lax (or Strict)."))


# ---------------------------------------------------------------- CORS
def cors_probe(url, origin):
    try:
        r = fetch(url, headers={"Origin": origin}, allow_redirects=True)
    except requests.RequestException:
        return None, None
    return (r.headers.get("Access-Control-Allow-Origin"),
            r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true")


def check_cors(url, findings):
    host = urlparse(url).hostname or ""
    probes = [
        ("arbitrary origin", "https://evil-attacker.example"),
        ("null origin", "null"),
        ("suffix bypass", f"https://{host}.evil-attacker.example"),
        ("prefix bypass", f"https://evil-attacker{host}"),
        ("http downgrade", f"http://{host}"),
    ]
    for label, origin in probes:
        acao, creds = cors_probe(url, origin)
        if acao is None:
            continue
        if acao == "*":
            sev = "CRITICAL" if creds else "LOW"
            title = ("CORS wildcard with credentials" if creds
                     else "CORS allows any origin (*)")
            findings.append(Finding(
                "CORS", title, sev,
                "Access-Control-Allow-Origin: * returned.",
                "Restrict to an explicit allow-list; never combine * with credentials."))
            return  # same result for all probes
        if acao == origin:
            if label == "http downgrade":
                sev = "LOW"
            else:
                sev = "CRITICAL" if creds else "HIGH"
            findings.append(Finding(
                "CORS", f"CORS reflects origin ({label})", sev,
                f"Sent Origin: {origin} -> ACAO: {acao}"
                + (" with credentials=true" if creds else ""),
                "Validate Origin against an exact allow-list; do not reflect it."))
    # preflight with dangerous method
    try:
        r = requests.options(
            url, timeout=TIMEOUT, verify=False,
            headers={"User-Agent": UA, "Origin": "https://evil-attacker.example",
                     "Access-Control-Request-Method": "DELETE"})
        allow = r.headers.get("Access-Control-Allow-Methods", "")
        if r.headers.get("Access-Control-Allow-Origin") in ("*", "https://evil-attacker.example") \
                and any(m in allow.upper() for m in ("DELETE", "PUT", "PATCH")):
            findings.append(Finding(
                "CORS", "Preflight allows state-changing methods to untrusted origin",
                "HIGH", f"Allow-Methods: {allow}",
                "Limit allowed methods and origins on preflight responses."))
    except requests.RequestException:
        pass


# ------------------------------------------------------ transport / misc
def check_transport(url, findings):
    p = urlparse(url)
    if p.scheme == "http":
        findings.append(Finding("Transport", "Site served over plain HTTP", "HIGH",
                                url, "Serve over HTTPS and redirect HTTP to HTTPS."))
        return
    http_url = "http://" + p.netloc + (p.path or "/")
    try:
        r = fetch(http_url, allow_redirects=False)
        loc = r.headers.get("Location", "")
        if not (300 <= r.status_code < 400 and loc.startswith("https://")):
            findings.append(Finding(
                "Transport", "HTTP does not redirect to HTTPS", "MEDIUM",
                f"{http_url} returned {r.status_code}.",
                "Add a 301 redirect from HTTP to HTTPS."))
    except requests.RequestException:
        pass  # port 80 closed is fine


# -------------------------------------------------------------- scoring
def grade(score):
    return ("A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65
            else "D" if score >= 50 else "F")


def scan(target):
    result = ScanResult(target=target)
    url = normalize(target)
    try:
        resp = fetch(url)
    except requests.RequestException as e:
        result.error = str(e)[:200]
        result.score, result.grade = 0, "-"
        return result

    result.final_url, result.status = resp.url, resp.status_code
    findings = []
    check_transport(url, findings)
    check_headers(resp, findings)
    check_cookies(resp, findings)
    check_cors(resp.url, findings)

    findings.sort(key=lambda f: -SEVERITY_ORDER[f.severity])
    result.findings = findings
    result.score = max(0, 100 - sum(SEVERITY_POINTS[f.severity] for f in findings))
    result.grade = grade(result.score)
    return result


# ------------------------------------------------------------- reporting
COLORS = {"CRITICAL": "\033[95m", "HIGH": "\033[91m", "MEDIUM": "\033[93m",
          "LOW": "\033[94m", "INFO": "\033[90m"}
RESET = "\033[0m"


def print_result(r: ScanResult):
    print("=" * 70)
    print(f"Target : {r.target}")
    if r.error:
        print(f"ERROR  : {r.error}")
        return
    print(f"Final  : {r.final_url}  (HTTP {r.status})")
    print(f"Score  : {r.score}/100   Grade: {r.grade}")
    print("-" * 70)
    if not r.findings:
        print("No issues found.")
    for f in r.findings:
        c = COLORS[f.severity] if sys.stdout.isatty() else ""
        end = RESET if c else ""
        print(f"{c}[{f.severity:<8}]{end} ({f.category}) {f.title}")
        print(f"           {f.detail}")
        if f.fix:
            print(f"           Fix: {f.fix}")


def html_report(results):
    badge = {"CRITICAL": "#7b1fa2", "HIGH": "#d32f2f", "MEDIUM": "#f57c00",
             "LOW": "#1976d2", "INFO": "#757575"}
    out = ["<!doctype html><html><head><meta charset='utf-8'><title>Web Scan Report</title>",
           "<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#222}"
           "h1{border-bottom:2px solid #333}.card{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}"
           ".b{color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600}"
           "table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #eee;padding:6px;text-align:left;vertical-align:top}"
           ".g{font-size:2rem;font-weight:700}</style></head><body>",
           f"<h1>Web Security Scan Report</h1><p>Generated {datetime.now():%Y-%m-%d %H:%M}</p>"]
    for r in results:
        out.append(f"<div class='card'><h2>{escape(r.target)}</h2>")
        if r.error:
            out.append(f"<p>Error: {escape(r.error)}</p></div>")
            continue
        out.append(f"<p>HTTP {r.status} &middot; Score <b>{r.score}/100</b> "
                   f"&middot; Grade <span class='g'>{r.grade}</span></p>")
        if r.findings:
            out.append("<table><tr><th>Severity</th><th>Category</th><th>Issue</th><th>Detail / Fix</th></tr>")
            for f in r.findings:
                out.append(
                    f"<tr><td><span class='b' style='background:{badge[f.severity]}'>{f.severity}</span></td>"
                    f"<td>{escape(f.category)}</td><td>{escape(f.title)}</td>"
                    f"<td>{escape(f.detail)}<br><i>Fix: {escape(f.fix)}</i></td></tr>")
            out.append("</table>")
        else:
            out.append("<p>No issues found.</p>")
        out.append("</div>")
    out.append("</body></html>")
    return "\n".join(out)


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description="Audit sites for secure headers, cookies and CORS flaws.")
    ap.add_argument("urls", nargs="*", help="target URLs")
    ap.add_argument("-f", "--file", help="file with one URL per line")
    ap.add_argument("--json", help="write JSON report to this path")
    ap.add_argument("--html", help="write HTML report to this path")
    args = ap.parse_args()

    targets = list(args.urls)
    if args.file:
        with open(args.file) as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not targets:
        ap.error("provide at least one URL or -f file")

    print("Only scan systems you own or are authorised to test.\n")
    results = []
    for t in targets:
        r = scan(t)
        print_result(r)
        results.append(r)
        time.sleep(0.5)  # be polite

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([asdict(r) for r in results], fh, indent=2)
        print(f"\nJSON report: {args.json}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html_report(results))
        print(f"HTML report: {args.html}")

    worst = min((r.score for r in results), default=100)
    sys.exit(0 if worst >= 80 else 1)


if __name__ == "__main__":
    main()
