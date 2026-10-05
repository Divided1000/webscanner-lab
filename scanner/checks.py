"""
Vulnerability checks. Each function probes the target and reports a Finding if
the vulnerability is detected. Detection is behavioral/evidence-based — we infer
the flaw from how the app responds to crafted input, which is how real DAST
tools (Burp, ZAP) work.
"""

from .core import Scanner, Finding


# ---------------------------------------------------------------------------
# Check 1 — SQL Injection (OWASP A03)
# Technique: send a classic auth-bypass payload and a logically-false payload.
# If the bypass "logs in" but the false one does not, the input is reaching the
# SQL engine as code -> injection. We also flag SQL errors leaking in responses.
# ---------------------------------------------------------------------------
def check_sql_injection(s: Scanner):
    # Baseline: obviously-wrong creds should NOT authenticate.
    baseline = s.get("/login", params={"username": "nouser", "password": "nopass"})
    # Attack: comment-out the password check so WHERE is always satisfied.
    attack = s.get("/login", params={"username": "admin'--", "password": "x"})
    if baseline is None or attack is None:
        return

    base_auth = "authenticated" in baseline.text.lower()
    atk_auth = "authenticated" in attack.text.lower()

    # Injection confirmed if the payload authenticates when the baseline did not.
    if atk_auth and not base_auth:
        s.report(Finding(
            check="sql_injection",
            owasp="A03:2021 Injection",
            severity="CRITICAL",
            endpoint="/login",
            evidence="Payload username=admin'-- bypassed authentication "
                     "(baseline invalid creds were rejected).",
            remediation="Use parameterized queries / prepared statements; never "
                        "concatenate user input into SQL.",
        ))
        return

    # Secondary signal: SQL error text leaking indicates injection reached SQL.
    err = s.get("/login", params={"username": "'", "password": "x"})
    if err is not None and any(
        kw in err.text.lower() for kw in ["sql", "syntax", "sqlite", "unrecognized token"]
    ):
        s.report(Finding(
            check="sql_injection",
            owasp="A03:2021 Injection",
            severity="HIGH",
            endpoint="/login",
            evidence=f"Single-quote payload triggered a SQL error in the response "
                     f"(HTTP {err.status_code}), indicating input reaches the SQL engine.",
            remediation="Use parameterized queries; suppress verbose DB errors to users.",
        ))


# ---------------------------------------------------------------------------
# Check 2 — Reflected XSS (OWASP A03)
# Technique: inject a unique script payload; if it comes back verbatim (not
# HTML-encoded) in an HTML response, the input is reflected unsafely.
# ---------------------------------------------------------------------------
def check_reflected_xss(s: Scanner):
    payload = "<script>alert(1)</script>"
    resp = s.get("/search", params={"q": payload})
    if resp is None:
        return
    content_type = resp.headers.get("Content-Type", "")
    # Vulnerable if the raw payload appears un-encoded in an HTML response.
    if payload in resp.text and "text/html" in content_type:
        s.report(Finding(
            check="reflected_xss",
            owasp="A03:2021 Injection (XSS)",
            severity="HIGH",
            endpoint="/search",
            evidence=f"Payload {payload} was reflected unescaped in an HTML response.",
            remediation="Context-aware output encoding; set a Content-Security-Policy; "
                        "treat all user input as untrusted.",
        ))


# ---------------------------------------------------------------------------
# Check 3 — Broken Access Control / IDOR (OWASP A01)
# Technique: request sequential object IDs with no auth. If different IDs return
# different users' records, objects are exposed without authorization.
# ---------------------------------------------------------------------------
def check_idor(s: Scanner):
    seen = {}
    for uid in (1, 2, 3):
        resp = s.get(f"/account/{uid}")
        if resp is not None and resp.status_code == 200 and "username" in resp.text.lower():
            seen[uid] = resp.text

    # IDOR if we pulled multiple distinct records with no authentication.
    if len(seen) >= 2 and len(set(seen.values())) >= 2:
        s.report(Finding(
            check="idor",
            owasp="A01:2021 Broken Access Control",
            severity="HIGH",
            endpoint="/account/<id>",
            evidence=f"Retrieved {len(seen)} distinct user records by enumerating IDs "
                     f"({sorted(seen)}) with no authentication or ownership check.",
            remediation="Enforce authorization on every object access: verify the "
                        "authenticated user owns/may access the requested resource.",
        ))


# ---------------------------------------------------------------------------
# Check 4 — Security Misconfiguration: missing headers (OWASP A05)
# Technique: inspect response headers for standard protective headers.
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "Content-Security-Policy": "Mitigates XSS/data injection by restricting sources.",
    "Strict-Transport-Security": "Forces HTTPS, prevents protocol downgrade.",
    "X-Frame-Options": "Prevents clickjacking via framing.",
    "X-Content-Type-Options": "Stops MIME-type sniffing.",
}


def check_security_headers(s: Scanner):
    resp = s.get("/")
    if resp is None:
        return
    missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
    if missing:
        s.report(Finding(
            check="security_headers",
            owasp="A05:2021 Security Misconfiguration",
            severity="MEDIUM",
            endpoint="/",
            evidence="Missing security headers: " + ", ".join(missing),
            remediation="Set the missing headers (e.g. CSP, HSTS, X-Frame-Options, "
                        "X-Content-Type-Options) on all responses.",
        ))


ALL_CHECKS = [
    check_sql_injection,
    check_reflected_xss,
    check_idor,
    check_security_headers,
]
