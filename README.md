# webscanner-lab

A small **web application vulnerability scanner** (offensive security / DAST),
built in Python, plus a deliberately-vulnerable target app to test it against.
The scanner detects real OWASP Top 10 vulnerability classes and produces a
severity-ranked findings report with evidence and remediation.

This project demonstrates the **offensive** side of application security —
finding and proving vulnerabilities — through **automation**, which is how
modern DAST tooling (Burp Suite, OWASP ZAP) is used in CI/CD security programs.

> ⚠️ **Ethical use notice.** This tool is for learning and for scanning targets
> you **own or are explicitly authorized** to test. The included app in
> `target/` is the intended, safe target. Scanning systems without authorization
> is illegal. Only ever point this at something you own.

---

## What it detects

| Check | OWASP Top 10 | How it's detected |
|-------|--------------|-------------------|
| SQL Injection | A03:2021 Injection | Auth-bypass payload authenticates where baseline invalid creds fail; SQL errors leaking |
| Reflected XSS | A03:2021 Injection (XSS) | Script payload reflected unescaped in an HTML response |
| Broken Access Control (IDOR) | A01:2021 Broken Access Control | Enumerating object IDs returns other users' records with no authorization |
| Security Misconfiguration | A05:2021 Security Misconfiguration | Missing protective headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) |

Detection is **behavioral / evidence-based** — the scanner infers each flaw from
how the app responds to crafted input, the same approach real DAST tools use.

---

## Layout

```
webscanner-lab/
├── target/
│   └── vulnerable_app.py   # deliberately-vulnerable Flask app (the safe target)
├── scanner/
│   ├── core.py             # HTTP client + Finding model + report structure
│   ├── config.py           # ScanConfig: endpoints/params (retarget without code edits)
│   ├── checks.py           # the four vulnerability checks
│   └── __main__.py         # CLI entry point
├── requirements.txt
└── README.md
```

---

## Run it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1) Start the vulnerable target (terminal 1)
python target/vulnerable_app.py          # http://127.0.0.1:8000

# 2) Scan it (terminal 2)
python -m scanner http://127.0.0.1:8000 --json report.json

# CI/DAST mode: exit non-zero if anything is found (gate a pipeline build)
python -m scanner http://127.0.0.1:8000 --fail-on-findings
```

### Retargeting / configuration

Endpoints and parameters live in `scanner/config.py` (`ScanConfig`), separate
from the check logic — so the scanner can be pointed at a different app by
editing config rather than code, the way real DAST tools are configured per
target.

---

## Example output

Scanning the included target produces:

```
  web vulnerability scanner  ->  target: http://127.0.0.1:8000
  --------------------------------------------------------
  [CRITICAL] A03:2021 Injection
      check:       sql_injection
      endpoint:    /login
      evidence:    Payload username=admin'-- bypassed authentication
                   (baseline invalid creds were rejected).
      remediation: Use parameterized queries / prepared statements.

  [HIGH] A03:2021 Injection (XSS)
      check:       reflected_xss
      endpoint:    /search
      evidence:    Payload <script>alert(1)</script> reflected unescaped.

  [HIGH] A01:2021 Broken Access Control
      check:       idor
      endpoint:    /account/<id>
      evidence:    Retrieved 3 distinct user records by enumerating IDs
                   with no authentication or ownership check.

  [MEDIUM] A05:2021 Security Misconfiguration
      check:       security_headers
      endpoint:    /
      evidence:    Missing: Content-Security-Policy, Strict-Transport-Security,
                   X-Frame-Options, X-Content-Type-Options
  --------------------------------------------------------
  Summary: 4 finding(s) -> {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 1}
```

---

## Honest limitations

This is a **learning / portfolio tool, not a replacement for Burp Suite or OWASP
ZAP.** Specifically:

- It checks **known endpoints**; it does not crawl/spider a full application.
- Detection uses **targeted payloads**, so it can miss variations and does not
  attempt evasion/WAF bypass.
- It covers **four** vulnerability classes, not the full OWASP Top 10.
- Pattern/behavioral detection can produce false negatives against defenses it
  isn't designed to probe.

The value is in demonstrating *how* automated vulnerability detection works —
crafting payloads, interpreting responses as evidence, mapping to OWASP, and
reporting with remediation — the foundation DAST tooling is built on.

## Next steps (roadmap)

- [ ] Add a crawler to discover endpoints automatically
- [ ] More checks: CSRF, open redirect, command injection, SSRF
- [ ] Authenticated scanning (session handling)
- [ ] Integrate into CI (fail build on new HIGH/CRITICAL) — DAST-in-pipeline
