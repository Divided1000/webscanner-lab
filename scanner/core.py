"""
Scanner core: HTTP client, Finding model, and the report structure that the
individual vulnerability checks (sqli, xss, idor, headers) plug into.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
import requests


@dataclass
class Finding:
    """A single vulnerability the scanner detected."""
    check: str                 # which check produced it
    owasp: str                 # OWASP Top 10 mapping, e.g. "A03:2021 Injection"
    severity: str              # CRITICAL / HIGH / MEDIUM / LOW
    endpoint: str              # where it was found
    evidence: str              # concrete proof (payload + observed signal)
    remediation: str           # how to fix it

    def to_dict(self):
        return asdict(self)


class Scanner:
    """Lightweight HTTP client + findings collector shared by all checks."""

    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.findings: list[Finding] = []

    def get(self, path: str, **kwargs) -> Optional[requests.Response]:
        url = self.base_url + path
        try:
            return self.session.get(url, timeout=self.timeout, **kwargs)
        except requests.RequestException:
            return None

    def report(self, finding: Finding):
        self.findings.append(finding)

    def summary(self) -> dict:
        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {"total": len(self.findings), "by_severity": counts}
