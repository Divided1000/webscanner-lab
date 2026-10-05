"""
CLI entry point for the web vulnerability scanner.

Usage:
    python -m scanner http://127.0.0.1:8000
    python -m scanner http://127.0.0.1:8000 --json report.json

ETHICAL USE: only scan targets you own or are explicitly authorized to test.
"""

import argparse
import json
import sys

from .core import Scanner
from .checks import ALL_CHECKS
from .config import DEFAULT_CONFIG


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Minimal OWASP web vulnerability scanner (learning tool).")
    parser.add_argument("target", help="Base URL of the target you own/are authorized to test")
    parser.add_argument("--json", metavar="FILE", help="Also write findings to a JSON file")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="Exit non-zero if any findings are reported (useful in CI/DAST pipelines)")
    args = parser.parse_args(argv)

    cfg = DEFAULT_CONFIG

    print(f"\n  web vulnerability scanner  ->  target: {args.target}")
    print("  " + "-" * 56)
    print("  Reminder: only scan systems you own or are authorized to test.\n")

    s = Scanner(args.target)

    # Confirm the target is reachable before scanning.
    if s.get("/") is None:
        print(f"  [!] Target {args.target} is not reachable. Is it running?\n")
        return 2

    for check in ALL_CHECKS:
        check(s, cfg)

    findings = sorted(s.findings, key=lambda f: SEV_ORDER.get(f.severity, 9))

    if not findings:
        print("  No vulnerabilities detected by the current checks.\n")
    else:
        for f in findings:
            print(f"  [{f.severity}] {f.owasp}")
            print(f"      check:       {f.check}")
            print(f"      endpoint:    {f.endpoint}")
            print(f"      evidence:    {f.evidence}")
            print(f"      remediation: {f.remediation}\n")

    summary = s.summary()
    print("  " + "-" * 56)
    print(f"  Summary: {summary['total']} finding(s) -> {summary['by_severity']}\n")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"target": args.target, "summary": summary,
                       "findings": [f.to_dict() for f in findings]}, fh, indent=2)
        print(f"  JSON report written to {args.json}\n")

    # CI/DAST pipelines can gate a build on findings.
    if args.fail_on_findings and findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
