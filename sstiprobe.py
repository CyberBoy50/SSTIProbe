#!/usr/bin/env python3
"""
SSTIProbe — Server-Side Template Injection Tester (detection only)
PNY Trainings, Web Security — Final Project, Jahanzaib Yosuf
Deadline: Tuesday, 25 November 2026

WHAT IT DOES
  You give it a lab URL + a parameter name. It sends harmless
  arithmetic payloads (e.g. {{7*7}}) in 4 template syntax families
  and checks whether the response contains the COMPUTED answer (49).
  If yes, it fingerprints the engine, confirms with a second
  multiplication, and saves a report. No exploitation payloads,
  ever. Lab only — only test systems you own.

HOW DETECTION WORKS (the idea in one line)
  A template engine EVALUATES {{7*7}} to 49. A safe app just
  PRINTS "{{7*7}}" back as text. So: 49 in the response = evaluated.

USAGE
  python sstiprobe.py --url http://127.0.0.1:5000/vuln --param name
  python sstiprobe.py --url http://127.0.0.1:5000/vuln --param name --method POST
  python sstiprobe.py --url http://127.0.0.1:5000/vuln --param name --method POST --json
  python sstiprobe.py --url http://127.0.0.1:5000/safe  --param name --output report.txt
"""

import argparse
import sys
from datetime import datetime

import requests

# ---------------------------------------------------------------------------
# STEP 4 — One payload table drives all 4 syntax families.
# Each family carries a DIFFERENT multiplication, so we always know
# which family produced a hit. (start, end) = the family's braces.
# ---------------------------------------------------------------------------
PAYLOADS = [
    # family,      start, end,  first test (a*b=result), confirm test
    ("double-brace {{ }}", "{{", "}}", (7, 7, 49),  (7, 8, 56)),
    ("dollar-brace ${ }",  "${", "}",  (8, 8, 64),  (8, 9, 72)),
    ("hash-brace #{ }",    "#{", "}",  (9, 9, 81),  (9, 7, 63)),
    ("star-brace *{ }",    "*{", "}",  (6, 7, 42),  (6, 8, 48)),
]

# STEP 5 — Engine fingerprint markers (detection only, still arithmetic).
# Jinja2 (Python) repeats a string with *: 7*'7' -> 7777777.
# If that exact string appears, the engine behaves like Jinja2.
FINGERPRINT_MARKER = "7777777"


def build_payload(start, end, a, b):
    """Make one detection payload, e.g. {{7*7}} from ('{{','}}',7,7)."""
    return f"{start}{a}*{b}{end}"


# ---------------------------------------------------------------------------
# STEP 1 — Fetch the baseline: the normal response, before any payload.
# We need it so we can tell "the payload changed the page" apart from
# "the page already looked like that".
# ---------------------------------------------------------------------------
def send_request(url, param, value, method, use_json, timeout=10):
    """Send one request with `value` in `param`. Returns response text."""
    if method == "POST":
        if use_json:
            resp = requests.post(url, json={param: value}, timeout=timeout)
        else:
            resp = requests.post(url, data={param: value}, timeout=timeout)
    else:  # GET
        resp = requests.get(url, params={param: value}, timeout=timeout)
    return resp.text


def fetch_baseline(url, param, method, use_json, timeout=10):
    """Baseline = response to a harmless value ('SSTIProbeBaseline')."""
    body = send_request(url, param, "SSTIProbeBaseline", method, use_json, timeout)
    print(f"[Step 1] Baseline: {len(body)} characters")
    print(f"          {body[:120]!r}")
    return body


# ---------------------------------------------------------------------------
# STEP 3 — The evaluation check. Three possible verdicts:
#   evaluated  -> computed result IS in the response, payload text is NOT
#                 (the engine ran the maths — this is SSTI)
#   reflected  -> payload text IS in the response, result is NOT
#                 (the app just echoed our input back — not SSTI)
#   no-change  -> neither result nor payload appears
# ---------------------------------------------------------------------------
def check_evaluation(baseline, test_body, payload, expected_result):
    """Decide evaluated / reflected / no-change from baseline + test."""
    result = str(expected_result)
    result_is_new = result in test_body and result not in baseline
    if result_is_new and payload not in test_body:
        return "evaluated"
    if payload in test_body:
        return "reflected"
    return "no-change"


# ---------------------------------------------------------------------------
# STEP 5 — Fingerprinting: only called AFTER evaluation is confirmed.
# Sends 7*'7' in the same family's braces. Jinja2 gives 7777777.
# ---------------------------------------------------------------------------
def fingerprint_engine(url, param, start, end, method, use_json, timeout=10):
    """Return the engine name, or 'Unknown' if no marker matches."""
    marker_payload = f"{start}7*'7'{end}"
    body = send_request(url, param, marker_payload, method, use_json, timeout)
    if FINGERPRINT_MARKER in body:
        return "Jinja2 (Python string-repeat marker 7*'7' = 7777777)"
    return "Unknown template engine"


# ---------------------------------------------------------------------------
# STEP 2 + 4 + 5 — Probe every family, confirm, fingerprint.
# ---------------------------------------------------------------------------
def probe(url, param, baseline, method, use_json, timeout=10):
    """Run all families. Returns a list of confirmed findings."""
    findings = []
    for family, start, end, (a, b, result), (c, d, confirm_result) in PAYLOADS:
        payload = build_payload(start, end, a, b)
        body = send_request(url, param, payload, method, use_json, timeout)
        verdict = check_evaluation(baseline, body, payload, result)
        print(f"[{family}] payload {payload} -> {verdict}")

        if verdict != "evaluated":
            continue

        # Confirm with a SECOND, different multiplication (PDF Step 5/6).
        # One hit could be a coincidence; two different answers cannot be.
        confirm_payload = build_payload(start, end, c, d)
        confirm_body = send_request(url, param, confirm_payload, method, use_json, timeout)
        confirm_verdict = check_evaluation(baseline, confirm_body, confirm_payload, confirm_result)
        print(f"  Confirm: payload {confirm_payload} -> {confirm_verdict}")
        if confirm_verdict != "evaluated":
            print("  Not confirmed — skipping (could be a false positive).")
            continue

        engine = fingerprint_engine(url, param, start, end, method, use_json, timeout)
        print(f"  Engine fingerprinted: {engine}")
        findings.append({
            "family": family,
            "payload": payload,
            "expected_result": result,
            "confirm_payload": confirm_payload,
            "confirm_result": confirm_result,
            "engine": engine,
            "evidence": body[:300],
        })
    return findings


# ---------------------------------------------------------------------------
# STEP 6 — Report: print it AND save it to a file.
# ---------------------------------------------------------------------------
REMEDIATION = (
    "Never render user input as a template. Pass it as a VARIABLE "
    "(e.g. render_template_string('Hello {{ name }}!', name=user_input)) "
    "so the engine prints it instead of evaluating it. "
    "If a template must be built from input, use a sandboxed engine "
    "and an allow-list of safe values."
)


def build_report(url, param, method, findings):
    """Build the full report text."""
    lines = [
        "SSTIProbe Report",
        f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Target URL: {url}",
        f"Parameter: {param}",
        f"Method: {method}",
        "",
    ]
    if not findings:
        lines += [
            "Result: NOT VULNERABLE (no template evaluation detected)",
            "No payload was evaluated. This does not prove the app is",
            "safe in every way — only that these 4 families did not",
            "evaluate arithmetic in this parameter.",
        ]
    else:
        lines.append(f"Result: VULNERABLE — {len(findings)} syntax family/families evaluated input")
        for f in findings:
            lines += [
                "",
                f"Vulnerable parameter: {param}",
                f"Syntax family: {f['family']}",
                f"Engine: {f['engine']}",
                f"Detection payload: {f['payload']}  -> computed {f['expected_result']}",
                f"Confirmation payload: {f['confirm_payload']}  -> computed {f['confirm_result']}",
                f"Evidence (response snippet): {f['evidence']!r}",
            ]
        lines += ["", f"Remediation: {REMEDIATION}"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# STEP 6 — CLI arguments (argparse).
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="SSTIProbe — detect Server-Side Template Injection (lab only, detection payloads only)."
    )
    parser.add_argument("--url", required=True, help="Lab URL, e.g. http://127.0.0.1:5000/vuln")
    parser.add_argument("--param", required=True, help="Parameter name to test, e.g. name")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"],
                        help="Request method (default: GET)")
    parser.add_argument("--json", action="store_true",
                        help="Send POST body as JSON instead of a form (stretch feature)")
    parser.add_argument("--output", default="sstiprobe_report.txt",
                        help="Report file to save (default: sstiprobe_report.txt)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    print(f"SSTIProbe — testing {args.url}  param={args.param}  method={args.method}")
    try:
        baseline = fetch_baseline(args.url, args.param, args.method, args.json, args.timeout)
        findings = probe(args.url, args.param, baseline, args.method, args.json, args.timeout)
    except requests.RequestException as exc:
        print(f"ERROR: could not reach the lab app: {exc}")
        print("Is lab_app.py running?  python run.py lab")
        return 1

    report = build_report(args.url, args.param, args.method, findings)
    print("\n" + report)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)
    print(f"Report saved to: {args.output}")
    return 0 if not findings else 0  # exit 0 either way; the report is the result


if __name__ == "__main__":
    sys.exit(main())
