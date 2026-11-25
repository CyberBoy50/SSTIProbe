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

THE 6 MUST-HAVE FEATURES (PDF) — all in this file:
  1. CLI input for target URL, parameter name and request method
     -> parse_args() + ask_interactive() below (args or [?] prompts)
  2. Baseline request before any payload
     -> fetch_baseline()
  3. Detection payloads, 4 syntax families, distinct multiplication each
     -> PAYLOADS table
  4. Evaluation detection: computed result in response, not payload text
     -> check_evaluation()
  5. Engine fingerprinting with engine-specific markers
     -> fingerprint_engine()
  6. Report saved to a file: parameter, evidence, remediation note
     -> build_report() + main() writes the file

USAGE — two ways, same tool:
  Interactive (like LOCATIONCAT — it asks you):
    python run.py probe
      [?] ENTER TARGET URL: http://127.0.0.1:5000/vuln
      [?] ENTER PARAMETER NAME: name
      [?] ENTER REQUEST METHOD [GET/POST]: GET

  With arguments (for scripts / demo):
    python run.py probe --url http://127.0.0.1:5000/vuln --param name
    python run.py probe --url http://127.0.0.1:5000/vuln --param name --method POST
    python run.py probe --url http://127.0.0.1:5000/vuln --param name --method POST --json
    python run.py probe --url http://127.0.0.1:5000/safe  --param name --output report.txt
"""

import argparse
import sys
from datetime import datetime

import requests

# --- Colours (ANSI: works on Kali/macOS/Windows 10+ terminals) ----------
# colorama is used if installed (it fixes colours on older Windows cmd);
# without it the ANSI codes below still work on modern terminals.
try:
    import colorama

    colorama.init()
except Exception:  # noqa: BLE001 - colour is cosmetic, never fatal
    pass

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = r"""
  ____  ____  _____ ___ ____  ____   ___  ____  _____
 / ___|/ ___||_   _|_ _|  _ \|  _ \ / _ \|  _ \| ____|
 \___ \\___ \  | |  | || |_) | |_) | | | | |_) |  _|
  ___) |___) | | |  | ||  __/|  _ <| |_| |  _ <| |___
 |____/|____/  |_| |___|_|   |_| \_\\___/|_| \_\_____|

              by CyberBoy50
        SSTI DETECTOR  |  LAB ONLY
 ==================================================
"""

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


_BANNER_SHOWN = False


def print_banner():
    """LOCATIONCAT-style banner, printed once at the start."""
    global _BANNER_SHOWN
    if _BANNER_SHOWN:
        return
    _BANNER_SHOWN = True
    print(CYAN + BOLD + BANNER + RESET)


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
    print(f"{CYAN}[1] BASELINE:{RESET} {len(body)} characters  ->  {body[:120]!r}")
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
    print(f"{CYAN}[2] DETECTION:{RESET} 4 syntax families, each with its own multiplication")
    for family, start, end, (a, b, result), (c, d, confirm_result) in PAYLOADS:
        payload = build_payload(start, end, a, b)
        body = send_request(url, param, payload, method, use_json, timeout)
        verdict = check_evaluation(baseline, body, payload, result)
        if verdict == "evaluated":
            colour, mark = RED, "[!]"
        elif verdict == "reflected":
            colour, mark = YELLOW, "[-]"
        else:
            colour, mark = "", "[ ]"
        print(f"  {colour}{mark} [{family}] {payload} = {result} -> {verdict}{RESET}")

        if verdict != "evaluated":
            continue

        # Confirm with a SECOND, different multiplication (PDF Step 5/6).
        # One hit could be a coincidence; two different answers cannot be.
        confirm_payload = build_payload(start, end, c, d)
        confirm_body = send_request(url, param, confirm_payload, method, use_json, timeout)
        confirm_verdict = check_evaluation(baseline, confirm_body, confirm_payload, confirm_result)
        print(f"      {CYAN}[3] CONFIRM:{RESET} {confirm_payload} = {confirm_result} -> {confirm_verdict}")
        if confirm_verdict != "evaluated":
            print("      Not confirmed — skipping (could be a false positive).")
            continue

        engine = fingerprint_engine(url, param, start, end, method, use_json, timeout)
        print(f"      {CYAN}[4] ENGINE:{RESET} {engine}")
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
# FEATURE 1 — CLI input: arguments OR interactive [?] prompts.
# If --url / --param are given, they are used as-is (script mode).
# Anything missing is asked, LOCATIONCAT-style, with a sensible default.
# ---------------------------------------------------------------------------
def ask_interactive(prompt, default=""):
    """Ask one [?] question; Enter on its own takes the default."""
    shown = f"{default}" if default else ""
    answer = input(f"{CYAN}[?]{RESET} {prompt} [{shown}]: ").strip()
    return answer or default


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="SSTIProbe — detect Server-Side Template Injection (lab only, detection payloads only)."
    )
    parser.add_argument("--url", default=None, help="Lab URL, e.g. http://127.0.0.1:5000/vuln")
    parser.add_argument("--param", default=None, help="Parameter name to test, e.g. name")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"],
                        help="Request method (default: GET)")
    parser.add_argument("--json", action="store_true",
                        help="Send POST body as JSON instead of a form (stretch feature)")
    parser.add_argument("--output", default="sstiprobe_report.txt",
                        help="Report file to save (default: sstiprobe_report.txt)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    args = parser.parse_args(argv)

    # Interactive mode: only when URL or parameter were NOT given as
    # arguments. With --url + --param given, nothing is ever asked —
    # the tool runs straight away (script / demo mode).
    if not args.url or not args.param:
        print_banner()
        if not args.url:
            args.url = ask_interactive("ENTER TARGET URL", "http://127.0.0.1:5000/vuln")
        if not args.param:
            args.param = ask_interactive("ENTER PARAMETER NAME", "name")
        method = ask_interactive("ENTER REQUEST METHOD [GET/POST]", "GET").upper()
        args.method = method if method in ("GET", "POST") else "GET"
    return args


def main(argv=None):
    args = parse_args(argv)
    # Banner was already shown in interactive mode; show it in args mode too.
    print_banner()
    print(f"{BOLD}TARGET :{RESET} {args.url}")
    print(f"{BOLD}PARAM  :{RESET} {args.param}")
    print(f"{BOLD}METHOD :{RESET} {args.method}")
    print("-" * 50)
    try:
        baseline = fetch_baseline(args.url, args.param, args.method, args.json, args.timeout)
        findings = probe(args.url, args.param, baseline, args.method, args.json, args.timeout)
    except requests.RequestException as exc:
        print(f"{RED}[!] ERROR: could not reach the lab app: {exc}{RESET}")
        print("Is lab_app.py running?  python run.py lab")
        return 1

    report = build_report(args.url, args.param, args.method, findings)
    print()
    if findings:
        print(f"{RED}{BOLD}[!] VULNERABLE — template injection found in parameter '{args.param}'{RESET}")
    else:
        print(f"{GREEN}{BOLD}[+] NOT VULNERABLE — no template evaluation detected{RESET}")
    print(report)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)
    print(f"{CYAN}[5] REPORT SAVED TO:{RESET} {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
