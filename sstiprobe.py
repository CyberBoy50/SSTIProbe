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

USAGE — three ways, same tool:
  Menu (GhostTrack / TraceRecon style — default when run with no args):
    python run.py probe
    python run.py probe --menu
      [ 1] Scan a target (enter URL, parameter, method)
      [ 2] Quick scan: vulnerable lab  /vuln
      [ 3] Quick scan: safe lab  /safe
      [ 4] Run Step 3 test (evaluation check)
      [ 0] Exit
      [ ? ] Select option :

  Interactive prompts (option 1 in the menu asks the same questions):
    python run.py probe -i        # opens the menu (SSTImap -i style)
      [?] ENTER TARGET URL: http://127.0.0.1:5000/vuln
      [?] ENTER PARAMETER NAME: name
      [?] ENTER REQUEST METHOD [GET/POST]: GET

  With arguments (for scripts / demo):
    python run.py probe --url http://127.0.0.1:5000/vuln --param name
    python run.py probe --url http://127.0.0.1:5000/vuln --param name --method POST
    python run.py probe --url http://127.0.0.1:5000/vuln --param name --method POST --json
    python run.py probe --url http://127.0.0.1:5000/safe  --param name --output report.txt
    python run.py probe --version
    python run.py probe --url http://127.0.0.1:5000/vuln --param name --no-color
"""

import argparse
import os
import sys
import time
from datetime import datetime

import requests

VERSION = "2.2"

# --- Colours (ANSI: works on Kali/macOS/Windows 10+ terminals) ----------
# colorama is used if installed (it fixes colours on older Windows cmd);
# without it the ANSI codes below still work on modern terminals.
try:
    import colorama

    colorama.init()
except Exception:  # noqa: BLE001 - colour is cosmetic, never fatal
    pass

# --- Colours, TraceRecon style: one class, short names ------------------
# GhostTrack does the same with plain variables:
#   Bl='\033[30m' Re='\033[1;31m' Gr='\033[1;32m' Ye='\033[1;33m'
#   Blu='\033[1;34m' Mage='\033[1;35m' Cy='\033[1;36m' Wh='\033[1;37m'
# TraceRecon puts them in a class C (RST/BLD/RED/GRN/YEL/BLU/MAG/CYN/WHT).
class C:
    RST = "\033[0m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[1;31m"
    GRN = "\033[1;32m"
    YEL = "\033[1;33m"
    BLU = "\033[1;34m"
    MAG = "\033[1;35m"
    CYN = "\033[1;36m"
    WHT = "\033[1;37m"


RED = C.RED
GREEN = C.GRN
YELLOW = C.YEL
CYAN = C.CYN
BOLD = C.BLD
RESET = C.RST


def clear():
    """Clear the screen — GhostTrack / TraceRecon pattern.
    Windows: cls, macOS/Linux: clear."""
    os.system("cls" if os.name == "nt" else "clear")


def sep(color=C.GRN, char="─", width=58):
    """A rule line, TraceRecon style: sep(C.GRN, '─') / sep(C.GRN, '═')."""
    print(f"{color}{char * width}{C.RST}")


def header(title, color=C.GRN):
    """A titled section header with rule lines above and below."""
    sep(color)
    print(f"{color} {title}{C.RST}")
    sep(color)


def ok(msg):
    """[+] success line: ' [+] message' — white brackets, green plus."""
    print(f" {C.WHT}[{C.GRN}+{C.WHT}]{C.RST} {msg}")


def warn(msg):
    """[!] warning line, yellow."""
    print(f" {C.WHT}[{C.YEL}!{C.WHT}]{C.RST} {C.YEL}{msg}{C.RST}")


def err(msg):
    """[✗] error line, red."""
    print(f" {C.WHT}[{C.RED}x{C.WHT}]{C.RST} {C.RED}{msg}{C.RST}")


def info(label, value, label_color=C.WHT, val_color=C.GRN):
    """One aligned field — TraceRecon style:
    ' Target URL            : http://...' (label 22 chars, white; value green)."""
    print(f" {label_color}{label:<22}{C.RST}: {val_color}{value}{C.RST}")

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


def disable_colours():
    """Turn all colours off (--no-color, like sqlmap / SSTImap / Gobuster)."""
    global RED, GREEN, YELLOW, CYAN, BOLD, RESET
    RED = GREEN = YELLOW = CYAN = BOLD = RESET = ""
    for attr in ("RST", "BLD", "DIM", "RED", "GRN", "YEL", "BLU", "MAG", "CYN", "WHT"):
        setattr(C, attr, "")


def print_banner():
    """Startup sequence (research consensus): banner, version, author,
    legal disclaimer — like SSTImap / sqlmap."""
    global _BANNER_SHOWN
    if _BANNER_SHOWN:
        return
    _BANNER_SHOWN = True
    print(CYAN + BOLD + BANNER + RESET)
    print(f"[*] Version: {VERSION}")
    print("[*] Author: CyberBoy50")
    print(
        "[!] LEGAL DISCLAIMER: Lab only — only test systems you own "
        "or have written permission to test."
    )
    # TraceRecon-style box under the banner.
    print(f"{C.GRN}")
    print("┌──────────────────────────────────────────────────┐")
    print(f"│ SSTI Detector v{VERSION} — detection only        │")
    print("│ For authorized lab use only                      │")
    print("└──────────────────────────────────────────────────┘")
    print(f"{C.RST}", end="")


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
    parser.add_argument("-i", "--interactive", action="store_true",
                        help="Interactive mode: show the menu (like SSTImap -i)")
    parser.add_argument("--menu", action="store_true",
                        help="Show the numbered menu (GhostTrack / TraceRecon style)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable coloured output (like sqlmap --disable-coloring)")
    parser.add_argument("--version", action="version",
                        version=f"SSTIProbe {VERSION} by CyberBoy50")
    args = parser.parse_args(argv)

    if args.no_color:
        disable_colours()
    return args


# ---------------------------------------------------------------------------
# MENU MODE — GhostTrack / TraceRecon pattern, adapted to SSTIProbe.
# GhostTrack keeps a list of options as dicts {num, text, func} and builds
# the menu text with option_text(); TraceRecon keeps tuples
# (num, label, key, colour) and show_menu() prints "[ 1] Label" bullets
# between '═' rule lines, then asks "[ ? ] Select option : ".
# After each option GhostTrack does: input("Press enter to continue")
# and loops back to main(); Ctrl+C prints "[ ! ] Exit".
# ---------------------------------------------------------------------------
MENU_OPTIONS = [
    (1, "Scan a target (enter URL, parameter, method)", "scan"),
    (2, "Quick scan: vulnerable lab  /vuln", "vuln"),
    (3, "Quick scan: safe lab  /safe", "safe"),
    (4, "Run Step 3 test (evaluation check)", "test"),
    (0, "Exit", None),
]


def show_menu():
    """Clear screen, banner, then the numbered menu."""
    clear()
    print_banner()
    sep(C.GRN, "═")
    for num, label, _key in MENU_OPTIONS:
        print(f" {C.GRN}[{C.WHT}{num:>2}{C.GRN}]{C.RST} {C.WHT}{label}{C.RST}")
    sep(C.GRN, "═")


def run_step3_test():
    """Step 3 test, run from the menu: the same 3 cases as test_evaluation.py."""
    header("STEP 3 TEST — evaluation check")
    baseline = "Hello SSTIProbeBaseline!"
    payload = "{{7*7}}"
    cases = [
        ("evaluated", "Hello 49!", "evaluated"),
        ("reflected", "Hello {{7*7}}!", "reflected"),
        ("no-change", "Hello Guest!", "no-change"),
    ]
    passed = 0
    for name, body, want in cases:
        got = check_evaluation(baseline, body, payload, 49)
        status = "PASS" if got == want else "FAIL"
        if got == want:
            passed += 1
            ok(f"{status}: {name:<10} -> got '{got}', expected '{want}'")
        else:
            err(f"{status}: {name:<10} -> got '{got}', expected '{want}'")
    if passed == len(cases):
        ok(f"All {passed} Step-3 tests passed.")
    else:
        err(f"{passed}/{len(cases)} Step-3 tests passed.")
    return 0


def do_scan(args):
    """One full scan: config block, baseline, detection, report."""
    header("SCAN")
    # Gobuster-style config block, now as aligned info() fields (TraceRecon).
    info("Target", args.url)
    info("Parameter", args.param)
    info("Method", args.method)
    info("Output", args.output)
    sep()
    try:
        warn("Querying target …")
        baseline = fetch_baseline(args.url, args.param, args.method, args.json, args.timeout)
        findings = probe(args.url, args.param, baseline, args.method, args.json, args.timeout)
    except requests.exceptions.Timeout:
        err("Request timed out. Is the lab app running?  python run.py lab")
        return 1
    except requests.exceptions.ConnectionError:
        err(f"Could not connect to {args.url}. Is the lab app running?  python run.py lab")
        return 1
    except requests.RequestException as exc:
        err(f"Could not reach the lab app: {exc}")
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
    ok(f"REPORT SAVED TO: {args.output}")
    return 0


def menu_loop(args):
    """Numbered menu loop. Returns 0 on clean exit."""
    while True:
        show_menu()
        try:
            choice = input(f"{C.WHT}\n [ ? ] {C.GRN}Select option{C.WHT} : {C.GRN}").strip()
            print(C.RST, end="")
            if choice == "0":
                print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
                return 0
            if choice == "1":
                args.url = ask_interactive("ENTER TARGET URL", args.url or "http://127.0.0.1:5000/vuln")
                args.param = ask_interactive("ENTER PARAMETER NAME", args.param or "name")
                method = ask_interactive("ENTER REQUEST METHOD [GET/POST]", args.method).upper()
                args.method = method if method in ("GET", "POST") else "GET"
                do_scan(args)
            elif choice == "2":
                args.url, args.param, args.method = "http://127.0.0.1:5000/vuln", "name", "GET"
                do_scan(args)
            elif choice == "3":
                args.url, args.param, args.method = "http://127.0.0.1:5000/safe", "name", "GET"
                do_scan(args)
            elif choice == "4":
                run_step3_test()
            else:
                err("Please input a number from the menu (0-4).")
                time.sleep(1)
                continue
        except ValueError:
            err("Please input a number from the menu (0-4).")
            time.sleep(1)
            continue
        except KeyboardInterrupt:
            print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
            return 0
        # GhostTrack pattern: pause, then loop back to the menu.
        input(f"\n{C.WHT}[ {C.GRN}+ {C.WHT}] {C.GRN}Press enter to continue{C.RST}")
    return 0


def main(argv=None):
    args = parse_args(argv)
    try:
        # Menu mode: --menu / -i, or no arguments at all (like GhostTrack,
        # which has no args — it always opens its menu).
        if args.menu or args.interactive or (not args.url and not args.param):
            return menu_loop(args)
        # Args given but something missing: ask only for the missing part.
        print_banner()
        if not args.url:
            args.url = ask_interactive("ENTER TARGET URL", "http://127.0.0.1:5000/vuln")
        if not args.param:
            args.param = ask_interactive("ENTER PARAMETER NAME", "name")
        return do_scan(args)
    except KeyboardInterrupt:
        print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
