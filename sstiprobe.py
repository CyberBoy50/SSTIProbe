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

INSTALL — the probe needs NOTHING installed (sqlmap pattern):
  plain Python 3 is enough: it uses requests when installed, otherwise
  the standard library (urllib). Only the LAB needs flask:
    python run.py setup        # venv + requests + flask, first time only
  Or skip setup entirely for the probe:
    python3 sstiprobe.py --url http://127.0.0.1:5000/vuln --param name

USAGE — three ways, same tool:
  Menu (GhostTrack / TraceRecon style — default when run with no args):
    python run.py probe
    python run.py probe --menu
      [ 1] Scan a target (enter URL, parameter, method)
      [ 2] Quick scan: vulnerable lab  /vuln
      [ 3] Quick scan: safe lab  /safe
      [ 4] Run Step 3 test (evaluation check)
      [ 5] Check lab status (is the lab running?)
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
    python run.py probe --batch    # never ask, use defaults (sqlmap style)
    python run.py probe --url http://127.0.0.1:5000/vuln --param name -q  # quiet
"""

import argparse
import os
import random
import sys
import time
from datetime import datetime

# Zero-dependency probe (sqlmap pattern: it works out of the box, no
# install step, because it uses only the Python standard library).
# requests is preferred when installed; otherwise we fall back to
# urllib (stdlib). Only the LAB needs flask (pip install via run.py).
try:
    import requests

    HAVE_REQUESTS = True
except ImportError:  # noqa: BLE001 - requests simply is not installed
    requests = None  # type: ignore[assignment]
    HAVE_REQUESTS = False

VERSION = "2.4"
QUIET = False

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
# STEP 4 — Payload system, upgraded from tplmap / SSTImap (detection only).
#
# What the big tools do (see RESEARCH_CLI_TOOLS.md for the original code):
#  * tplmap utils/rand.py: random ints, not fixed ones. randint_n(1) starts
#    at 2 "to avoid number repetition on evaluation e.g. 1*8=8 creating
#    false positives". randints = 3 random 2-digit ints, generated once
#    per run and reused by every payload, with the expected result computed
#    from the SAME randoms. tplmap Jinja2 test_render is
#    '{{(n1,n2*n3)}}' with expected '(n1, n2*n3)'.
#  * tplmap core/plugin.py _detect_render(): every payload is wrapped in a
#    header + trailer made of a RANDOM 10-digit number, so the tool can
#    check the exact string "header + result + trailer" — proof the number
#    came from evaluation in that exact spot, not from elsewhere on the page.
#  * tplmap set_contexts(): the input is not always in "text context".
#    It may sit inside {{ }}, {% %}, a string, or a comment, so each engine
#    lists contexts with a level (0 = text, 1 = code tag, 5 = if/for/comment)
#    and a prefix/suffix that CLOSES the open tag first, e.g. Jinja2 level 1
#    prefix '%(closure)s}}' covers {{%s}}, '%(closure)s%}' covers {% %s %}.
#    --level picks how deep to test; _generate_contexts() skips levels above it.
#  * tplmap _detect_blind() / plugins/languages/python.py 'blind' action:
#    when nothing is reflected, send a TRUE expression and a FALSE one
#    (test_bool_true "'a'.join('ab') == 'aab'", test_bool_false "True == False")
#    and compare the two responses. Different answer = evaluated (blind).
#  * Smarty test_render: '{r1}{*comment*}{r2}' expected 'r1r2' — the comment
#    is stripped by the parser, proving the tag was parsed, not echoed.
#  * SSTImap plugins/python/jinja2.py: test_render '{{(n1,n2*n3)|e}}',
#    plus a 'render_error' technique that closes the expression differently.
#
# What SSTIProbe copies (all arithmetic-only, lab-only):
#  1. Fixed 7*7-style first test per family (PDF example, demo-friendly).
#  2. Random-pair confirm (tplmap rand pattern) as a THIRD check.
#  3. Header/trailer wrapped confirm (tplmap render pattern).
#  4. Contexts: text (level 0), inside {{ }} and {% %} (level 1),
#     comment block (level 5). --level controls depth, default 1.
#  5. Boolean blind check (tplmap blind pattern) when render finds nothing.
#  6. One extra family per engine: ERB <%= %> and Smarty comment { }.
# NOT copied: evaluate/execute/os-shell/RCE actions. Detection only.
# ---------------------------------------------------------------------------

def randint_n(n):
    """Random n-digit int — tplmap utils/rand.py.
    1-digit starts at 2 to avoid 1*8=8 false positives."""
    range_start = 2 if n == 1 else 10 ** (n - 1)
    return random.randint(range_start, (10 ** n) - 1)


def random_pair():
    """Two random 2-digit ints for a confirm multiplication."""
    return randint_n(2), randint_n(2)


# One entry per syntax family. Each carries a DIFFERENT multiplication, so
# we always know which family produced a hit. "engine" is the likely engine
# for that family (a guess until fingerprinting confirms it).
PAYLOADS = [
    # family, engine guess, start, end, first test, confirm test
    {"family": "double-brace {{ }}", "engine": "Jinja2 / Twig",
     "start": "{{", "end": "}}", "test": (7, 7, 49), "confirm": (7, 8, 56)},
    {"family": "dollar-brace ${ }", "engine": "Mako / FreeMarker",
     "start": "${", "end": "}", "test": (8, 8, 64), "confirm": (8, 9, 72)},
    {"family": "hash-brace #{ }", "engine": "Velocity / FreeMarker",
     "start": "#{", "end": "}", "test": (9, 9, 81), "confirm": (9, 7, 63)},
    {"family": "star-brace *{ }", "engine": "generic",
     "start": "*{", "end": "}", "test": (6, 7, 42), "confirm": (6, 8, 48)},
    {"family": "erb <%= %>", "engine": "ERB (Ruby)",
     "start": "<%=", "end": "%>", "test": (5, 5, 25), "confirm": (5, 6, 30)},
    # Smarty comment test (tplmap smarty.py): {11}{*x*}{22} -> "1122".
    # The comment is stripped only if the tag was parsed.
    {"family": "smarty comment { }", "engine": "Smarty (PHP)", "kind": "comment",
     "test": (11, 22, "1122"), "confirm": (33, 44, "3344")},
]

# Contexts (tplmap set_contexts pattern). Level 0 = plain text context.
# Level 1 = input sits inside an open tag: close it first, inject, reopen.
# Level 5 = comment block: '#}' closes a comment, '{#' reopens it.
CONTEXTS = [
    {"level": 0, "name": "text context", "prefix": "", "suffix": ""},
    {"level": 1, "name": "inside {{ }}", "prefix": "}}", "suffix": "{{"},
    {"level": 1, "name": "inside {% %}", "prefix": "%}", "suffix": "{%"},
    {"level": 5, "name": "comment block", "prefix": "#}", "suffix": "{#"},
]

# STEP 5 — Engine fingerprint markers (detection only, still arithmetic).
# Jinja2 (Python) repeats a string with *: 7*'7' -> 7777777.
# If that exact string appears, the engine behaves like Jinja2.
FINGERPRINT_MARKER = "7777777"


def build_payload(fam, a, b):
    """Make one detection payload for a family, e.g. {{7*7}}.
    Smarty comment family: {11}{*x*}{22} from (11, 22)."""
    if fam.get("kind") == "comment":
        return f"{{{a}}}{{*x*}}{{{b}}}"
    return f"{fam['start']}{a}*{b}{fam['end']}"


def wrap_context(payload, ctx):
    """Wrap a payload in a context's prefix/suffix (tplmap contexts)."""
    return f"{ctx['prefix']}{payload}{ctx['suffix']}"


def build_wrapped(fam, a, b):
    """Header/trailer wrapped payload (tplmap _detect_render pattern).
    Returns (payload, expected_string). The header/trailer are random
    10-digit numbers, so the exact string proves evaluation in place."""
    header, trailer = randint_n(10), randint_n(10)
    start, end = fam["start"], fam["end"]
    payload = f"{start}{header}{end}{start}{a}*{b}{end}{start}{trailer}{end}"
    return payload, f"{header}{a * b}{trailer}"


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
    if QUIET:
        return
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
    """Send one request with `value` in `param`. Returns response text.
    With requests installed it uses requests; without it, plain urllib
    from the standard library — so the probe runs with zero installs."""
    if HAVE_REQUESTS:
        if method == "POST":
            if use_json:
                resp = requests.post(url, json={param: value}, timeout=timeout)
            else:
                resp = requests.post(url, data={param: value}, timeout=timeout)
        else:  # GET
            resp = requests.get(url, params={param: value}, timeout=timeout)
        return resp.text
    # --- urllib fallback (stdlib only) -------------------------------------
    import json as _json
    import urllib.error
    import urllib.parse
    import urllib.request

    if method == "POST":
        if use_json:
            data = _json.dumps({param: value}).encode()
            req = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json"}, method="POST")
        else:
            data = urllib.parse.urlencode({param: value}).encode()
            req = urllib.request.Request(url, data=data, method="POST")
    else:
        sep_char = "&" if "?" in url else "?"
        req = urllib.request.Request(
            url + sep_char + urllib.parse.urlencode({param: value}))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:  # e.g. 500 template error page
        return exc.read().decode("utf-8", errors="replace")


def lab_is_running(timeout=3):
    """Quick check: is the lab answering on 127.0.0.1:5000? (stdlib only)"""
    import urllib.request

    try:
        with urllib.request.urlopen("http://127.0.0.1:5000/", timeout=timeout) as resp:
            return resp.status == 200
    except Exception:  # noqa: BLE001 - any failure means "not running"
        return False


def fetch_baseline(url, param, method, use_json, timeout=10):
    """Baseline = response to a harmless value ('SSTIProbeBaseline')."""
    body = send_request(url, param, "SSTIProbeBaseline", method, use_json, timeout)
    if not QUIET:
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
# STEP 2 + 4 + 5 — Probe every family in every context, confirm, fingerprint.
# tplmap detect(): render technique first ('R'), blind ('T') only if render
# found nothing. _generate_contexts() skips contexts above --level.
# ---------------------------------------------------------------------------
def check_blind(url, param, baseline, method, use_json, timeout=10):
    """Boolean blind check (tplmap _detect_blind pattern, arithmetic only).
    Sends a TRUE expression and a FALSE one with NO braces — the input
    lands in code context (lab /blind puts it in {% if ... %}).
    Different responses for true vs false = the engine evaluated it.
    Returns a finding dict, or None."""
    true_expr, false_expr = "7*7==49", "7*7==50"
    true_body = send_request(url, param, true_expr, method, use_json, timeout)
    false_body = send_request(url, param, false_expr, method, use_json, timeout)
    # Blind means EVALUATED but not printed: the expressions themselves
    # must NOT appear in the responses. If they do, the app merely
    # reflected different inputs — that is not blind evaluation
    # (this is what made /safe look "blind" before the fix).
    if (true_body != false_body and true_body != baseline
            and true_expr not in true_body and false_expr not in false_body):
        return {
            "family": "boolean blind (no braces)",
            "payload": true_expr,
            "expected_result": "response differs for true vs false",
            "confirm_payload": false_expr,
            "confirm_result": "different response",
            "engine": "Unknown template engine (blind — no output to fingerprint)",
            "evidence": f"true -> {true_body[:120]!r} | false -> {false_body[:120]!r}",
            "context": "code context (blind)",
            "technique": "boolean blind",
        }
    return None


def probe(url, param, baseline, method, use_json, timeout=10, level=1, technique="RT"):
    """Run all families in all contexts up to --level. Returns findings."""
    findings = []
    if not QUIET:
        print(f"{CYAN}[2] DETECTION:{RESET} {len(PAYLOADS)} syntax families, "
              f"contexts up to level {level} (tplmap pattern)")
    for fam in PAYLOADS:
        family = fam["family"]
        a, b, result = fam["test"]
        c, d, confirm_result = fam["confirm"]
        hit = None
        # Context loop (tplmap _generate_contexts): text first, then code.
        for ctx in CONTEXTS:
            if ctx["level"] > level:
                continue
            payload = wrap_context(build_payload(fam, a, b), ctx)
            body = send_request(url, param, payload, method, use_json, timeout)
            verdict = check_evaluation(baseline, body, payload, result)
            if verdict == "evaluated":
                colour, mark = RED, "[!]"
            elif verdict == "reflected":
                colour, mark = YELLOW, "[-]"
            else:
                colour, mark = "", "[ ]"
            if not QUIET:
                print(f"  {colour}{mark} [{family}] [{ctx['name']}] {payload} = {result} -> {verdict}{RESET}")
            if verdict == "evaluated":
                hit = {"ctx": ctx, "payload": payload, "body": body}
                break
        if not hit:
            continue

        # Confirm with a SECOND, different multiplication (PDF Step 5/6).
        # One hit could be a coincidence; two different answers cannot be.
        confirm_payload = wrap_context(build_payload(fam, c, d), hit["ctx"])
        confirm_body = send_request(url, param, confirm_payload, method, use_json, timeout)
        confirm_verdict = check_evaluation(baseline, confirm_body, confirm_payload, confirm_result)
        if not QUIET:
            print(f"      {CYAN}[3] CONFIRM:{RESET} {confirm_payload} = {confirm_result} -> {confirm_verdict}")
        if confirm_verdict != "evaluated":
            if not QUIET:
                print("      Not confirmed — skipping (could be a false positive).")
            continue

        # [3a] Random-pair confirm (tplmap rand pattern): fresh random
        # numbers every run, expected computed from the same randoms.
        ra, rb = random_pair()
        rand_payload = wrap_context(build_payload(fam, ra, rb), hit["ctx"])
        rand_body = send_request(url, param, rand_payload, method, use_json, timeout)
        rand_verdict = check_evaluation(baseline, rand_body, rand_payload, ra * rb)
        if not QUIET:
            print(f"      {CYAN}[3a] RANDOM CONFIRM:{RESET} {rand_payload} = {ra * rb} -> {rand_verdict}")
        if rand_verdict != "evaluated":
            if not QUIET:
                print("      Random confirm failed — skipping (could be a false positive).")
            continue

        # [3b] Header/trailer wrapped confirm (tplmap _detect_render):
        # random 10-digit markers around the result prove evaluation in place.
        if fam.get("kind") != "comment":
            wrapped_payload, wrapped_expected = build_wrapped(fam, a, b)
            wrapped_payload = wrap_context(wrapped_payload, hit["ctx"])
            wrapped_body = send_request(url, param, wrapped_payload, method, use_json, timeout)
            wrapped_ok = wrapped_expected in wrapped_body and wrapped_expected not in baseline
            if not QUIET:
                print(f"      {CYAN}[3b] WRAPPED CONFIRM:{RESET} header+{a}*{b}+trailer -> "
                      f"{'evaluated' if wrapped_ok else 'not confirmed'}")
            if not wrapped_ok:
                if not QUIET:
                    print("      Wrapped confirm failed — skipping (could be a false positive).")
                continue

        engine = fingerprint_engine(url, param, fam.get("start", ""), fam.get("end", ""), method, use_json, timeout)
        if engine.startswith("Unknown"):
            engine = f"Likely {fam['engine']} (family guess — fingerprint inconclusive)"
        if not QUIET:
            print(f"      {CYAN}[4] ENGINE:{RESET} {engine}")
        findings.append({
            "family": family,
            "payload": hit["payload"],
            "expected_result": result,
            "confirm_payload": confirm_payload,
            "confirm_result": confirm_result,
            "engine": engine,
            "evidence": hit["body"][:300],
            "context": hit["ctx"]["name"],
            "technique": "render",
        })

    # Blind technique (tplmap 'T'): only if render found nothing.
    if not findings and "T" in technique:
        if not QUIET:
            print(f"{CYAN}[2b] BLIND:{RESET} render found nothing — trying boolean blind (true vs false)")
        blind = check_blind(url, param, baseline, method, use_json, timeout)
        if blind:
            if not QUIET:
                print(f"  {RED}[!] [boolean blind] 7*7==49 vs 7*7==50 -> responses differ -> evaluated{RESET}")
            findings.append(blind)
        elif not QUIET:
            print("  [ ] [boolean blind] responses identical — no blind evaluation")
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
            "safe in every way — only that these 6 families did not",
            "evaluate arithmetic in this parameter (render or blind).",
        ]
    else:
        lines.append(f"Result: VULNERABLE — {len(findings)} syntax family/families evaluated input")
        for f in findings:
            lines += [
                "",
                f"Vulnerable parameter: {param}",
                f"Syntax family: {f['family']}",
                f"Context: {f.get('context', 'text context')}",
                f"Technique: {f.get('technique', 'render')}",
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
    parser.add_argument("--level", type=int, default=1, choices=[0, 1, 5],
                        help="Context depth, tplmap style: 0=text only, 1=+code tags (default), 5=+comment blocks")
    parser.add_argument("--technique", default="RT", choices=["R", "T", "RT"],
                        help="Technique, tplmap style: R=render, T=boolean blind, RT=both (default)")
    parser.add_argument("--batch", action="store_true",
                        help="Never ask anything; use defaults (sqlmap --batch pattern)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Quiet mode: only the verdict + report path (Gobuster -q pattern)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable coloured output (like sqlmap --disable-coloring)")
    parser.add_argument("--version", action="version",
                        version=f"SSTIProbe {VERSION} by CyberBoy50")
    args = parser.parse_args(argv)

    if args.no_color:
        disable_colours()
    global QUIET
    QUIET = args.quiet
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
    (5, "Check lab status (is the lab running?)", "lab"),
    (0, "Exit", None),
]


def lab_status():
    """Menu option 5: is the lab answering? Tell the user how to start it."""
    header("LAB STATUS")
    if lab_is_running():
        ok("Lab is running at http://127.0.0.1:5000")
        info("Endpoints", "/vuln  /vuln-dollar  /safe  /blind")
    else:
        err("Lab is NOT running.")
        print("  Start it in a SECOND terminal:")
        print("    python run.py lab")
        print("  Then come back here and pick option 1, 2 or 3.")
    return 0


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
    if not QUIET:
        header("SCAN")
        # Gobuster-style config block, now as aligned info() fields (TraceRecon).
        info("Target", args.url)
        info("Parameter", args.param)
        info("Method", args.method)
        info("Level", args.level)
        info("Technique", args.technique)
        info("Output", args.output)
        sep()
    try:
        if not QUIET:
            warn("Querying target …")
        baseline = fetch_baseline(args.url, args.param, args.method, args.json, args.timeout)
        findings = probe(args.url, args.param, baseline, args.method, args.json,
                         args.timeout, level=args.level, technique=args.technique)
    except Exception as exc:  # noqa: BLE001 - typed below when requests exists
        if HAVE_REQUESTS and isinstance(exc, requests.exceptions.Timeout):
            err("Request timed out. Is the lab app running?  python run.py lab")
            return 1
        if HAVE_REQUESTS and isinstance(exc, requests.exceptions.ConnectionError):
            err(f"Could not connect to {args.url}. Is the lab app running?  python run.py lab")
            return 1
        err(f"Could not reach the lab app: {exc}")
        print("Is lab_app.py running?  python run.py lab")
        return 1

    report = build_report(args.url, args.param, args.method, findings)
    print()
    if findings:
        print(f"{RED}{BOLD}[!] VULNERABLE — template injection found in parameter '{args.param}'{RESET}")
    else:
        print(f"{GREEN}{BOLD}[+] NOT VULNERABLE — no template evaluation detected{RESET}")
    # Quiet mode (-q): only verdict + report path, no full report on screen.
    if not QUIET:
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
            elif choice == "5":
                lab_status()
            else:
                err("Please input a number from the menu (0-5).")
                time.sleep(1)
                continue
        except ValueError:
            err("Please input a number from the menu (0-5).")
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
        # --batch (sqlmap pattern): never ask, never show the menu —
        # missing values become the defaults and the scan runs straight away.
        # --quiet implies the same (a scripted run has nothing to ask).
        if args.batch or args.quiet:
            args.url = args.url or "http://127.0.0.1:5000/vuln"
            args.param = args.param or "name"
            return do_scan(args)
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
