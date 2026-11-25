"""Step 3 test — feed check_evaluation() 3 prepared responses,
one of each kind, and confirm all 3 verdicts. Plus payload-system
tests (tplmap patterns): random ints, context wrapping, header/trailer.
Run:
    ./venv/bin/python test_evaluation.py
"""
import sstiprobe
from sstiprobe import (
    CONTEXTS,
    PAYLOADS,
    build_payload,
    build_wrapped,
    check_evaluation,
    randint_n,
    wrap_context,
)

BASELINE = "Hello SSTIProbeBaseline!"
PAYLOAD = "{{7*7}}"

cases = [
    # (name, test_body, expected verdict)
    ("evaluated", "Hello 49!", "evaluated"),        # engine ran 7*7 = 49
    ("reflected", "Hello {{7*7}}!", "reflected"),   # app just echoed the text
    ("no-change", "Hello Guest!", "no-change"),      # neither 49 nor payload
]

failed = 0
for name, body, expected in cases:
    got = check_evaluation(BASELINE, body, PAYLOAD, 49)
    ok = "PASS" if got == expected else "FAIL"
    if got != expected:
        failed += 1
    print(f"{ok}: {name:10s} -> got {got!r}, expected {expected!r}")

# --- Payload-system tests (pure functions, no network) ---------------------
jinja = PAYLOADS[0]
smarty = PAYLOADS[5]


def check(name, got, want):
    global failed
    ok = "PASS" if got == want else "FAIL"
    if got != want:
        failed += 1
    print(f"{ok}: {name:10s} -> got {got!r}, expected {want!r}")


check("build {{7*7}}", build_payload(jinja, 7, 7), "{{7*7}}")
check("build smarty", build_payload(smarty, 11, 22), "{11}{*x*}{22}")
check("context {{ }}", wrap_context("{{7*7}}", CONTEXTS[1]), "}}{{7*7}}{{")
check("context {% %}", wrap_context("{{7*7}}", CONTEXTS[2]), "%}{{7*7}}{%")
check("context text", wrap_context("{{7*7}}", CONTEXTS[0]), "{{7*7}}")
# randint_n(1) starts at 2 (tplmap: avoid 1*8=8 false positives)
check("randint 1-digit", 2 <= randint_n(1) <= 9, True)
check("randint 2-digit", 10 <= randint_n(2) <= 99, True)
# Header/trailer: expected string must be header + result + trailer.
wp, we = build_wrapped(jinja, 7, 7)
check("wrapped expected", we[10:12] == "49" and len(we) == 10 + 2 + 10, True)
check("wrapped payload", wp.count("{{") == 3, True)

# --- Fingerprint tests (v2.8): monkeypatch send_request, no network. ------
# Jinja2 evaluates {{7*'7'}} and leaves ${7*'7'} untouched; Mako does
# the opposite. The fingerprint must tell them apart.


def _fake_send(jinja_hit, mako_hit):
    def fake(url, param, value, method, use_json, timeout=10):
        if value == "{{7*'7'}}":
            return "Hello 7777777!" if jinja_hit else "Hello {{7*'7'}}!"
        if value == "${7*'7'}":
            return "Hello 7777777!" if mako_hit else "Hello ${7*'7'}!"
        return "Hello Guest!"
    return fake


_orig_send = sstiprobe.send_request
sstiprobe.send_request = _fake_send(True, False)
check("fingerprint Jinja2",
      sstiprobe.fingerprint_engine("http://x", "name", "GET", False),
      "Jinja2 / Twig ({{ }} string-repeat marker 7*'7' = 7777777)")
sstiprobe.send_request = _fake_send(False, True)
check("fingerprint Mako",
      sstiprobe.fingerprint_engine("http://x", "name", "GET", False),
      "Mako (Python string-repeat marker 7*'7' = 7777777)")
sstiprobe.send_request = _fake_send(False, False)
check("fingerprint Unknown",
      sstiprobe.fingerprint_engine("http://x", "name", "GET", False),
      "Unknown template engine")
sstiprobe.send_request = _orig_send

print("All tests passed." if failed == 0 else f"{failed} test(s) FAILED.")
raise SystemExit(1 if failed else 0)
