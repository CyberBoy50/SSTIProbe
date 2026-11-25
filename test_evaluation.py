"""Step 3 test — feed check_evaluation() 3 prepared responses,
one of each kind, and confirm all 3 verdicts. Run:
    ./venv/bin/python test_evaluation.py
"""
from sstiprobe import check_evaluation

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

print("All 3 Step-3 tests passed." if failed == 0 else f"{failed} test(s) FAILED.")
raise SystemExit(1 if failed else 0)
