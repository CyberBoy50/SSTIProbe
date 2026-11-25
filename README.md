# SSTIProbe — Server-Side Template Injection Tester

**Student:** Jahanzaib Yosuf · **Track:** Web Security · **Instructor:** Abdul Mannan
**Course:** PNY Trainings, Cyber Security Department · **Deadline:** 25 November 2026

A Python command-line tool that **detects** Server-Side Template Injection (SSTI)
using harmless arithmetic only — never exploitation payloads. Lab only.

## How detection works

A template engine **evaluates** `{{7*7}}` to `49`. A safe app just **prints**
`{{7*7}}` back as text. So:

| Response contains | Verdict |
|---|---|
| `49`, but not `{{7*7}}` | **evaluated** — SSTI confirmed |
| `{{7*7}}`, but not `49` | **reflected** — echoed, not evaluated |
| neither | **no-change** |

A finding is only reported after a **second, different** multiplication
(e.g. `{{7*8}}` → `56`) also evaluates. Then the engine is fingerprinted
with `7*'7'` → `7777777` (Jinja2 string-repeat marker).

## Requirements

- **Python 3.10+** — the only system requirement. Check with `python --version`
  (Windows) or `python3 --version` (macOS / Linux).
- **Python packages** (in `requirements.txt`, installed automatically by `run.py`):
  - `requests>=2.31` — sending the test requests
  - `flask>=3.0` — the lab app only (`lab_app.py`); the tool itself needs just `requests`
- **Internet** — only for the first-time install of those two packages.
- **No other tools** — no database, no Docker, no extra services.

## Install

```bash
git clone https://github.com/CyberBoy50/SSTIProbe.git
cd SSTIProbe
python run.py setup     # Windows: python, macOS/Linux: python3
```

- **Windows 11 / 10:** install Python from
  [python.org/downloads](https://www.python.org/downloads/) and tick
  **"Add python.exe to PATH"**. If `python` is not recognised, use `py`.
- **macOS:** install Python from python.org, or `brew install python`.
  Then `python3 run.py setup`.
- **Kali Linux:** Python is pre-installed, but the venv package is often
  missing — run this first:
  ```bash
  sudo apt update && sudo apt install -y python3-venv python3-pip
  python3 run.py setup
  ```
- **Other Linux:** same as Kali, minus the `apt` step if `python3-venv` is
  already installed.

`run.py setup` creates a virtual environment (`venv/`) and installs
`requirements.txt` into it — your system Python stays untouched.
Full per-machine steps (your Windows 11 host, Kali VM, Windows 10 VM)
are in [`SETUP_YOUR_MACHINES.md`](SETUP_YOUR_MACHINES.md).

## Files

| File | What it is |
|---|---|
| `sstiprobe.py` | The tool (CLI, baseline, 4 payload families, fingerprint, report) |
| `run.py` | Cross-platform launcher — Windows, macOS, Linux (finds the venv Python, auto-setup) |
| `run_lab.bat` / `run_probe.bat` | Windows double-click shortcuts |
| `run_lab.sh` / `run_probe.sh` | macOS/Linux shortcuts |
| `SETUP_YOUR_MACHINES.md` | Setup for Windows 11 host, Kali VM, Windows 10 VM |
| `lab_app.py` | Your own vulnerable lab app (Flask, `127.0.0.1` only) |
| `test_evaluation.py` | Step 3 test — 3 prepared responses, 3 verdicts |
| `requirements.txt` | `requests`, `flask` |
| `sstiprobe_report.txt` | Sample report from the lab run |
| `report_vuln_dollar.txt`, `report_safe.txt`, `report_post.txt` | Other lab runs |

## Works on Windows, macOS and Linux

The tool itself (`sstiprobe.py`, `lab_app.py`) is pure Python — no
OS-specific code. The only difference between operating systems is
where the venv Python lives (`venv/bin/python` vs `venv\Scripts\python.exe`),
so use the launcher `run.py` — it finds the right path for your OS,
creates the venv and installs requirements automatically on first run.

**Requirement on every OS:** Python 3.10+ installed
([python.org](https://www.python.org/downloads/)). On Windows, tick
"Add python.exe to PATH" during install; if `python` is not recognised,
use `py` instead of `python` in the commands below.

| | Windows (cmd / PowerShell) | macOS / Linux (Terminal) |
|---|---|---|
| Setup (first time) | `python run.py setup` | `python3 run.py setup` |
| Start the lab | `python run.py lab` | `python3 run.py lab` |
| Run the tool | `python run.py probe --url http://127.0.0.1:5000/vuln --param name` | `python3 run.py probe --url http://127.0.0.1:5000/vuln --param name` |
| Step 3 test | `python run.py test` | `python3 run.py test` |

Double-click shortcuts (no typing): Windows → `run_lab.bat` / `run_probe.bat`,
macOS/Linux → `./run_lab.sh` / `./run_probe.sh`.

Manual setup (if you prefer it — same on all OS, only the venv path differs):

```bash
python3 -m venv venv
# macOS/Linux:  ./venv/bin/pip install -r requirements.txt
# Windows:      venv\Scripts\pip install -r requirements.txt
```

## Run the lab + the tool

Terminal 1 — start the lab app:

```bash
python run.py lab          # Windows: python, macOS/Linux: python3
# Lab runs at http://127.0.0.1:5000
#   /vuln         vulnerable, {{ }}  (Jinja2)
#   /vuln-dollar  vulnerable, ${ }  (Jinja2 with $ delimiters)
#   /safe         safe — input passed as a variable
```

Terminal 2 — run SSTIProbe:

```bash
# Vulnerable endpoint — should report VULNERABLE, Jinja2, 49 / 56
python run.py probe --url http://127.0.0.1:5000/vuln --param name

# Second engine — should report VULNERABLE, ${ }, 64 / 72
python run.py probe --url http://127.0.0.1:5000/vuln-dollar --param name

# Safe endpoint — should report NOT VULNERABLE
python run.py probe --url http://127.0.0.1:5000/safe --param name

# POST form (stretch) / POST JSON (stretch)
python run.py probe --url http://127.0.0.1:5000/vuln --param name --method POST
python run.py probe --url http://127.0.0.1:5000/vuln --param name --method POST --json
```

Every run prints the result and saves it to `sstiprobe_report.txt`
(change it with `--output report.txt`).

## One finding, explained

On `/vuln?name={{7*7}}` the lab answered `Hello 49!` — the template engine
ran the maths instead of printing the text. The confirm payload `{{7*8}}`
gave `56`, and the fingerprint `{{7*'7'}}` gave `7777777`, identifying Jinja2.
The fix is in `lab_app.py` (`/safe`): pass user input as a **variable**
(`render_template_string("Hello {{ name }}!", name=name)`), never glue it
into the template string.

## Defensive lesson

**Never render user input as a template.** That is the whole rule. The
engine cannot tell "template the developer wrote" from "text the user typed"
once they are mixed — so it evaluates both. Keep them separate: the template
is code you wrote, the input is data passed as a variable. If input must
shape a template, use a sandboxed engine and an allow-list.

## Lab rules

Test **only** your own lab app (`127.0.0.1`). Never point this tool at a
real website you do not own or have written permission to test.
Unauthorised access is a criminal offence under PECA 2016 (Pakistan).
Detection payloads only: arithmetic evaluation, nothing more.
