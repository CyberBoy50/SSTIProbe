# SSTIProbe — Server-Side Template Injection Tester

**Student:** Jahanzaib Yosuf · **Track:** Web Security · **Instructor:** Abdul Mannan
**Course:** PNY Trainings, Cyber Security Department · **Deadline:** 25 November 2026

A Python command-line tool that **detects** Server-Side Template Injection (SSTI)
using harmless arithmetic only — never exploitation payloads. Only test systems
you own or have written permission to test — your own website or lab.

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

## Interface

LOCATIONCAT-style banner, colours, and interactive prompts:

```
  ____  ____  _____ ___ ____  ____   ___  ____  _____
 / ___|/ ___||_   _|_ _|  _ \|  _ \ / _ \|  _ \| ____|
 ...
              by CyberBoy50
        SSTI DETECTOR  |  AUTHORIZED USE ONLY

[?] ENTER TARGET URL [http://127.0.0.1:5000/vuln]:
[?] ENTER PARAMETER NAME [name]:
[?] ENTER REQUEST METHOD [GET/POST] [GET]:
```

## Installation — compared with the famous tools (read from their READMEs)

| Tool | Install steps | Needs |
|---|---|---|
| **sqlmap** | `git clone` — works out of the box | Python 2.7/3.x only, **zero deps** |
| **nmap** | `sudo apt install nmap` / `brew install nmap` / Windows .exe (+Npcap) | system package, admin rights |
| **Gobuster** | `go install ...@latest` or prebuilt binary | Go 1.24+ (or download binary) |
| **Hydra** | `git clone`, `./configure`, `make`, `make install` + `apt-get install libssl-dev libssh-dev ...` | C compiler + system libraries — hardest |
| **John** | compile from source (`./configure && make`) or binary distro | C compiler |
| **Nikto** | `git clone`, `perl nikto.pl` (or Docker) | Perl |
| **tplmap** | `pip install -r requirements.txt` (7 pinned deps) | **Python 2 — dead** |
| **SSTImap** | `pip install -r requirements.txt` (5 deps) | Python 3 |
| **GhostTrack** | `apt-get install git python3`, `git clone`, `pip3 install -r requirements.txt` | Python 3 + 2 deps |
| **TraceRecon** | `git clone`, `pip install -r requirements.txt` (4 deps) | Python 3.8+ |
| **SSTIProbe** | `git clone` + `python run.py setup` (auto venv + install) — or **nothing**: the probe runs on plain Python 3 (urllib fallback, sqlmap pattern) | Python 3.10+; flask only for the lab |

Behaviour compared: sqlmap/nmap/Hydra/John/Nikto/Gobuster/tplmap are
args-only (sqlmap adds `[Y/n]` prompts + `--batch`, Hydra has a separate
`hydra-wizard`, Gobuster is mode-based, John keeps session files).
GhostTrack/TraceRecon are menu-only. SSTImap has args + `-i` shell.
**SSTIProbe has all three**: menu (default), args, and `[?]` prompts —
plus `--batch` (sqlmap), `-q` (Gobuster), `--no-color`, `--level`,
`--technique`, and `run.py doctor` to check the setup.

Run it with no arguments and it opens the numbered menu, GhostTrack /
TraceRecon style (`python run.py probe` or `--menu`):
```
 [ 1] Scan a target (enter URL, parameter, method)
 [ 2] Quick scan: /vuln (Enter = lab, or type your own URL)
 [ 3] Quick scan: /safe (Enter = lab, or type your own URL)
 [ 4] Run Step 3 test (evaluation check)
 [ 5] Check a website / lab is reachable
 [ 0] Exit
 [ ? ] Select option :
```
After each scan it asks `Press enter to continue` and returns to the menu.
Options 1, 2 and 3 all ask the `[?]` questions (URL, parameter, method) —
on 2 and 3, pressing Enter takes the lab default (`/vuln` or `/safe`),
or type any own website URL instead. Option 5 checks whether a website
answers (Enter = the lab, or type your own URL). Ctrl+C exits.
Give `--url` and `--param` and it runs straight away with no menu or prompts.
Every run shows the 6 must-have features as numbered steps:
`[1] BASELINE`, `[2] DETECTION`, `[3] CONFIRM`, `[3a] RANDOM CONFIRM`,
`[3b] WRAPPED CONFIRM`, `[4] ENGINE`, `[5] REPORT SAVED TO`, plus the
final `[!] VULNERABLE` / `[+] NOT VULNERABLE` verdict.

Payload system (tplmap / SSTImap patterns, detection-only):
- 6 syntax families: `{{ }}` (Jinja2/Twig), `${ }` (Mako/FreeMarker),
  `#{ }` (Velocity/FreeMarker), `*{ }`, `<%= %>` (ERB),
  Smarty comment `{11}{*x*}{22}` → `1122` (comment stripped = parsed).
- Contexts (tplmap `set_contexts`): text (level 0), inside `{{ }}` and
  `{% %}` (level 1, close the tag first: `}}{{7*7}}{{`), comment block
  (level 5). `--level {0,1,5}` controls depth, default 1.
- Confirm in 3 ways: fixed second multiplication (`{{7*8}}` → 56),
  random-pair confirm (fresh random 2-digit numbers every run, tplmap
  `rand.py` pattern), header/trailer wrapped confirm (random 10-digit
  markers around the result, tplmap `_detect_render` pattern).
- Boolean blind technique (tplmap `_detect_blind`): if render finds
  nothing, send `7*7==49` (true) vs `7*7==50` (false) with no braces;
  different responses = evaluated. Lab endpoint `/blind` tests this.
  `--technique {R,T,RT}` picks render / blind / both (default RT).
- Timing blind (PDF stretch): if boolean blind also finds nothing,
  compare response times — `range(3000000)|list` (~0.13s) vs baseline
  (~0.004s). No sleep, no RCE, just a heavy harmless computation.
- Form discovery (PDF stretch): `--discover <page-url>` fetches a lab
  page, finds its `<form>` tags (stdlib `html.parser`) and probes every
  input automatically. See `DEMO.md` for a real run.
- Engine fingerprint: `7*'7'` → `7777777` = Jinja2; otherwise the family
  gives a "likely engine" guess. No exploitation payloads anywhere.

Startup sequence (like SSTImap / sqlmap): banner → `[*] Version: 2.9` →
`[*] Author: CyberBoy50` → `[!] LEGAL DISCLAIMER: Only test systems you own...` →
TraceRecon-style box, then a Gobuster-style `[+]` config block
(Target, Parameter, Method, Output) with aligned `info()` fields.

Flags (see `python run.py probe --help`):
```
--menu              show the numbered menu (default with no args)
-i, --interactive   open the menu (SSTImap -i style)
--level {0,1,5}     context depth (tplmap style, default 1)
--technique {R,T,RT} render / boolean blind / both (default RT)
--discover PAGE_URL fetch a lab page and probe every form input (PDF stretch)
--batch             never ask, use defaults (sqlmap --batch style)
-q, --quiet         only verdict + report path (Gobuster -q style)
--version           print SSTIProbe version and exit
--no-color          disable coloured output (sqlmap --disable-coloring style)
--url / --param / --method / --json / --output / --timeout
```

Demo and write-up: see `DEMO.md` — real runs on `/vuln`, `/safe`,
`/blind` and `--discover`, the sample report, one finding explained,
and the defensive lesson (never render user input as a template).

Setup check:
```
python run.py doctor     # Python version, venv, requests, flask, lab on :5000
```

Lab endpoints (`python run.py lab`, http://127.0.0.1:5000):
`/vuln` (Jinja2 `{{ }}`), `/vuln-dollar` (Mako `${ }`, real engine), `/safe` (fixed app),
`/blind` (boolean blind — input inside `{% if ... %}`, nothing reflected).

Interface code patterns (copied as ideas, not code — see
`RESEARCH_CLI_TOOLS.md` for the originals): colour class `C` and helpers
`ok()` / `warn()` / `err()` / `info()` / `sep()` / `header()` from
TraceRecon; `clear()` (`cls` on Windows, `clear` elsewhere), menu list
`{num, text, func}` and `Press enter to continue` loop from GhostTrack;
version/author/disclaimer startup lines from SSTImap's `utils/cliparser.py`;
`LEGAL_DISCLAIMER` constant printed at startup from sqlmap's
`lib/core/settings.py`.

## Must-have features (PDF) — where each one lives

| # | Feature | In the code |
|---|---|---|
| 1 | CLI input for target URL, parameter name, request method | `parse_args()` + `ask_interactive()` in `sstiprobe.py` |
| 2 | Baseline request before any payload | `fetch_baseline()` |
| 3 | Detection payloads, 4 syntax families, distinct multiplication each | `PAYLOADS` table (`{{7*7}}`=49, `${8*8}`=64, `#{9*9}`=81, `*{6*7}`=42) |
| 4 | Evaluation detection: computed result in response, not payload text | `check_evaluation()` — `evaluated` / `reflected` / `no-change` |
| 5 | Engine fingerprinting with engine-specific markers | `fingerprint_engine()` — `7*'7'` → `7777777` = Jinja2 |
| 6 | Report saved to a file: parameter, evidence, remediation note | `build_report()` → `sstiprobe_report.txt` |

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
#   /vuln-dollar  vulnerable, ${ }  (Mako, real engine)
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

> DISCLAIMER — AUTHORIZED USE ONLY. This tool was built for ethical, authorized security testing only. You are using it on your own responsibility. The authors are not responsible for how you use it, or for anything that happens because of your use. Only test systems, code, and data you own or have explicit written permission to test — testing anything else may be illegal (for example, PECA 2016 in Pakistan).

License: MIT — see LICENSE
