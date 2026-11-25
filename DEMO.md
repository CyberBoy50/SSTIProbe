# SSTIProbe — Demo and Write-up

**Student:** Jahanzaib Yosuf — PNY Trainings, Web Security
**Instructor:** Abdul Mannan — **Deadline:** Tuesday, 25 November 2026
**Tool version in this demo:** v2.8 — **GitHub:** https://github.com/CyberBoy50/SSTIProbe

Everything below is a real run against the lab app on this machine
(`python run.py lab`, http://127.0.0.1:5000). Only test systems you own
or have written permission to test — your own website or lab. The
random-confirm numbers change on every run; the fixed `{{7*7}}` → 49
result does not.

## Setup

```bash
git clone https://github.com/CyberBoy50/SSTIProbe.git
cd SSTIProbe
python run.py setup        # venv + requests + flask (first time only)
```

Terminal 1 — start the lab:

```bash
python run.py lab
```

Terminal 2 — run the tool (or just `python run.py probe` for the menu):

```bash
python run.py probe --url http://127.0.0.1:5000/vuln --param name
```

## Demo 1 — Vulnerable endpoint `/vuln` (real output)

```
[1] BASELINE: HTTP 200, 24 characters  ->  'Hello SSTIProbeBaseline!'
[2] DETECTION: 6 syntax families, contexts up to level 1 (tplmap pattern)
  [!] [double-brace {{ }}] [text context] {{7*7}} = 49 -> evaluated
      [3] CONFIRM: {{7*8}} = 56 -> evaluated
      [3a] RANDOM CONFIRM: {{98*70}} = 6860 -> evaluated
      [3b] WRAPPED CONFIRM: header+7*7+trailer -> evaluated
      [4] ENGINE: Jinja2 (Python string-repeat marker 7*'7' = 7777777)
  [-] [dollar-brace ${ }] [text context] ${8*8} = 64 -> reflected
  [-] [hash-brace #{ }] [text context] #{9*9} = 81 -> reflected
  [-] [star-brace *{ }] [text context] *{6*7} = 42 -> reflected
  [-] [erb <%= %>] [text context] <%=5*5%> = 25 -> reflected
  [-] [smarty comment { }] [text context] {11}{*x*}{22} = 1122 -> reflected

[!] VULNERABLE — template injection found in parameter 'name'
 [+] REPORT SAVED TO: report_vuln.txt
```

## Demo 2 — Safe endpoint `/safe`

```bash
python run.py probe --url http://127.0.0.1:5000/safe --param name
```

```
Result: NOT VULNERABLE (no template evaluation detected)
No payload was evaluated. This does not prove the app is
safe in every way — only that these 6 families did not
evaluate arithmetic in this parameter (render or blind).
```

## Demo 3 — Blind endpoint `/blind`

```bash
python run.py probe --url http://127.0.0.1:5000/blind --param name
```

Nothing is reflected here, so the render check finds nothing and the
tool falls back to blind detection: `7*7==49` (true) returns `OK`,
`7*7==50` (false) returns `FAIL` — different answers, so the engine
evaluated the input. Report excerpt:

```
Syntax family: boolean blind (no braces)
Technique: boolean blind
Engine: Unknown template engine (blind — no output to fingerprint)
Detection payload: 7*7==49  -> computed response differs for true vs false
Evidence (response snippet): "true -> 'OK' | false -> 'FAIL'"
```

## Demo 4 — Form discovery

```bash
python run.py probe --discover http://127.0.0.1:5000/ --output report_discover.txt
```

```
 [+] Found 1 form(s) on the page.
 Form action           : http://127.0.0.1:5000/vuln
 Input                 : name
[!] VULNERABLE — input 'name'
 [+] DISCOVERY REPORT SAVED TO: report_discover.txt (1 vulnerable input(s) found)
```

## Sample report — `report_vuln.txt` (real file in this repo)

```
SSTIProbe Report
Date: 2026-11-25 16:01:47
Target URL: http://127.0.0.1:5000/vuln
Parameter: name
Method: GET

Result: VULNERABLE — 1 syntax family/families evaluated input

Vulnerable parameter: name
Syntax family: double-brace {{ }}
Context: text context
Technique: render
Engine: Jinja2 (Python string-repeat marker 7*'7' = 7777777)
Detection payload: {{7*7}}  -> computed 49
Confirmation payload: {{7*8}}  -> computed 56
Evidence (response snippet): 'Hello 49!'

Remediation: Never render user input as a template. Pass it as a VARIABLE (e.g. render_template_string('Hello {{ name }}!', name=user_input)) so the engine prints it instead of evaluating it. If a template must be built from input, use a sandboxed engine and an allow-list of safe values.
```

## One finding, explained

**Finding:** the `name` parameter of `/vuln` is vulnerable to server-side
template injection in the Jinja2 engine.

**Why it is real, not a coincidence:** the baseline request
(`SSTIProbeBaseline`) returns `Hello SSTIProbeBaseline!` — 24 characters,
HTTP 200. Sending `{{7*7}}` returns `Hello 49!`: the number 49 appears
and the payload text `{{7*7}}` does not, so the template engine *ran*
the multiplication instead of printing it. A second, different
multiplication (`{{7*8}}` → 56) confirms it, a fresh random pair
(`{{98*70}}` → 6860) confirms it again, and a header/trailer-wrapped
payload confirms the 49 came from evaluation in that exact spot.
Finally `7*'7'` returns `7777777` — Python string repetition — which
fingerprints the engine as Jinja2. The other five families were only
reflected, so they are not vulnerable here.

**Why it matters:** the lab builds its template with
`render_template_string(f"Hello {name}!")` — user input glued straight
into template code. The same flaw in a real app lets an attacker run
template code on the server.

## Defensive lesson — never render user input as a template

**The rule:** user input is data, never template code. Pass it as a
variable: `render_template_string("Hello {{ name }}!", name=user_input)`.
Then `{{7*7}}` is printed literally and never evaluated — that is
exactly what the `/safe` endpoint does, and the tool reports it
NOT VULNERABLE.

**Why it matters:** a template engine runs code. The moment input
becomes part of the template string, the engine cannot tell "the
developer's code" from "the attacker's code" — so it runs both.

**How to follow it:** (1) never build template strings with f-strings
or `+` from user input; (2) pass every user value as a template
variable; (3) if a template must be assembled from input, use a
sandboxed engine and an allow-list of safe values.

## How to reproduce this demo

```bash
python run.py lab          # terminal 1
python run.py probe --url http://127.0.0.1:5000/vuln --param name
python run.py probe --url http://127.0.0.1:5000/safe --param name
python run.py probe --url http://127.0.0.1:5000/blind --param name
python run.py probe --discover http://127.0.0.1:5000/
python run.py test         # Step 3 evaluation test (12 checks, all pass)
```
