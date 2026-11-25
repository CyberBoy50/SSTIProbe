# Research — CLI Interfaces of Well-Known Pen-Test Tools

Researched 2026-11-25 (GitHub + internet). Scope: **interface/UX only**,
for authorised lab testing. No exploitation payloads, RCE commands, or
instructions for attacking real targets. SSTIProbe stays detection-only,
lab-only, as the PDF requires.

## 1. sqlmap — https://github.com/sqlmapproject/sqlmap
- Args-only, no menu. `python sqlmap.py [options]`, `-u`, `-r`, `--batch`
  (never ask, use defaults), `--level`, `--risk`, `--output-dir`,
  `--report-json`, `--disable-coloring`, `--version`.
- Startup: ASCII banner built around `__H__`, version in braces,
  then a full legal disclaimer on startup: usage without prior mutual
  consent is illegal; end user is responsible for obeying the law.
- Input: inline yes/no questions with default in capitals, `[Y/n]` / `[y/N]`.
- Markers: timestamped `[INFO]` / `[WARNING]` / `[ERROR]` / `[CRITICAL]` / `[*]`.
- Reporting: per-target files under output dir, session SQLite file,
  dump formats CSV/HTML/SQLITE/JSONL, `--report-json`.

## 2. nmap — https://github.com/nmap/nmap
- Args-only, no menu/prompts. `nmap [scan type] [options] {target}`.
  `-sV -sS -O -A -p -T0..T5 -v --script -oN/-oX/-oG/-oA`.
- Startup: no banner, no disclaimer. Plain line:
  `Starting Nmap 7.80 ( https://nmap.org ) at ...`
- Runtime interaction only: single keypresses `v` verbosity, `d` debug,
  `p` status, `?` help. `--noninteractive` disables it.
- Reporting: normal/XML/grepable/script-kiddie, `-oA` writes all three.

## 3. Hydra (THC-Hydra) — https://github.com/vanhauser-thc/thc-hydra
- Args-only main binary; bare `hydra` prints short summary.
  `-l/-L login, -p/-P password, -t parallel, -o output, -R restore`.
- Startup: ASCII banner `H Y D R A`, `(c) 2001-2023 by van Hauser / THC`,
  `Please do not use in military or secret service organizations, or for
  illegal purposes.` README: `THIS TOOL IS FOR LEGAL PURPOSES ONLY!`
- Interactive path is separate: `hydra-wizard` asks sequential questions
  (service, target, username, password, port) then shows a summary and
  asks for final confirmation. `xhydra` is a GTK GUI.
- Markers: `[DATA]` summaries, `[ERROR]` errors, findings as
  `[port][service] host: ... login: ... password: ...`
- Reporting: `-o` text/json/jsonv1, `hydra.restore` session file.

## 4. John the Ripper — https://github.com/openwall/john
- Args-only. `john <hash-file>`, `--wordlist`, `--rules`, `--format`,
  `--show`, `--restore`, `--test`, `--list=formats`.
- Startup: no banner. Plain version line, `Loaded N password hashes`,
  `Press 'q' or Ctrl-C to abort, almost any other key for status`.
- Reporting: cracked results in `john.pot`, session in `john.rec`,
  event log `john.log`, `--show` re-displays results.

## 5. Nikto — https://github.com/sullo/nikto
- Args-only Perl CLI. `nikto -h <host>` — note: `-h` is the *target*,
  `-Help`/`-H` is help. `-port -ssl -Tuning -output -Format -update`.
- Startup: no banner. Header box with `+ Target IP / Hostname / Port /
  Start Time`, then `+ Server: <banner>`.
- Markers: `-` banner line, `+` every finding line, footer
  `+ N requests: 0 error(s) and N item(s) reported`.
- Reporting: `-o` + `-Format` csv/json/htm/sql/txt/xml.

## 6. Gobuster — https://github.com/OJ/gobuster
- Mode-based args-only: `gobuster [mode] [options]`, modes
  `dir dns vhost s3 gcs tftp fuzz`. `-u -w -t --threads -o -q --no-color`.
- Startup: `=`-rule banner, `Gobuster v3.x`, authors, then a `[+]`
  config block: `Mode, Url/Domain, Threads, Wordlist` — before scanning.
- Markers: `[+]` config/info, `[-]` errors, `[!]` warnings.
  Hits: `<path> (Status: NNN) [Size: N]`. Progress line, then `Finished`.
- Reporting: `-o` plain text file; no JSON for `dir` mode.
- README: "Always get proper authorization before testing any target."

## 7. tplmap (legacy) — https://github.com/epinna/tplmap
- No longer maintained, Python 2. Args-only: `./tplmap.py -u '<url>'`,
  `-d`, `-L` list file, `--cookie`, `--level`, `-e` engine, `--log`.
  Injection point marked with `*` in URL/data.
- Startup: `[+] Tplmap 0.5` header only, no banner, no disclaimer.
- Markers: `[+]` only. Identification block: `GET parameter: name`,
  `Engine: Jinja2`, `Injection: {{*}}`, `Context: text`, `OS: linux`,
  `Technique: render`, then `Capabilities:` list.

## 8. SSTImap — https://github.com/vladko312/SSTImap
- Maintained successor to tplmap, Python 3, v1.4.0, GPL-3.0.
- Two modes: predetermined `./sstimap.py -u <url>` and interactive
  `python3 sstimap.py -i -u '<url>'`. Flags: `-u -r -d -H -C -m -l
  (level 1-5) -e (engine) -t (technique) --generic --crawl --no-color`.
- Startup: box-drawing ASCII banner, then:
  ```
  [*] Version: 1.4.0
  [*] Author: @vladko312
  [*] Based on Tplmap
  [!] LEGAL DISCLAIMER: Usage of SSTImap for attacking targets without
  prior mutual consent is illegal. ...
  ```
- Interactive mode: typed commands (`url`, `run`, `help`), not a numbered
  menu. Results stay valid until the URL changes; Ctrl+C aborts a step
  without stopping the program.
- Markers: `[*]` info/progress, `[+]` confirmed, `[!]` disclaimer.
- Reporting: `--save-vuln` / `--load-vuln`; HTML/JSONL reports are
  listed as future plans, not present.

## 9. Small Kali-style single-purpose tools (LOCATIONCAT pattern)

### GhostTrack — https://github.com/HunxByts/GhostTrack (20,881 stars)
- No CLI args at all. `python3 GhostTR.py` → ASCII ghost banner +
  `[ + ] C O D E B Y H U N X [ + ]` → numbered menu:
  ```
  [ 1 ] IP Tracker
  [ 2 ] Show Your IP
  [ 3 ] Phone Number Tracker
  [ 4 ] Username Tracker
  [ 0 ] Exit
  @Ghost~#
  ```
  Then `Enter IP target : `, one `requests.get()` to a public API,
  grouped `[BASIC INFORMATION]` / `[GEOGRAPHIC LOCATION]` output.
  Console output only, no file export.

### TraceRecon — https://github.com/PRATHAM777P/TraceRecon
- `[?]`-prompt variant, closest to LOCATIONCAT:
  ```
  [ ? ] Select option : 1
  Enter target IP (leave blank for auto-detect): 8.8.8.8
  ```
  Nine numbered modules, `────` rule lines, `RESULT — ...` headers,
  `[FOUND] ...` / `[---] ... not found`, summary counts.
- Reporting: every module asks `Export results? [y/N]: y` and writes
  timestamped JSON + TXT into `output/`.

### LOCATIONCAT — as named
- No GitHub repo was found. Only an Instagram demo reel:
  https://www.instagram.com/reel/DfzrOyPy9dc/ — "Only For Education
  purpose". Sequence: `python locationcat.py` → red ASCII banner
  `LOCATIONCAT by @rootuser.ru` → IP entered → status lines
  `Initializing... Validating IP address... Analyzing demo data...` →
  demo results → `MAP GENERATED` → disclaimer that it is **not real
  IP geolocation**. Treat it as a staged/demo script, not a real
  tracker; GhostTrack/TraceRecon are the working equivalents.

## Cross-tool comparison

| Aspect | sqlmap | nmap | Hydra | Gobuster | tplmap | SSTImap | GhostTrack/TraceRecon |
|---|---|---|---|---|---|---|---|
| Interaction | Args + `[Y/n]`, `--batch` | Args only | Args; `hydra-wizard` Q&A | Args, mode-based | Args only | Args **or** `-i` shell | Menu + `[?]` prompts |
| Startup | ASCII banner + version + full disclaimer | Plain `Starting Nmap` line | ASCII banner + short notice | `=` banner + `[+]` config block | `[+] Tplmap 0.5` only | Box-art banner + version/author + disclaimer | ASCII banner + author |
| Markers | `[INFO]/[WARNING]/[ERROR]/[*]` | Port table, `Nmap done:` | `[DATA]/[ERROR]` | `[+]/[-]/[!]` | `[+]` only | `[*]/[+]/[!]` | `=====` headers, `[FOUND]`, `[+] saved` |
| Colours | On by default, `--disable-coloring` | None documented | None documented | Since v3.2, `--no-color` | Not documented | On by default, `--no-color` | ANSI green/white/red |
| Report file | Output dir, session SQLite, JSON | `-oN/-oX/-oG/-oA` | `-o` text/json, restore file | `-o` plain text | `--log=scan.log` | `--save-vuln` (HTML/JSON planned) | TraceRecon: JSON+TXT in `output/` |

## Payload system — what tplmap / SSTImap do (code read 2026-11-25)

Only detection parts are quoted here. The `evaluate` / `execute` /
`execute_blind` actions in these files are exploitation (RCE) — they
were read to understand what NOT to copy; SSTIProbe has no equivalent.

### tplmap `utils/rand.py`
```python
def randint_n(n):
    # If the length is 1, starts from 2 to avoid
    # number repetition on evaluation e.g. 1*8=8
    # creating false positives
    if n == 1: range_start = 2
    else: range_start = 10**(n-1)
    return random.randint(range_start, (10**n)-1)
randints = [randint_n(2) for n in range(3)]      # 3 random 2-digit ints
randstrings = [randstr_n(2) for n in range(3)]   # 3 random 2-char strings
```

### tplmap `plugins/engines/jinja2.py` (render + contexts)
```python
'render': '{{%(code)s}}', 'header': '{{%(header)s}}', 'trailer': '{{%(trailer)s}}'
'test_render': '(%(n1)s,%(n2)s*%(n3)s)' % {'n1': rand.randints[0], ...}
'test_render_expected': '%(res)s' % {'res': (rand.randints[0], rand.randints[1]*rand.randints[2])}
self.set_contexts([
    {'level': 0},                                            # text context
    {'level': 1, 'prefix': '%(closure)s}}', ...},             # covers {{%s}}
    {'level': 1, 'prefix': '%(closure)s%%}', ...},            # covers {% %s %}
    {'level': 5, 'prefix': '%(closure)s\n', 'suffix': '\n', ...},  # if/for
    {'level': 5, 'prefix': '#}', 'suffix': '{#'},            # comment blocks
])
```

### tplmap `plugins/engines/smarty.py` and `mako.py`
```python
# Smarty: render is BARE code '%(code)s'; test uses a comment:
'test_render': "{%(r1)s}{*%(comment)s*}{%(r2)s}"   # expected '%(r1)s%(r2)s'
# Smarty contexts: level 1 prefix '%(closure)s}' suffix '{'; level 5
# '%(closure)s}{/if}{if 1}', assign escape, comment '*}' / '{*'.
# Mako: render '${%(code)s}'; contexts level 1 '%(closure)s}' and
# '%(closure)s%%>' suffix '<%#' (code blocks <% %>); level 5 '#\n'.
```

### tplmap `plugins/engines/twig.py`
```python
# test_render is string-based, not arithmetic:
'test_render': '"%(s1)s\n"|nl2br' % {'s1': rand.randstrings[0]}
'test_render_expected': '%(res)s<br />' % {'res': rand.randstrings[0]}
# Contexts: level 1 prefix '%(closure)s}}' suffix '{{1'; level 5
# '%(closure)s %%}{%% endfor %%}{%% for a in [1] %%}'.
```

### tplmap `plugins/languages/python.py` — blind actions
```python
'blind': {'call': 'evaluate_blind',
    'test_bool_true': "'a'.join('ab') == 'aab'",
    'test_bool_false': 'True == False'}
# (evaluate_blind itself uses eval + time.sleep — exploitation, NOT copied.)
```

### tplmap `core/plugin.py` — detection flow
```python
def detect(self):
    techniques = self.channel.args.get('technique')
    if 'R' in techniques: self._detect_render()     # render first
    if 'T' in techniques and not self.get('engine'): self._detect_blind()
def _detect_render(self):
    for prefix, suffix in self._generate_contexts():   # respects --level
        expected = render_action.get('test_render_expected')
        payload = render_action.get('test_render')
        trailer_rand = rand.randint_n(10)              # random 10-digit
        trailer = render_action.get('trailer') % {'trailer': trailer_rand}
        if expected == self.render(code=payload, trailer=trailer, prefix=prefix, suffix=suffix):
            ... confirmed, channel.detected('render', ...)
def _detect_blind(self):                               # true vs false
    payload_true = action.get('test_bool_true'); payload_false = action.get('test_bool_false')
    for prefix, suffix in self._generate_contexts():
        if not inject(code=payload_true, blind=True): continue
        if inject(code=payload_false, blind=True): continue
        self.set('blind', True)   # true worked, false did not -> blind
def _detect_unreliable_render(self):                   # fallback: substring
    if expected in self.render(code=payload, trailer='', prefix='', suffix=''):
        ... 'unreliable rendering' ...
# render_req_tm = deque([0.5], maxlen=5) — average response time, used to
# judge time-based blind delays.
```

### SSTImap `plugins/python/jinja2.py` (structure found by browser read)
```python
class Jinja2(python.Python): priority = 5
'render': '{code}', 'header': '{{{{{header[0]}+{header[1]}}}}}'
'test_render': f'{{{{({rand.randints[0]},{rand.randints[1]}*{rand.randints[2]})|e}}}}'
'test_render_expected': f'{(rand.randints[0],rand.randints[1]*rand.randints[2])}'
'render_error': {'render': '{code}', 'test_render': f'({rand...})|e', ...}
# contexts: level 1 '{closure}}}}}' ({{ }}), '{closure}%}}' ({% %});
# level 5 '{closure}\n', comment '#}}' / '{#'.
# Repo layout: plugins/ by language (custom, generic, java, javascript,
# languages, php, python, ruby); core/ has channel.py, checks.py,
# plugin.py, matcher.py, interactive.py; utils/ has rand.py, closures.py.
```

## What was applied to SSTIProbe v2.3 (within the PDF)
1. Random-pair confirm (`randint_n`, 1-digit starts at 2) — tplmap rand.
2. Header/trailer wrapped confirm with random 10-digit markers.
3. Contexts with `--level {0,1,5}` (text / code tags / comment blocks).
4. Boolean blind technique `--technique {R,T,RT}` (true `7*7==49` vs
   false `7*7==50`, no braces), with the reflection guard: the
   expressions must NOT appear in the responses, else it is mere
   reflection, not blind evaluation (this fixed a /safe false positive
   found in testing).
5. Two new families: ERB `<%= 5*5 %>` and Smarty comment `{11}{*x*}{22}`.
6. Lab gained a `/blind` endpoint (`{% if <input> %}OK{% else %}FAIL`).
7. NOT copied: evaluate/execute/os-shell/RCE, time-sleep blind, or
   Twig's string `nl2br` test. SSTIProbe stays detection-only, lab-only.

## Code studied (read from the repos, 2026-11-25)

### GhostTrack — `GhostTR.py` (full file read)
```python
Bl = '\033[30m'  # VARIABLE BUAT WARNA CUYY
Re = '\033[1;31m'; Gr = '\033[1;32m'; Ye = '\033[1;33m'
Blu = '\033[1;34m'; Mage = '\033[1;35m'; Cy = '\033[1;36m'; Wh = '\033[1;37m'

def is_option(func):            # decorator: run banner before each function
    def wrapper(*args, **kwargs):
        run_banner()
        func(*args, **kwargs)
    return wrapper

ip = input(f"{Wh}\n Enter IP target : {Gr}")   # label white, typed text green
print(f' {Wh}============= {Gr}SHOW INFORMATION IP ADDRESS {Wh}=============')
print(f"{Wh} Country       :{Gr}", ip_data["country"])   # label : value

options = [{'num': 1, 'text': 'IP Tracker', 'func': IP_Track},
           {'num': 2, 'text': 'Show Your IP', 'func': showIP},
           {'num': 3, 'text': 'Phone Number Tracker', 'func': phoneGW},
           {'num': 4, 'text': 'Username Tracker', 'func': TrackLu},
           {'num': 0, 'text': 'Exit', 'func': exit}]
def option_text():              # builds "[ 1 ] IP Tracker\n[ 2 ] ..."
    text = ''
    for opt in options:
        text += f'{Wh}[ {opt["num"]} ] {Gr}{opt["text"]}\n'
    return text
def clear():
    if os.name == 'nt': _ = os.system('cls')   # Windows
    else: _ = os.system('clear')               # macOS / Linux
def option(): clear(); stderr.writelines(f"""<big GHOST banner>
{Wh}[ + ] C O D E B Y H U N X [ + ]"""); stderr.writelines(f"\n\n\n{option_text()}")
def run_banner(): clear(); time.sleep(1); stderr.writelines(f"""<ghost art>
: g g : {Wh}| {Gr}GHOST - TRACKER - IP ADDRESS {Wh}| ...""")
def main():
    clear(); option(); time.sleep(1)
    opt = int(input(f"{Wh}\n [ + ] {Gr}Select Option : {Wh}"))
    execute_option(opt)
def execute_option(opt):
    call_option(opt)
    input(f'\n{Wh}[ {Gr}+ {Wh}] {Gr}Press enter to continue')
    main()
```

### TraceRecon — `tracerecon.py` (first 430 lines read)
```python
class C:                        # colours as one class
    RST = "\033[0m"; BLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[1;31m"; GRN = "\033[1;32m"; YEL = "\033[1;33m"
    BLU = "\033[1;34m"; MAG = "\033[1;35m"; CYN = "\033[1;36m"; WHT = "\033[1;37m"

def clear(): os.system("cls" if os.name == "nt" else "clear")
def sep(color=C.GRN, char="─", width=58): print(f"{color}{char * width}{C.RST}")
def ok(msg):   print(f" {C.WHT}[{C.GRN}+{C.WHT}]{C.RST} {msg}")
def warn(msg): print(f" {C.WHT}[{C.YEL}!{C.WHT}]{C.RST} {C.YEL}{msg}{C.RST}")
def err(msg):  print(f" {C.WHT}[{C.RED}✗{C.WHT}]{C.RST} {C.RED}{msg}{C.RST}")
def info(label, value, label_color=C.WHT, val_color=C.GRN):
    print(f" {label_color}{label:<22}{C.RST}: {val_color}{value}{C.RST}")

BANNER = """<block-art TRACE / RECON>
┌──────────────────────────────────────────────────┐
│ OSINT & Network Reconnaissance Toolkit v{VERSION} │
│ For authorized research & educational use only   │
└──────────────────────────────────────────────────┘"""

MENU = [(1, "IP Address Tracker", "ip", C.GRN), (2, "My Public IP", "myip", C.CYN),
        (3, "Phone Number OSINT", "phone", C.BLU), ... (0, "Exit", None, C.RED)]
def show_menu():
    clear(); stderr.write(BANNER); sep(C.GRN, "═")
    bullet = f"{C.GRN}[{color}{num:>2}{C.GRN}]"
    print(f" {bullet} {C.WHT}{label}{C.RST}")
    sep(C.GRN, "═")

raw = input(f"\n {C.WHT}Enter target IP{C.RST} (leave blank for auto-detect): {C.GRN}").strip()
warn("Querying ipwho.is API …")
export = input(f"\n {C.WHT}Export results? {C.GRN}[y/N]{C.RST}: ").strip().lower()
# save_result(): timestamped JSON + TXT into output/
def safe_get(url, **kwargs):    # Session + timeout + typed errors
    try: resp = SESSION.get(url, timeout=TIMEOUT, **kwargs); resp.raise_for_status(); return resp
    except requests.exceptions.Timeout: err("Request timed out.")
    except requests.exceptions.ConnectionError: err("No network connection.")
    except requests.exceptions.HTTPError as e: err(f"HTTP error: {e.response.status_code}")
```

### SSTImap — `utils/cliparser.py` (found by code search)
```python
msg += f"\n\033[94m[*]\033[0m Version: {version}"
msg += f"\n\033[94m[*]\033[0m Author: @vladko312"      # OSC8 hyperlink to GitHub
msg += f"\n\033[34m[*]\033[0m Based on Tplmap"
msg += f"\n\033[91m[!] LEGAL DISCLAIMER\033[0m: Usage of SSTImap for attacking
        targets without prior mutual consent is illegal. ..."
```

### sqlmap — `lib/core/settings.py` + `sqlmap.py` (found by code search)
```python
LEGAL_DISCLAIMER = "Usage of sqlmap for attacking targets without prior mutual
consent is illegal. It is the end user's responsibility to obey all applicable
local, state and federal laws. Developers assume no liability and are not
responsible for any misuse or damage caused by this program"
# sqlmap.py startup:
dataToStdout("[!] legal disclaimer: %s\n\n" % LEGAL_DISCLAIMER, forceOutput=True)
dataToStdout("[*] starting @ %s\n\n" % time.strftime("%X /%Y-%m-%d/"), forceOutput=True)
```

## What was applied to SSTIProbe v2.2 (within the PDF)
1. Numbered menu (`--menu`, default with no args) — GhostTrack/TraceRecon
   pattern: options list, `show_menu()`, `[ ? ] Select option : ` prompt,
   `Press enter to continue` loop, Ctrl+C → `[ ! ] Exit`.
2. Colour class `C` + helpers `ok()` / `warn()` / `err()` / `info()` /
   `sep()` / `header()` / `clear()` — TraceRecon pattern (GhostTrack's
   plain colour variables are the same idea).
3. TraceRecon-style box under the banner; aligned `info()` fields for
   the config block; `warn("Querying target …")` status line.
4. Typed network errors in the scan (Timeout / ConnectionError /
   RequestException) — TraceRecon `safe_get()` pattern.
5. Step 3 test callable from the menu (option 4), reusing
   `check_evaluation()` — the same 3 cases as `test_evaluation.py`.
6. NOT copied: GhostTrack/TraceRecon's OSINT targets (IP/phone/username),
   SSTImap's exploitation follow-ups, sqlmap's injection engine. SSTIProbe
   stays detection-only, lab-only, as the PDF requires.

## What was applied to SSTIProbe v2.1 (within the PDF)
1. Startup: banner → `[*] Version: 2.1` → `[*] Author: CyberBoy50` →
   `[!] LEGAL DISCLAIMER: lab only...` (SSTImap/sqlmap pattern).
2. Explicit `-i` / `--interactive` flag, like SSTImap; interactive is no
   longer only the fallback when args are missing.
3. `--version` flag and `--no-color` flag (sqlmap/SSTImap/Gobuster pattern).
4. Gobuster-style `[+]` config block at startup: Target, Parameter,
   Method, Output file — before scanning starts.
5. Kept: inline defaults in prompts (sqlmap style), `[*]/[+]/[!]/[-]`
   markers, saved text report with evidence + remediation.
6. NOT added: any exploitation follow-up (`--os-shell`, RCE, file
   read/write). The PDF forbids it; that is what separates SSTIProbe
   from tplmap/SSTImap.
