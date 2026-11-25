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
