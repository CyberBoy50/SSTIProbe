# Research — How CLI Security Tools Work on GitHub

Researched 2026-11-25, while comparing SSTIProbe with real tools.
Question: CLI based tool kaam kaise karta hai — banner, input, detection, output?

## 1. The big SSTI tools: tplmap → SSTImap

**tplmap** (epinna/tplmap, Python 2, no longer maintained) was the original
automatic SSTI detector + exploiter. **SSTImap** (vladko312/SSTImap, also
szybnev/SSTImap) is its maintained successor in Python 3.

What SSTImap is, in its own words: a penetration testing tool that checks
websites for Code Injection and SSTI and can exploit them, developed as an
interactive tool for detection and exploitation.

### How detection works (same idea as SSTIProbe)
- Send a payload, check the response for the computed result.
Tplmap "generates a set of payloads... for Jinja2, it might generate
payloads like `{{7*7}}`... If the response contains the result of the
evaluated payload (e.g. if the response contains `49`...), it indicates
a potential SSTI vulnerability".
- Then it fingerprints the engine and reports: engine, injection point,
technique. SSTImap's sample output is:
`[+] Jinja2 plugin has confirmed injection with tag '{{*}}'`
followed by `GET parameter: name`, `Engine: Jinja2`, `Technique: render`.
- Detection techniques are named R/E/B/T: Rendered, Error-based,
Boolean-based blind, Time-based blind.

### How the CLI works
- **Predetermined mode:** one command, no questions:
`./sstimap.py -u https://example.com/page?name=John`
Short flags: `-u` URL, `-d` POST data, `-m` method, `-e` engine,
`-l` level, `-i` interactive mode.
- **Interactive mode (`-i`):** "commands are used to interact with SSTImap...
target URL must be supplied via initial `-u` argument or `url` command.
After that, you can use `run` command to check URL for SSTI".
So interactive = a small shell inside the tool (`url`, `run`, `help`),
not just 3 questions at the start.
- **Startup sequence:** ASCII banner, then `[*] Version:`, `[*] Author:`,
then a `[!] LEGAL DISCLAIMER` about only testing with consent.
- **Output markers:** `[*]` info, `[+]` found/success, `[!]` warning.
Exactly the markers SSTIProbe now uses.

### What SSTIProbe must NOT copy from them
Exploitation: `--os-shell`, `--os-cmd`, file read/write, reverse shell.
Our PDF forbids it — detection only, lab only. SSTImap does it; we don't.

## 2. Small SSTI detectors (closest to SSTIProbe)

GitHub search "SSTI template injection detector" finds small Python tools,
e.g. NaldyXploit-ID/SSTI-Detector (v5.0, MIT, 1 main file `main.py` +
`requirements.txt` + README with badges, screenshot and version).
Pattern of these small tools:
- One `main.py`, one `requirements.txt`, one README.
- Banner + version + author at the top, then prompts or argparse.
- Payload list in the code, `requests` to send them, check response text.
- Much smaller than tplmap/SSTImap — no plugins, no exploitation.

SSTIProbe already follows this shape. It is ahead of most of them on one
point: it confirms with a second multiplication and fingerprints the
engine before reporting — many small detectors report on the first hit.

## 3. LOCATIONCAT-style tools (the interface the user showed)

LOCATIONCAT (IP location tracker, by @rootuser.ru) is the classic
single-purpose Kali-style tool:
- Big ASCII banner with the tool name, `by @author`, one-line purpose
(`IP LOCATION TRACKER`), a dashed separator line.
- One `input()` prompt: `[?] ENTER IP ADDRESS: ` — then it calls an API
with `requests` and prints the fields, coloured.
- No argparse, no flags, no config file. Run → banner → ask → result.
- That is the whole UX: **banner first, question second, answer third.**

SSTIProbe v2 copies exactly this flow for its interactive mode:
banner → `[?] ENTER TARGET URL` → `[?] ENTER PARAMETER NAME` →
`[?] ENTER REQUEST METHOD` → scan → report.
The difference: SSTIProbe also keeps argparse mode (`--url --param`),
because the PDF requires CLI input and scripts/demos need it.

## 4. How a good Python CLI is built (general pattern)

From CLI guides and real tool codebases:
- **argparse** is the standard way to take flags; it also generates
`--help` automatically.
- **Missing-argument pattern used by real tools:** show the error in RED,
show usage in GREEN, then **fall back to interactive prompts for the
missing arguments**. That is exactly what
SSTIProbe v2 does.
- **Functions, not one long script:** separate logic into small functions
(`main()` only orchestrates), DRY, validate input early and fail fast
with a helpful message.
- **Colour:** "add color to the output... The `colorama` library is a
popular choice for cross-platform colored terminal text".
SSTIProbe uses ANSI codes + `colorama.init()` when installed, so it
works on Kali, macOS and Windows.
- **Startup sequence (seen in many tools):** banner → version/author →
legal note → prompts → `[*]` progress → `[+]`/`[!]` result → saved file.

## 5. Comparison table

| Feature | tplmap / SSTImap | Small detectors | SSTIProbe v2 |
|---|---|---|---|
| Detection `{{7*7}}` → 49 | yes | yes | yes |
| 4 syntax families | many engines/plugins | 1–2 families | 4, distinct maths each |
| Confirm with 2nd payload | yes | rarely | yes |
| Engine fingerprint | yes | rarely | yes (Jinja2 marker) |
| Interactive mode | `-i` shell | `input()` prompts | `[?]` prompts |
| Args mode | `-u -d -m -e -l` | rarely | `--url --param --method` |
| Banner + colours | yes | yes | yes |
| Report to file | some | rarely | yes, with remediation |
| Exploitation (RCE/shell) | yes | sometimes | **no — PDF forbids it** |
| Lab-only / legal note | disclaimer | rarely | yes, in banner + README |

## 6. Concrete improvements to apply next (within the PDF)

These fit the PDF and the research — none of them add exploitation:
1. `--help` already works via argparse — document it in README (done in v2).
2. Add a `[!] LEGAL DISCLAIMER` line under the banner, like SSTImap:
"Lab only — only test systems you own or have permission to test."
3. Add `-i` as an explicit alias for interactive mode
(`python run.py probe -i`), matching SSTImap's flag.
4. Add `--version` flag printing `SSTIProbe 2.0 by CyberBoy50`.
5. (Stretch, PDF) Blind detection by timing + form discovery — only if
time is left before submission; both are listed as stretch in the PDF.
6. Keep the report file — SSTImap's own future-plans list includes
"Saving found vulnerabilities / Reports in HTML or other format",
so a saved report is already the professional standard.

## Sources
- SSTImap README — https://github.com/szybnev/SSTImap
- tplmap — https://github.com/epinna/tplmap
- SSTImap (maintained fork) — https://github.com/vladko312/SSTImap
- NaldyXploit-ID/SSTI-Detector — https://github.com/NaldyXploit-ID/SSTI-Detector
- TInjA (SSTI+CSTI scanner) — https://github.com/Hackmanit/TInjA
