# SSTIProbe — Step by Step Guide (Roman Urdu)

Ye guide tumhe har step samjhata hai: **kya kiya, kyun kiya, aur kaise run karna hai.**
PDF ke 7 steps ke mutabiq banaya gaya hai. Deadline: **25 Nov 2026, aaj.**

> Sirf apne lab par test karna hai (`127.0.0.1`). Kisi real website par kabhi nahi.

---

## Pehle — Setup (2 minute, Windows / Mac / Linux — sab par same)

```bash
cd sstiprobe
python run.py setup        # Windows: python, Mac/Linux: python3
```

**Kya ho raha hai:** `run.py` tumhare OS ke hisaab se sahi venv Python dhoondta hai —
Mac/Linux par `venv/bin/python`, Windows par `venv\Scripts\python.exe` — venv banata hai
aur `requirements.txt` install karta hai. `venv` ek alag Python environment hai, taake
Flask/requests tumhare system Python ko kharab na karein. `requirements.txt` mein sirf
2 cheezein hain: `requests` (HTTP bhejne ke liye) aur `flask` (lab app ke liye).

**Windows par:** Python install karte waqt "Add python.exe to PATH" tick karna.
Agar `python` na chale to `py` likho: `py run.py setup`.
**Double-click wala tareeqa:** Windows par `run_lab.bat`, Mac/Linux par `./run_lab.sh` —
ye khud setup bhi kar lete hain, kuch type karne ki zaroorat nahi.

> Purane commands (`./venv/bin/python ...`) sirf Mac/Linux par chalte thay — ab
> `python run.py lab` / `python run.py probe ...` teeno OS par same hai. Tool khud
> (`sstiprobe.py`, `lab_app.py`) pure Python hai, usmein koi OS-specific code nahi hai.

---

## Step 1 — Baseline fetch karo

**File:** `sstiprobe.py` → `fetch_baseline()` aur `send_request()`
**Kya:** Pehle normal request bhejo, bina payload ke. Value hai `SSTIProbeBaseline`.
**Kyun:** Normal page kaisa dikhta hai, ye pata hona chahiye — warna baad mein samajh
nahi aayega ke payload ne page badla ya page pehle se hi aisa tha.

**Test:**

```bash
python run.py lab        # Terminal 1 — lab chalao
curl "http://127.0.0.1:5000/vuln?name=Cyber"   # Terminal 2 — jawab: Hello Cyber!
```

Result tha: `Hello Cyber!` — status 200, length 24 characters. Baseline mil gaya. ✅

---

## Step 2 — Ek detection payload

**File:** `sstiprobe.py` → `build_payload()`
**Kya:** `{{7*7}}` bhejo. Ye sirf maths hai, koi exploit nahi.
**Kyun:** Agar template engine isko evaluate kare, jawab mein `49` aayega.
Agar safe app ho, to `{{7*7}}` waisa ka waisa wapas aayega.

**Test (browser ya curl):**

```bash
curl "http://127.0.0.1:5000/vuln?name=%7B%7B7*7%7D%7D"
# Jawab: Hello 49!   <-- evaluate hua, vulnerable hai
curl "http://127.0.0.1:5000/safe?name=%7B%7B7*7%7D%7D"
# Jawab: Hello {{7*7}}!   <-- evaluate nahi hua, safe hai
```

---

## Step 3 — Evaluation check (function)

**File:** `sstiprobe.py` → `check_evaluation(baseline, test_body, payload, expected_result)`
**Kya:** Function 3 faisle karta hai:

| Faisla | Matlab |
|---|---|
| `evaluated` | `49` jawab mein hai, `{{7*7}}` nahi — engine ne maths chalaya |
| `reflected` | `{{7*7}}` jawab mein hai, `49` nahi — sirf echo hua |
| `no-change` | Dono mein se kuch nahi |

**Test — ye run karke dikhao, sir ko ye pasand aayega:**

```bash
python run.py test
```

**Asli result:**

```
PASS: evaluated  -> got 'evaluated', expected 'evaluated'
PASS: reflected  -> got 'reflected', expected 'reflected'
PASS: no-change  -> got 'no-change', expected 'no-change'
All 3 Step-3 tests passed.
```

---

## Step 4 — Charon syntax families

**File:** `sstiprobe.py` → `PAYLOADS` table
**Kya:** Har family ke liye alag multiplication, taake pata chale kis family ne hit kiya:

| Family | Payload | Jawab |
|---|---|---|
| `{{ }}` double-brace | `{{7*7}}` | 49 |
| `${ }` dollar-brace | `${8*8}` | 64 |
| `#{ }` hash-brace | `#{9*9}` | 81 |
| `*{ }` star-brace | `*{6*7}` | 42 |

**Kyun table, alag code nahi:** Ek table se 4 families chalti hain — code chhota,
saaf, aur nayi family add karna ek line ka kaam hai. Yehi "code clarity" ke 15 marks hain.

**Test — 2 alag engines:**

```bash
python run.py probe --url http://127.0.0.1:5000/vuln --param name
# {{ }} se detect hua

python run.py probe --url http://127.0.0.1:5000/vuln-dollar --param name
# ${ } se detect hua — doosra engine, apni family se
```

---

## Step 5 — Engine fingerprinting

**File:** `sstiprobe.py` → `fingerprint_engine()`
**Kya:** Evaluate confirm hone ke BAAD, `{{7*'7'}}` bhejo.
Jinja2 (Python) mein string repeat hoti hai: `7*'7'` = `7777777`.
**Kyun:** Sirf "vulnerable hai" kehna kaafi nahi — kaunsa engine hai, ye bhi batana hai.
Report mein aaya: `Jinja2 (Python string-repeat marker 7*'7' = 7777777)`.

**Confirm bhi isi step mein:** Doosri multiplication `{{7*8}}` → `56` bhi check hoti hai.
Ek hit coincidence ho sakta hai, do alag jawab nahi.

---

## Step 6 — CLI arguments aur report

**File:** `sstiprobe.py` → `parse_args()` (argparse) aur `build_report()`
**Kya:** Ab URL, param aur method command line se aate hain — code mein hardcode nahi:

```bash
python run.py probe --url http://127.0.0.1:5000/vuln --param name --method POST
python run.py probe --url http://127.0.0.1:5000/vuln --param name --method POST --json
python run.py probe --url http://127.0.0.1:5000/safe --param name --output report_safe.txt
```

**Report:** Har run screen par report dikhata hai AUR file mein save karta hai
(default `sstiprobe_report.txt`). Report mein hota hai: vulnerable parameter,
evidence (`Hello 49!`), engine, aur remediation note.

**Stretch features (bonus):** POST form aur POST JSON dono kaam karte hain.

---

## Step 7 — Full run on lab app (final test)

**Test — teeno runs, asli results:**

```bash
# 1. Vulnerable {{ }} — VULNERABLE, Jinja2, 49 / 56
python run.py probe --url http://127.0.0.1:5000/vuln --param name

# 2. Vulnerable ${ } — VULNERABLE, 64 / 72
python run.py probe --url http://127.0.0.1:5000/vuln-dollar --param name

# 3. Safe — NOT VULNERABLE (charon families sirf "reflected")
python run.py probe --url http://127.0.0.1:5000/safe --param name
```

Report `sstiprobe_report.txt` mein check karo: vulnerable parameter (`name`),
evidence (`Hello 49!`), engine (Jinja2) — teeno sahi hain. ✅

---

## Lab app kya hai? (`lab_app.py`)

| Route | Kya hai |
|---|---|
| `/vuln` | **Vulnerable, jaan boojh kar.** `render_template_string(f"Hello {name}!")` — input template mein chipka diya, is liye evaluate hota hai. |
| `/vuln-dollar` | Wahi flaw, `${ }` syntax mein — lekin asli **Mako** engine (v2.8 se). |
| `/safe` | **Fix.** `render_template_string("Hello {{ name }}!", name=name)` — input VARIABLE ke tor par jata hai, template code nahi banta. |

Yehi farq remediation note mein likha hai — aur yehi tumhari defensive lesson hai:
**user input ko kabhi template mat banao.**

---

## GitHub par publish karna (10 marks)

```bash
cd sstiprobe
git init
git add sstiprobe.py lab_app.py test_evaluation.py README.md requirements.txt sstiprobe_report.txt
git commit -m "SSTIProbe — SSTI detection tool (lab only)"
# GitHub par naya repo banao (SSTIProbe), phir:
git remote add origin https://github.com/<tumhara-username>/SSTIProbe.git
git push -u origin main
```

`venv/` aur `__pycache__/` commit mat karna — wo tumhare computer ke liye hain.

---

## Agar sir poochhein to — ek line mein jawab

- **SSTI kya hai?** User input template engine mein code ban ke evaluate ho jaye.
- **Detect kaise kiya?** `{{7*7}}` bheja, `49` mila — maths chala, matlab evaluate hua.
- **Confirm kaise kiya?** Doosri maths `{{7*8}}` → `56`, phir fingerprint `7*'7'` → `7777777` (Jinja2).
- **Fix kya hai?** Input ko variable banao, template string mein chipkao mat.
