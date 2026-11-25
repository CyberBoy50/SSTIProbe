# SSTIProbe — Setup on YOUR machines

**Host:** Windows 11 · **VM 1:** Kali Linux · **VM 2:** Windows 10

One rule for all three: **lab aur tool ek hi machine par chalao.**
Lab sirf `127.0.0.1` (localhost) par sunta hai, is liye host ka lab VM se
nahi khulega, aur VM ka lab host se nahi. Har machine par dono cheezein
ek saath chalao — wahi machine, wahi `127.0.0.1:5000`.

Files har machine tak kaise pahunchao: neeche Option A ya B — jo asaan lage.
`venv/` copy mat karo, wo har machine par khud banega.

---

## Option A — GitHub se (recommended, teeno machines par same)

1. Host (Win 11) par GitHub repo banao aur push karo (guide: `STEP_BY_STEP_GUIDE.md`, end).
2. Har VM / host par:
   ```bash
   git clone https://github.com/<tumhara-username>/SSTIProbe.git
   cd SSTIProbe
   ```

## Option B — Zip copy karo

1. `SSTIProbe.zip` (is project ke saath mili hai) ko VM mein copy karo —
   VMware/VirtualBox Shared Folder, drag-and-drop, ya USB se.
2. VM mein unzip karo, folder ke andar jao.

---

## 1) Windows 11 — Host

**Python install (ek dafa):**
1. https://www.python.org/downloads/ se Python 3.12 ya 3.13 download karo.
2. Install karte waqt **"Add python.exe to PATH" tick zaroor karo** — ye sab se
   common ghalti hai. Phir `Install Now`.
3. Check karo (cmd ya PowerShell — `Win + R`, likho `cmd`):
   ```cmd
   python --version
   ```
   Jawab `Python 3.12.x` jaisa aana chahiye. Agar `python` na pehchane to
   `py --version` try karo, aur aage ke commands mein `python` ki jagah `py` likho.

**Chalao:**
```cmd
cd SSTIProbe
python run.py setup
```
Pehli baar venv banega aur Flask/requests install honge (1–2 minute, internet chahiye).

Terminal 1 — lab:
```cmd
python run.py lab
```
Ya double-click: `run_lab.bat`. Windows Firewall poochhe to **Allow** karo —
sirf localhost hai, bahar se koi nahi aa sakta.

Terminal 2 — tool:
```cmd
python run.py probe --url http://127.0.0.1:5000/vuln --param name
python run.py probe --url http://127.0.0.1:5000/safe --param name
python run.py test
```
Ya double-click: `run_probe.bat` (phir usmein arguments nahi de sakte — wo
default vuln run karta hai; full control ke liye cmd use karo).

---

## 2) Kali Linux — VM

Kali mein Python pehle se hota hai, bas `venv` wala package kabhi kabhi
missing hota hai. Ek dafa:

```bash
sudo apt update && sudo apt install -y python3-venv python3-pip
python3 --version
```

**Chalao (Terminal):**
```bash
cd SSTIProbe
python3 run.py setup
```

Terminal 1 — lab:
```bash
python3 run.py lab
# ya: ./run_lab.sh
```

Terminal 2 — tool:
```bash
python3 run.py probe --url http://127.0.0.1:5000/vuln --param name
python3 run.py probe --url http://127.0.0.1:5000/vuln-dollar --param name
python3 run.py probe --url http://127.0.0.1:5000/safe --param name
python3 run.py test
```

**Kali tip:** Agar VM mein internet na ho to `run.py setup` fail hoga —
pehle VM ka network NAT/Bridged check karo, phir dobara chalao.

---

## 3) Windows 10 — VM

Bilkul Windows 11 host jaisa — koi farq nahi:

1. https://www.python.org/downloads/ se Python install karo,
   **"Add python.exe to PATH" tick karo**.
2. cmd mein:
   ```cmd
   cd SSTIProbe
   python run.py setup
   python run.py lab
   ```
   (doosri cmd window mein)
   ```cmd
   python run.py probe --url http://127.0.0.1:5000/vuln --param name
   ```

---

## Har machine par expected result (same)

| Command | Result |
|---|---|
| `run.py test` | 3 PASS (evaluated / reflected / no-change) |
| `probe ... /vuln` | **VULNERABLE**, Jinja2, `{{7*7}}` → 49, confirm → 56 |
| `probe ... /vuln-dollar` | **VULNERABLE**, `${8*8}` → 64 |
| `probe ... /safe` | **NOT VULNERABLE** |

## Agar kuch na chale — quick checks

- `python: command not found` (Windows) → Python PATH mein nahi; dobara
  install karo, "Add to PATH" tick ke saath, ya `py` use karo.
- `ensurepip is not available` (Kali) → `sudo apt install -y python3-venv`
  chalao, phir `run.py setup` dobara.
- `could not reach the lab app` → pehle `run.py lab` wali window chal rahi
  honi chahiye, aur URL mein `127.0.0.1:5000` hona chahiye.
- Port 5000 busy → lab do dafa chal raha hai; ek window band karo.
