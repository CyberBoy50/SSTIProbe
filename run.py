#!/usr/bin/env python3
"""
SSTIProbe — cross-platform launcher (Windows, macOS, Linux).

Why this file exists:
  On macOS/Linux the venv Python lives at  venv/bin/python
  On Windows it lives at              venv\\Scripts\\python.exe
  So "./venv/bin/python ..." breaks on Windows, and
  "venv\\Scripts\\python.exe ..." breaks on Mac/Linux.
  This launcher finds the right path for YOUR operating system,
  creates the venv + installs requirements if needed, then runs
  the tool or the lab. One command works everywhere.

Usage — same on Windows (cmd / PowerShell), macOS and Linux:
  python run.py setup
      Create venv + install requests + flask (first time only).

  python run.py lab
      Start the lab app at http://127.0.0.1:5000

  python run.py probe
      Run SSTIProbe with no arguments -> the numbered menu opens.
      Everything after "probe" is passed to sstiprobe.py, e.g.
      python run.py probe --url http://127.0.0.1:5000/vuln --param name

  python run.py test
      Run the Step 3 evaluation test (3 verdicts).

  python run.py doctor
      Check everything: Python version, venv, requests, flask,
      and whether the lab is answering on port 5000.

On Windows, if "python" is not recognised, use "py" instead:
  py run.py lab
"""
import os
import socket
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / "venv"


def venv_python() -> Path:
    """Return the venv Python for this OS."""
    if sys.platform == "win32":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def ensure_venv() -> Path:
    """Create the venv + install requirements if they are missing."""
    python = venv_python()
    if not python.exists():
        print(f"[run.py] Creating virtual environment in {VENV_DIR} ...")
        venv.create(VENV_DIR, with_pip=True)
        print("[run.py] Installing requirements (requests, flask) ...")
        subprocess.check_call(
            [str(python), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")]
        )
        print("[run.py] Setup done.")
    return python


def run_script(python: Path, script: str, args: list[str]) -> int:
    """Run one of our scripts with the venv Python. Returns exit code."""
    return subprocess.call([str(python), str(ROOT / script), *args])


def doctor() -> int:
    """Check the setup and say what is missing, if anything."""
    ok = True

    def check(name: str, good: bool, hint: str = "") -> None:
        nonlocal ok
        mark = "[+]" if good else "[!]"
        print(f"{mark} {name}" + ("" if good else f"  -> {hint}"))
        if not good:
            ok = False

    check(f"Python {sys.version.split()[0]} (need 3.10+)",
          sys.version_info >= (3, 10), "install Python 3.10+ from python.org")
    python = venv_python()
    check(f"venv python at {python}", python.exists(),
          "run: python run.py setup")
    if python.exists():
        for module in ("requests", "flask"):
            proc = subprocess.run(
                [str(python), "-c", f"import {module}"],
                capture_output=True)
            check(f"{module} installed in venv", proc.returncode == 0,
                  "run: python run.py setup")
    try:
        with socket.create_connection(("127.0.0.1", 5000), timeout=2):
            lab_up = True
    except OSError:
        lab_up = False
    check("Lab answering on http://127.0.0.1:5000", lab_up,
          "start it in a second terminal: python run.py lab")
    print("Doctor: all good." if ok else "Doctor: fix the [!] lines above.")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        print("Commands: setup | lab | probe <sstiprobe args...> | test | doctor")
        return 0

    command, rest = argv[1], argv[2:]

    if command == "setup":
        ensure_venv()
        return 0
    if command == "lab":
        # Replace this process with the lab (os.execv) instead of spawning
        # it as a child: when the user stops the lab (Ctrl+C), nothing is
        # left running in the background. (A spawned child would survive
        # if only the launcher was killed — that left stale lab processes.)
        python = ensure_venv()
        os.execv(str(python), [str(python), str(ROOT / "lab_app.py"), *rest])
        return 0  # execv never returns
    if command == "probe":
        # No args is fine: sstiprobe.py opens its menu (GhostTrack style).
        return run_script(ensure_venv(), "sstiprobe.py", rest)
    if command == "test":
        return run_script(ensure_venv(), "test_evaluation.py", rest)
    if command == "doctor":
        return doctor()

    print(f"Unknown command: {command!r}")
    print("Commands: setup | lab | probe <sstiprobe args...> | test | doctor")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
