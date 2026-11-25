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

  python run.py probe --url http://127.0.0.1:5000/vuln --param name
      Run SSTIProbe. Everything after "probe" is passed to sstiprobe.py.

  python run.py test
      Run the Step 3 evaluation test (3 verdicts).

On Windows, if "python" is not recognised, use "py" instead:
  py run.py lab
"""
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


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        print("Commands: setup | lab | probe <sstiprobe args...> | test")
        return 0

    command, rest = argv[1], argv[2:]

    if command == "setup":
        ensure_venv()
        return 0
    if command == "lab":
        return run_script(ensure_venv(), "lab_app.py", rest)
    if command == "probe":
        if not rest:
            print("Example: python run.py probe --url http://127.0.0.1:5000/vuln --param name")
            return 1
        return run_script(ensure_venv(), "sstiprobe.py", rest)
    if command == "test":
        return run_script(ensure_venv(), "test_evaluation.py", rest)

    print(f"Unknown command: {command!r}")
    print("Commands: setup | lab | probe <sstiprobe args...> | test")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
