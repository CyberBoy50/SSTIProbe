@echo off
REM SSTIProbe — run the tool (Windows, cmd / PowerShell)
REM Example:  run_probe.bat --url http://127.0.0.1:5000/vuln --param name
REM If "python" is not recognised on your PC, change it to "py" below.
python run.py probe %*
pause
