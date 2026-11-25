#!/bin/sh
# SSTIProbe — run the tool (macOS / Linux)
# Usage:  ./run_probe.sh --url http://127.0.0.1:5000/vuln --param name
python3 run.py probe "$@"
