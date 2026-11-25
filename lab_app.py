"""
Lab app for SSTIProbe — ONLY for testing on your own machine.
DO NOT run this on a public server, and NEVER point SSTIProbe at a
real website you do not own.

What this file is:
  A tiny Flask app with 4 endpoints on http://127.0.0.1:5000
    /vuln         -> VULNERABLE, Jinja2 (real engine), {{ }} syntax
    /vuln-dollar -> VULNERABLE, Mako (real engine), ${ } syntax
    /safe        -> SAFE, user input is passed as a variable, never
                    rendered as a template
    /blind       -> BLIND: input lands inside {% if ... %} (code context),
                    nothing is reflected — the tool must use boolean
                    blind detection (true expression -> OK, false -> FAIL)

Why two vulnerable endpoints?
  PDF Step 4 says: test against lab endpoints for TWO different
  engines — each must be detected by its own family. Since v2.8 both
  are REAL engines: Jinja2 evaluates {{7*7}} and Mako evaluates
  ${7*7}. (Twig / ERB / Smarty need PHP or Ruby runtimes, so they are
  not in this Python lab — but SSTIProbe still detects all six syntax
  families on any site it is pointed at.)

Run (Windows, macOS, Linux — same command):
    python run.py lab
    # then open http://127.0.0.1:5000/ in your browser
"""
from flask import Flask, request, render_template_string

try:
    from mako.template import Template
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Mako is not installed — run: python run.py setup "
        "(it installs Mako for the /vuln-dollar endpoint).") from exc

app = Flask(__name__)


def get_name():
    """Read the 'name' value from query, form body, OR a JSON body.
    Without the JSON branch, --method POST --json probes would never
    reach the template (Flask's request.values ignores JSON bodies)."""
    name = request.values.get("name")
    if name is None:
        data = request.get_json(silent=True) or {}
        name = data.get("name")
    return name if name is not None else "Guest"


@app.route("/")
def home():
    return (
        "<h1>SSTIProbe Lab (local only)</h1>"
        "<p>Try these in your browser:</p>"
        "<ul>"
        "<li><a href='/vuln?name=Cyber'>/vuln?name=Cyber</a> — vulnerable, Jinja2 {{ }}</li>"
        "<li><a href='/vuln-dollar?name=Cyber'>/vuln-dollar?name=Cyber</a> — vulnerable, Mako ${ }</li>"
        "<li><a href='/safe?name=Cyber'>/safe?name=Cyber</a> — safe</li>"
        "<li><a href='/blind?name=1==1'>/blind?name=1==1</a> — blind (try 7*7==49 vs 7*7==50)</li>"
        "</ul>"
        "<h2>Try the form (for --discover)</h2>"
        "<form action='/vuln' method='get'>"
        "Name: <input name='name' value='Cyber'>"
        "<input type='submit' value='Say hello'>"
        "</form>"
        "<p>The form above posts to /vuln. SSTIProbe's --discover reads this "
        "page, finds the form, and probes its <b>name</b> input by itself.</p>"
        "<p>Vulnerable test: replace Cyber with {{7*7}} — "
        "if you see 49, the template evaluated it.</p>"
    )


@app.route("/vuln", methods=["GET", "POST"])
def vuln():
    # VULNERABLE ON PURPOSE (lab only):
    # user input is glued straight into the template string,
    # so Jinja2 evaluates it as code. {{7*7}} becomes 49.
    name = get_name()
    return render_template_string(f"Hello {name}!")


@app.route("/vuln-dollar", methods=["GET", "POST"])
def vuln_dollar():
    # VULNERABLE ON PURPOSE (lab only), REAL Mako engine:
    # user input is glued straight into the Mako template string,
    # so Mako evaluates it as code. ${7*7} becomes 49.
    # (Mako leaves {{7*7}} untouched — it is not a Jinja2 template.)
    name = get_name()
    return Template(f"Hello {name}!").render()


@app.route("/blind", methods=["GET", "POST"])
def blind():
    # BLIND ON PURPOSE (lab only): input lands inside {% if ... %},
    # so it is EVALUATED but never printed. The only signal is the
    # branch taken: true expression -> "OK", false -> "FAIL".
    # SSTIProbe's boolean blind check sends 7*7==49 (true) and
    # 7*7==50 (false) and compares the two responses.
    # Baseline value "SSTIProbeBaseline" is an undefined name -> falsy -> FAIL.
    name = get_name()
    return render_template_string(f"{{% if {name} %}}OK{{% else %}}FAIL{{% endif %}}")


@app.route("/safe", methods=["GET", "POST"])
def safe():
    # SAFE: input goes in as a VARIABLE, never as template code.
    # {{7*7}} is printed literally, never evaluated to 49.
    # This is the fix the report recommends.
    name = get_name()
    return render_template_string("Hello {{ name }}!", name=name)


if __name__ == "__main__":
    # 127.0.0.1 = only your own computer can reach it.
    app.run(host="127.0.0.1", port=5000, debug=False)
