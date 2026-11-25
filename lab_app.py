"""
Lab app for SSTIProbe — ONLY for testing on your own machine.
DO NOT run this on a public server, and NEVER point SSTIProbe at a
real website you do not own.

What this file is:
  A tiny Flask app with 3 endpoints on http://127.0.0.1:5000
    /vuln         -> VULNERABLE, Jinja2, {{ }} syntax
    /vuln-dollar -> VULNERABLE, Jinja2 with ${ } delimiters
                    (stands in for a ${ } engine, e.g. Mako/FreeMarker style)
    /safe        -> SAFE, user input is passed as a variable, never
                    rendered as a template

Why two vulnerable endpoints?
  PDF Step 4 says: test against lab endpoints for TWO different
  engines — each must be detected by its own family.

Run (Windows, macOS, Linux — same command):
    python run.py lab
    # then open http://127.0.0.1:5000/ in your browser
"""
from flask import Flask, request, render_template_string
from jinja2 import Environment

app = Flask(__name__)

# A second Jinja2 engine that uses ${ } instead of {{ }}.
# Same idea, different syntax family — that is what Step 4 tests.
dollar_env = Environment(variable_start_string="${", variable_end_string="}")


@app.route("/")
def home():
    return (
        "<h1>SSTIProbe Lab (local only)</h1>"
        "<p>Try these in your browser:</p>"
        "<ul>"
        "<li><a href='/vuln?name=Cyber'>/vuln?name=Cyber</a> — vulnerable, {{ }}</li>"
        "<li><a href='/vuln-dollar?name=Cyber'>/vuln-dollar?name=Cyber</a> — vulnerable, ${ }</li>"
        "<li><a href='/safe?name=Cyber'>/safe?name=Cyber</a> — safe</li>"
        "</ul>"
        "<p>Vulnerable test: replace Cyber with {{7*7}} — "
        "if you see 49, the template evaluated it.</p>"
    )


@app.route("/vuln", methods=["GET", "POST"])
def vuln():
    # VULNERABLE ON PURPOSE (lab only):
    # user input is glued straight into the template string,
    # so Jinja2 evaluates it as code. {{7*7}} becomes 49.
    name = request.values.get("name", "Guest")
    return render_template_string(f"Hello {name}!")


@app.route("/vuln-dollar", methods=["GET", "POST"])
def vuln_dollar():
    # Same flaw, ${ } syntax family.
    name = request.values.get("name", "Guest")
    template = dollar_env.from_string(f"Hello {name}!")
    return template.render()


@app.route("/safe", methods=["GET", "POST"])
def safe():
    # SAFE: input goes in as a VARIABLE, never as template code.
    # {{7*7}} is printed literally, never evaluated to 49.
    # This is the fix the report recommends.
    name = request.values.get("name", "Guest")
    return render_template_string("Hello {{ name }}!", name=name)


if __name__ == "__main__":
    # 127.0.0.1 = only your own computer can reach it.
    app.run(host="127.0.0.1", port=5000, debug=False)
