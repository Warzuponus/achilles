# Tests for configs/rules/achilles-python.yaml (opengrep --test). Never run.
# "ruleid: X" says the next line must be reported by rule X; "ok: X" says it must not.
import hashlib
import os
import pickle
import shutil
import ssl
import subprocess

import requests
import yaml
from flask import Flask, render_template_string, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)


def sql(db, name, user_id):
    cur = db.cursor()
    # ruleid: achilles.python.sql-string-building
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ruleid: achilles.python.sql-string-building
    cur.execute("SELECT * FROM users WHERE id = %s" % user_id)
    # ruleid: achilles.python.sql-string-building
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    # ruleid: achilles.python.sql-string-building
    cur.execute("SELECT * FROM t WHERE a = {}".format(name))
    query = f"DELETE FROM sessions WHERE user = '{name}'"
    # ruleid: achilles.python.sql-string-building
    cur.execute(query)
    # ok: achilles.python.sql-string-building
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    # ok: achilles.python.sql-string-building
    cur.execute("SELECT count(*) FROM users")
    # ok: achilles.python.sql-string-building
    cur.execute(f"SELECT count(*) FROM users")


def orm(User, term):
    # ruleid: achilles.python.sql-injection-orm-raw
    User.objects.raw(f"SELECT * FROM app_user WHERE name = '{term}'")
    # ok: achilles.python.sql-injection-orm-raw
    User.objects.raw("SELECT * FROM app_user WHERE name = %s", [term])
    sql_query = "SELECT * FROM app_user WHERE name='" + term + "' AND active=1"
    # ruleid: achilles.python.sql-injection-orm-raw
    User.objects.raw(sql_query)
    fixed_query = "SELECT * FROM app_user WHERE active = 1"
    # ok: achilles.python.sql-injection-orm-raw
    User.objects.raw(fixed_query)


def commands(host):
    # ruleid: achilles.python.os-command
    os.system("ping -c 1 " + host)
    # ruleid: achilles.python.os-command
    os.popen(f"nslookup {host}")
    # ok: achilles.python.os-command
    os.system("uptime")
    # ok: achilles.python.os-command
    subprocess.run(["ping", "-c", "1", host])


def code(snippet):
    # ruleid: achilles.python.code-injection-exec
    exec(snippet)
    # ok: achilles.python.code-injection-exec
    exec("print('constant')")


@app.route("/download")
def download():
    name = request.args.get("file", "")
    # ruleid: achilles.python.path-traversal
    return send_file(os.path.join("/srv/uploads", name))


@app.route("/read")
def read():
    path = request.args["path"]
    # ruleid: achilles.python.path-traversal
    with open(path) as f:
        return f.read()


@app.route("/safe-download")
def safe_download():
    name = secure_filename(request.args.get("file", ""))
    # ok: achilles.python.path-traversal
    return send_file(os.path.join("/srv/uploads", name))


@app.route("/remove", methods=["POST"])
def remove():
    target = request.form["dir"]
    # ruleid: achilles.python.path-traversal
    shutil.rmtree(target)


def not_a_request(path):
    # ok: achilles.python.path-traversal
    return open(path).read()


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    # ruleid: achilles.python.ssrf
    return requests.get(url, timeout=5).text


@app.route("/fixed")
def fixed():
    q = request.args.get("q", "")
    # ok: achilles.python.ssrf
    return requests.get("https://api.example.com/search", params={"q": q}).text


@app.route("/greet")
def greet():
    tmpl = request.args.get("t", "")
    # ruleid: achilles.python.template-injection
    return render_template_string(tmpl)


@app.route("/greet-safe")
def greet_safe():
    name = request.args.get("name", "")
    # ok: achilles.python.template-injection
    return render_template_string("Hello {{ name }}", name=name)


@app.route("/session", methods=["POST"])
def load_session():
    # ruleid: achilles.python.untrusted-deserialization
    return {"session": pickle.loads(request.get_data())}


def load_cache(path):
    with open(path, "rb") as f:
        # ok: achilles.python.untrusted-deserialization
        return pickle.load(f)


def config(text):
    # ruleid: achilles.python.yaml-unsafe-load
    yaml.load(text)
    # ruleid: achilles.python.yaml-unsafe-load
    yaml.load(text, Loader=yaml.Loader)
    # ok: achilles.python.yaml-unsafe-load
    yaml.load(text, Loader=yaml.SafeLoader)
    # ok: achilles.python.yaml-unsafe-load
    yaml.safe_load(text)


def hashes(password, blob):
    # ruleid: achilles.python.weak-hash
    hashlib.md5(password.encode()).hexdigest()
    # ruleid: achilles.python.weak-hash
    hashlib.new("sha1", password.encode())
    # ok: achilles.python.weak-hash
    hashlib.md5(blob, usedforsecurity=False).hexdigest()
    # ok: achilles.python.weak-hash
    hashlib.sha256(blob).hexdigest()


def tls(url):
    # ruleid: achilles.python.tls-verification-disabled
    requests.get(url, verify=False)
    # ruleid: achilles.python.tls-verification-disabled
    ssl._create_unverified_context()
    # ok: achilles.python.tls-verification-disabled
    requests.get(url, verify="/etc/ssl/internal-ca.pem")


@app.route("/login", methods=["POST"])
def login_lab(db, Login):
    name = request.POST.get("name")
    password = request.POST.get("pass")
    sql_query = "SELECT * FROM login WHERE user='" + name + "' AND password='" + password + "'"
    # ruleid: achilles.python.sql-injection
    Login.objects.raw(sql_query)
    cur = db.cursor()
    # ruleid: achilles.python.sql-injection
    cur.execute(request.form["query"])
    # ok: achilles.python.sql-injection
    cur.execute("SELECT * FROM t WHERE name = %s", [name])
    # ok: achilles.python.sql-injection
    cur.execute("SELECT * FROM t WHERE id = %s", [int(request.args["id"])])


@app.route("/hello")
def hello(HttpResponse, mark_safe):
    who = request.GET.get("name", "")
    # ruleid: achilles.python.reflected-xss
    HttpResponse("<h1>Hello " + who + "</h1>")
    # ruleid: achilles.python.reflected-xss
    mark_safe("<b>%s</b>" % who)
    # ok: achilles.python.reflected-xss
    HttpResponse("<h1>Hello " + escape(who) + "</h1>")
    # ok: achilles.python.reflected-xss
    HttpResponse(who, content_type="text/plain")
    # ruleid: achilles.python.reflected-xss
    return make_response("<p>" + request.args.get("q", "") + "</p>")


def signing_keys(jwt, payload, token):
    # ruleid: achilles.python.hardcoded-signing-key
    app.secret_key = "your-secret-key-here"
    # ruleid: achilles.python.hardcoded-signing-key
    app.config["SECRET_KEY"] = "dev"
    # ok: achilles.python.hardcoded-signing-key
    app.secret_key = os.environ["SECRET_KEY"]
    # ruleid: achilles.python.hardcoded-signing-key
    jwt.encode(payload, "PYGOAT", algorithm="HS256")
    # ok: achilles.python.hardcoded-signing-key
    jwt.encode(payload, os.environ["JWT_KEY"], algorithm="HS256")


# ruleid: achilles.python.hardcoded-signing-key
SECRET_COOKIE_KEY = "PYGOAT"
# ok: achilles.python.hardcoded-signing-key
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")


def xml_parsing(make_parser, feature_external_ges, etree, body):
    parser = make_parser()
    # ruleid: achilles.python.xxe
    parser.setFeature(feature_external_ges, True)
    # ok: achilles.python.xxe
    parser.setFeature(feature_external_ges, False)
    # ruleid: achilles.python.xxe
    etree.XMLParser(resolve_entities=True, no_network=False)
    # ok: achilles.python.xxe
    etree.XMLParser(resolve_entities=False)


if __name__ == "__main__":
    # ruleid: achilles.python.flask-debug
    app.run(host="0.0.0.0", debug=True)
    # ok: achilles.python.flask-debug
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
