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


if __name__ == "__main__":
    # ruleid: achilles.python.flask-debug
    app.run(host="0.0.0.0", debug=True)
    # ok: achilles.python.flask-debug
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
