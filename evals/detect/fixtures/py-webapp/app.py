"""Deliberately vulnerable demo service. Benchmark fixture: never run, never ship."""
import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
from flask import Flask, request, send_file

app = Flask(__name__)
db = sqlite3.connect("app.db", check_same_thread=False)


@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    cur = db.cursor()
    cur.execute(f"SELECT id, email FROM users WHERE name = '{name}'")
    return {"rows": cur.fetchall()}


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    out = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
    return out.stdout


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    return str(eval(expr))


@app.route("/download")
def download():
    name = request.args.get("file", "")
    return send_file(os.path.join("/srv/uploads", name))


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    return requests.get(url, timeout=5).text


@app.route("/session", methods=["POST"])
def load_session():
    return {"session": pickle.loads(request.get_data())}


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
