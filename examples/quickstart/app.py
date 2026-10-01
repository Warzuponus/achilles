"""A deliberately vulnerable sample for the Achilles quickstart. Do not deploy."""
import os
import sqlite3
import subprocess


def run(cmd):
    # Command injection: untrusted input reaches a shell.
    return subprocess.call(cmd, shell=True)


def lookup(conn: sqlite3.Connection, name):
    # SQL injection: string-built query.
    return conn.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()


def evaluate(expr):
    # Code injection: eval of untrusted input.
    return eval(expr)


if __name__ == "__main__":
    run(os.environ.get("CMD", "echo hi"))
