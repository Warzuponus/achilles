# Tests for the Python rules in configs/rules/achilles-baseline.yaml (opengrep --test).
import ast
import subprocess


def run(expr, host):
    # ruleid: achilles.python.dangerous-eval
    eval(expr)
    # ok: achilles.python.dangerous-eval
    ast.literal_eval(expr)
    # ruleid: achilles.python.subprocess-shell-true
    subprocess.run("ping -c 1 " + host, shell=True)
    # ok: achilles.python.subprocess-shell-true
    subprocess.run(["ping", "-c", "1", host])
