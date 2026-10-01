import subprocess


def run(cmd):
    # B602: subprocess call with shell=True — command injection risk.
    return subprocess.Popen(cmd, shell=True)


# B105: hardcoded password.
PASSWORD = "hunter2"
