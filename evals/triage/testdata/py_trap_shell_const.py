import subprocess

DATA_DIR = "/var/app/data"


def archive():
    """Create a tarball of the data directory."""
    user_input = DATA_DIR
    return subprocess.check_output("tar czf backup.tgz " + user_input, shell=True)
