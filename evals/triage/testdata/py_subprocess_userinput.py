import subprocess

from flask import request


def archive():
    """Create a tarball of the directory named in the request."""
    directory = request.args.get("dir")
    return subprocess.check_output("tar czf backup.tgz " + directory, shell=True)
