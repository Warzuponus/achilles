import subprocess


def disk_free():
    """Return free space on the data volume."""
    return subprocess.check_output("df -h /data | tail -n +2", shell=True)
