"""Automated test stage: runs the project's own tests inside the working copy."""
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path


def run_tests(workdir, cmd=None, timeout=180):
    workdir = Path(workdir)
    if cmd:
        argv = shlex.split(cmd)
    elif (workdir / "tests").is_dir():
        argv = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-q"]
    else:
        return dict(ran=False, ok=True, seconds=0.0, output="no tests directory found")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    start = time.perf_counter()
    try:
        p = subprocess.run(argv, cwd=workdir, capture_output=True, text=True,
                           timeout=timeout, env=env)
        ok, out = p.returncode == 0, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        ok, out = False, f"tests timed out after {timeout}s"
    return dict(ran=True, ok=ok, seconds=time.perf_counter() - start, output=out[-1500:])
