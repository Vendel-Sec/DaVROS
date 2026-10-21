import contextlib
import subprocess
import sys
from pathlib import Path


def run(*args: str, quiet: bool = False, cwd: Path | None = None) -> str:
    proc = subprocess.run(
        args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, text=True,
        cwd=cwd,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout)
        raise SystemExit(f"command failed ({proc.returncode}): {' '.join(args)}")
    if not quiet and proc.stdout.strip():
        for line in proc.stdout.strip().splitlines():
            print(f"    | {line}")
    return proc.stdout


def chmod(path: Path, mode: int) -> None:
    # A mode that cannot be set is not worth failing provisioning over: the leaf
    # checks read the mode that actually landed, whatever it is.
    with contextlib.suppress(OSError):
        path.chmod(mode)
