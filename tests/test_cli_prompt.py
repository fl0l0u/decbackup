#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CLI prompt/parsing tests, companion to tests/test_decbackup.py (same
harness style: exit code = number of failures).

Covers the device-parity behaviours that piped stdin/stdout cannot
reach: the -P prompt driven over a real pty (shown, password read from
/dev/tty, not echoed), the tty-less fallback (empty password -> 13, see
analysis/probes.py), the C-getopt-shaped parse errors surfacing in argv
order, and the never-a-traceback guarantees (generic failure (1) and the
SIGPIPE death of ``-d | head``).  POSIX only.
"""

import contextlib
import io
import os
import pathlib
import pty
import select
import signal
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from decbackup import cli as cli_mod  # noqa: E402

V = ROOT / "tests" / "vectors"
TMP = pathlib.Path(tempfile.mkdtemp(prefix="decbackup-cli-prompt-"))
PY = sys.executable
PROMPT_MARKER = b"Enter backup password"

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    mark = "ok  " if ok else "FAIL"
    print(f"{mark} {name}" + (f"  [{detail}]" if detail and not ok else ""))


def cli(*args, expect_rc=0):
    p = subprocess.run([PY, "-m", "decbackup", *args], capture_output=True, text=True, cwd=ROOT)
    return p


def pty_run(args, typed=b"", out=None, timeout=90):
    """Run ``python -m decbackup`` on its own pty (the slave becomes the
    controlling tty, so /dev/tty resolves for it); ``$OUT`` in args is
    replaced by `out`.  `typed` is fed to the master once the prompt
    appears in the output.  Returns (exit code, all master output); a
    wall-clock guard kills a hanging child instead of hanging the suite.
    """
    argv = [PY, "-m", "decbackup"] + [a.replace("$OUT", str(out)) for a in args]
    pid, master = pty.fork()
    if pid == 0:
        try:
            os.chdir(ROOT)
            os.execv(PY, argv)
        except OSError:
            os._exit(127)
    buf = b""
    typed_sent = not typed
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.25)
        if not ready:
            if not typed_sent and PROMPT_MARKER in buf:
                os.write(master, typed)
                typed_sent = True
            continue
        try:
            chunk = os.read(master, 4096)
        except OSError:  # Linux signals the slave's death with EIO
            break
        if not chunk:
            break
        buf += chunk
    else:
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGKILL)
        buf += b"<TIMEOUT>"
    with contextlib.suppress(OSError):
        os.close(master)
    _, status = os.waitpid(pid, 0)
    if typed and not typed_sent:
        buf += b"<PROMPT-NOT-SEEN>"
    return os.waitstatus_to_exitcode(status), buf


# --- -P over a real pty ------------------------------------------------------
out = TMP / "pty-test.tar"
rc, buf = pty_run(["-i", "tests/vectors/test.bkup", "-o", "$OUT", "-P"], b"testpass\n", out)
check("pty -P: prompt shown", PROMPT_MARKER in buf, repr(buf[-80:]))
check("pty -P: typed password not echoed", b"testpass" not in buf, repr(buf[-80:]))
check("pty -P: exit 0", rc == 0, f"rc={rc} {buf!r}")
payload_ok = out.exists() and out.read_bytes() == (V / "test.tar").read_bytes()
check("pty -P: payload decrypted", payload_ok)

# <Enter> on an empty-password backup (exercises the chomp path)
out = TMP / "pty-nopass.tar"
rc, buf = pty_run(["-i", "tests/vectors/nopass.bkup", "-o", "$OUT", "-P"], b"\n", out)
check(
    "pty -P: <Enter> = empty password",
    rc == 0 and out.exists() and out.read_bytes() == (V / "t2.tar").read_bytes(),
    f"rc={rc} {buf!r}",
)

# --- -P without a tty (device parity: empty password -> 13) -------------------
p = subprocess.run(
    [PY, "-m", "decbackup", "-i", str(V / "test.bkup"), "-o", str(TMP / "ttyless.out"), "-P"],
    stdin=subprocess.DEVNULL,
    capture_output=True,
    text=True,
    cwd=ROOT,
    preexec_fn=os.setsid,  # new session: no controlling tty at all
)
check(
    "cli -P: no tty -> empty password -> failed (13)",
    p.returncode == 1
    and p.stderr.strip() == "decrypt and/or verify backup failed (13)"
    and "Enter backup password" not in p.stderr,
    f"rc={p.returncode} stderr={p.stderr!r}",
)

# --- missing option argument: C-getopt shape + usage --------------------------
p = cli("-i", str(V / "test.bkup"), "-o", str(TMP / "mv.out"), "-p")
check(
    "cli: -p without value -> 'option requires an argument -- p' + usage",
    p.returncode == 1
    and "decbackup: option requires an argument -- p" in p.stderr
    and "Usage" in p.stderr,
    f"rc={p.returncode} stderr={p.stderr!r}",
)
p = cli("-o")
check(
    "cli: -o without value -> 'option requires an argument -- o' + usage",
    p.returncode == 1 and "option requires an argument -- o" in p.stderr and "Usage" in p.stderr,
    f"rc={p.returncode} stderr={p.stderr!r}",
)

# --- argv-order error precedence (sequential C getopt loop) -------------------
p = cli("-i", str(V / "test.bkup"), "-o", str(TMP / "dup.out"), "-p", "a", "-p", "b", "-z")
check(
    "cli: duplicate -p reported before later -z (message only, no usage)",
    p.returncode == 1 and p.stderr.strip() == "-p can only be specified once",
    f"rc={p.returncode} stderr={p.stderr!r}",
)
p = cli("-z", "-p", "a", "-p", "b")
check(
    "cli: -z first is reported first",
    p.returncode == 1
    and "illegal option -- z" in p.stderr
    and "Usage" in p.stderr
    and "-p can only" not in p.stderr,
    f"rc={p.returncode} stderr={p.stderr!r}",
)

# --- never a traceback ---------------------------------------------------------
p = cli("-i", str(V / "test.bkup"), "-o", "/proc/nope/out.tar", "-p", "testpass")
check(
    "cli: unwritable -o -> failed (1), no traceback",
    p.returncode == 1
    and p.stderr.strip() == "decrypt and/or verify backup failed (1)"
    and "Traceback" not in p.stderr,
    f"rc={p.returncode} stderr={p.stderr!r}",
)


def _boom(*args, **kwargs):
    raise RuntimeError("simulated library crash")


_real = cli_mod.decrypt_backup
cli_mod.decrypt_backup = _boom
err = io.StringIO()
try:
    with contextlib.redirect_stderr(err):
        rc = cli_mod.main(["-i", str(V / "test.bkup"), "-o", str(TMP / "boom.out"), "-p", "x"])
finally:
    cli_mod.decrypt_backup = _real
check(
    "cli: unexpected crash -> failed (1), no traceback",
    rc == 1 and err.getvalue() == "decrypt and/or verify backup failed (1)\n",
    f"rc={rc} stderr={err.getvalue()!r}",
)

# --- -d with a dead pipe: the original dies of SIGPIPE --------------------------
r, w = os.pipe()
p = subprocess.Popen(
    [
        PY,
        "-m",
        "decbackup",
        "-i",
        str(V / "mid.bkup"),
        "-o",
        str(TMP / "pipe.out"),
        "-p",
        "MidPass321",
        "-d",
    ],
    stdout=w,
    stderr=subprocess.PIPE,
    cwd=ROOT,
)
os.close(w)
os.close(r)  # no reader left before the dump is written
rc = p.wait(timeout=90)
errtext = p.stderr.read().decode()
p.stderr.close()
check(
    "cli: -d into closed pipe -> 141 (128+SIGPIPE), silent",
    rc == 128 + signal.SIGPIPE and not errtext.strip(),
    f"rc={rc} stderr={errtext!r}",
)

fails = sum(1 for _, ok in RESULTS if not ok)
print(f"\n{len(RESULTS) - fails}/{len(RESULTS)} checks passed")
sys.exit(fails)
