"""Command line interface, mirroring ``/usr/Firewall/sbin/decbackup``.

getopt string ``Pi:p:o:d``.  Success is silent (exit 0); failure prints
``decrypt and/or verify backup failed (%d)`` and exits 1.  ``-d`` dumps
the backup header after a successful decryption.  A closed reader on
that dump (``-d | head``) exits 128+SIGPIPE, like the original's death
by SIGPIPE; any other unexpected crash prints the same generic failure
(1) — the tool must never show a Python traceback.
"""

from __future__ import annotations

import contextlib
import getopt
import os
import signal
import sys

try:  # POSIX only; without it the tty prompt degrades to a plain read
    import termios
except ImportError:  # pragma: no cover - non-POSIX platforms
    termios = None  # type: ignore[assignment]

from .backup import BackupError, decrypt_backup

USAGE = (
    "Usage : () -i <backup> -o <output archive>\n"
    "                    [-p <password>] [-d : dump backup header]\n"
    "                    [-P : prompt for password]\n"
    "                    [--no-verify : skip signature verification"
    " (clone extension)]\n"
)

PROMPT = "Enter backup password (<Enter> for none): "

# the original getopt string is exactly "Pi:p:o:d"; --no-verify is a
# long-option extension, which cannot collide with that grammar
SHORT_OPTS = "Pi:p:o:d"
LONG_OPTS = ["no-verify"]


def _read_password(prompt: bool) -> str:
    """``t_getpass``: prints the prompt to stderr and reads one line from
    /dev/tty with terminal echo switched off via termios.  Without a
    controllable tty the password is empty — device parity: ``-P`` over a
    pipe yields 13, i.e. an empty password was used (analysis/probes.py).
    """
    if not prompt and not sys.stdin.isatty():
        return ""
    try:
        # read-only: "r+" makes Python ask for seekability and die with
        # io.UnsupportedOperation (an OSError subclass) on Linux ptys,
        # which the fallback below would silently swallow — no prompt,
        # empty password
        tty = open("/dev/tty")
    except OSError:
        return ""  # no controlling terminal (pipe, cron): parity fallback
    old = None
    try:
        fd = tty.fileno()
        if termios is not None:
            try:
                old = termios.tcgetattr(fd)
                masked = list(old)
                masked[3] &= ~termios.ECHO  # lflag: typed password stays hidden
                # TCSANOW, not TCSAFLUSH: never discard already-typed
                # input (e.g. piped into a pty wrapper ahead of the prompt)
                termios.tcsetattr(fd, termios.TCSANOW, masked)
            except termios.error:
                old = None  # not a terminal line after all: plain read
        try:
            print(PROMPT, file=sys.stderr, end="")
            sys.stderr.flush()
            line = tty.readline()
        finally:
            if old is not None:
                with contextlib.suppress(termios.error):
                    termios.tcsetattr(fd, termios.TCSANOW, old)
    finally:
        tty.close()
    if line.endswith("\n") or line.endswith("\r"):
        line = line[:-1]  # chomp exactly one newline character
    return line


def _parse_opts(argv: list[str]):
    """Yield ``(opt, arg)`` one option at a time, mirroring the original's
    ``while ((c = getopt(argc, argv, "Pi:p:o:d")) != -1)`` loop.

    ``getopt.getopt()`` parses all of argv before returning anything, so
    a later option error would mask an earlier application error: the
    device reports the duplicate -p of ``-p a -p b -z``, not the -z.
    Each step consumes a single argv element — plus the next one when a
    short option takes its value from a separate element — so every
    error is raised at the position the C loop would hit it.
    """
    rest = list(argv)
    while rest and rest[0].startswith("-") and rest[0] != "-":
        if rest[0] == "--":
            break  # end-of-options marker; the remainder is ignored
        try:
            opts, _ = getopt.getopt(rest[:1], SHORT_OPTS, LONG_OPTS)
            rest = rest[1:]
        except getopt.GetoptError:
            # may just be an option whose value is the *next* element;
            # if it still fails, the error is real and surfaces here,
            # in argv order
            if len(rest) < 2:
                raise
            opts, _ = getopt.getopt(rest[:2], SHORT_OPTS, LONG_OPTS)
            rest = rest[2:]
        yield from opts


def _getopt_error_text(exc: getopt.GetoptError) -> str:
    """C-getopt-shaped message for an option error.

    CPython sets ``exc.opt`` on *every* error path, so its truth cannot
    distinguish the cases: a known short option can only raise because
    its value is missing (``option requires an argument -- p``), a single
    unknown character is the device-verified ``illegal option -- z``,
    and anything else is one of the clone's long-option edges (no
    device wording exists for those — keep CPython's).
    """
    if len(exc.opt) == 1:
        if exc.opt in SHORT_OPTS:
            return f"decbackup: option requires an argument -- {exc.opt}"
        return f"decbackup: illegal option -- {exc.opt}"
    return f"decbackup: {exc.msg}"


def _run(argv: list[str]) -> int:
    input_path = output_path = None
    password: str | None = None
    prompt = False
    dump = False
    verify = True
    p_count = 0

    try:
        for opt, arg in _parse_opts(argv):
            if opt == "-P":
                prompt = True
            elif opt == "-p":
                p_count += 1
                if p_count > 1:
                    # device-verified: message only, no usage dump
                    print("-p can only be specified once", file=sys.stderr)
                    return 1
                password = arg
            elif opt == "-i":
                input_path = arg
            elif opt == "-o":
                output_path = arg
            elif opt == "-d":
                dump = True
            elif opt == "--no-verify":
                verify = False
    except getopt.GetoptError as exc:
        # match the C library's message shape
        print(_getopt_error_text(exc), file=sys.stderr)
        print(USAGE, file=sys.stderr, end="")
        return 1

    if input_path is None or output_path is None:
        print(USAGE, file=sys.stderr, end="")
        return 1

    if password is None:
        password = _read_password(prompt)

    if not verify:
        print(
            "decbackup: WARNING: signature verification skipped -- "
            "the output is decrypted but UNAUTHENTICATED",
            file=sys.stderr,
        )

    try:
        header = decrypt_backup(input_path, output_path, password, verify=verify)
    except BackupError as exc:
        print(f"decrypt and/or verify backup failed ({exc.code})", file=sys.stderr)
        return 1

    if dump:
        # dump the exact header text the library parsed and signature-
        # verified; re-reading the file here could show bytes that were
        # never checked (TOCTOU on a swapped/FIFO input)
        print(f"Header :\n{header['header_text']}\n", end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point.  No traceback may ever escape: the original binary has
    no failure mode that prints one, so anything unforeseen ends as the
    tool's generic failure instead."""
    argv = sys.argv[1:] if argv is None else argv
    try:
        rc = _run(argv)
        # flush here so a closed reader on the -d dump raises while the
        # BrokenPipeError guard below can still catch it: piped stdout is
        # block-buffered, so otherwise the error would only surface in
        # the interpreter's shutdown flush (noise + exit 120)
        sys.stdout.flush()
        return rc
    except BrokenPipeError:
        # ``decbackup -d ... | head``: the reader vanished mid-write.
        # The original dies of SIGPIPE (the shell sees 141); reproduce
        # that exit status quietly, pointing both streams at /dev/null
        # so nothing can be printed afterwards (standard Python CLI
        # convention).
        with contextlib.suppress(OSError):
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
            os.dup2(devnull, sys.stderr.fileno())
            os.close(devnull)
        return 128 + signal.SIGPIPE
    except Exception:
        # last line of defense: the library maps everything into
        # BackupError, but the no-traceback contract must not depend on
        # that alone
        with contextlib.suppress(OSError):
            print("decrypt and/or verify backup failed (1)", file=sys.stderr)
        return 1
