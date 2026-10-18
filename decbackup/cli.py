"""Command line interface, mirroring ``/usr/Firewall/sbin/decbackup``.

getopt string ``Pi:p:o:d``.  Success is silent (exit 0); failure prints
``decrypt and/or verify backup failed (%d)`` and exits 1.  ``-d`` dumps
the backup header after a successful decryption.
"""

from __future__ import annotations

import getopt
import sys

from .backup import HEADER_LEN, BackupError, decrypt_backup

USAGE = (
    "Usage : () -i <backup> -o <output archive>\n"
    "                    [-p <password>] [-d : dump backup header]\n"
    "                    [-P : prompt for password]\n"
    "                    [--no-verify : skip signature verification"
    " (clone extension)]\n"
)

PROMPT = "Enter backup password (<Enter> for none): "


def _read_password(prompt: bool) -> str:
    """``t_getpass``: reads from /dev/tty; without a tty the password is
    empty (empirically ``-P`` over a pipe yields error 13, i.e. an empty
    password was used)."""
    if not prompt and not sys.stdin.isatty():
        return ""
    try:
        with open("/dev/tty", "r+") as tty:
            tty.write(PROMPT)
            tty.flush()
            return tty.readline().rstrip("\r\n")
    except OSError:
        return ""


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    input_path = output_path = None
    password: str | None = None
    prompt = False
    dump = False
    verify = True
    p_count = 0

    # the original getopt string is exactly "Pi:p:o:d"; --no-verify is a
    # long-option extension, which cannot collide with that grammar
    try:
        opts, _ = getopt.getopt(argv, "Pi:p:o:d", ["no-verify"])
    except getopt.GetoptError as exc:
        # match the C library's message shape
        if exc.opt:
            print(f"decbackup: illegal option -- {exc.opt}", file=sys.stderr)
        else:
            print(f"decbackup: {exc.msg}", file=sys.stderr)
        print(USAGE, file=sys.stderr, end="")
        return 1

    for opt, arg in opts:
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
        decrypt_backup(input_path, output_path, password, verify=verify)
    except BackupError as exc:
        print(f"decrypt and/or verify backup failed ({exc.code})", file=sys.stderr)
        return 1

    if dump:
        try:
            with open(input_path, "rb") as f:
                block = f.read(HEADER_LEN)
        except OSError:
            block = b""
        text = block.split(b"\x00", 1)[0].decode("latin-1")
        print(f"Header :\n{text}\n", end="")
    return 0
