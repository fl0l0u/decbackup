#!/usr/bin/env python3
"""Empirical error-code matrix for decbackup on the SNS 5.1.4 VM.

Each probe is a *same-length* header edit or a surgical byte patch so the
PKCS#7 trailer length X at 0x400 stays intact (a length-changing sed edit
shifts the whole file, breaks X, and confounds the result -- an early
round of probes was invalidated this way; csh also rejects ``2>/dev/null``
on dd, silently turning "tamper" commands into no-ops).

The `real` column is a **recorded device observation table**: the codes
were observed on the VM with the real decbackup (RECON.md §6/§9/§10).
The vectors in tests/vectors/ are byte-identical to the device-side probe
files, so running this script locally against the clone reproduces the
parity check without a live device -- `clone` is what the clone returns
right now; any row where it drifts from `real` is a regression.

    python analysis/probes.py

Codes: see decbackup/backup.py and RECON.md.
"""

import pathlib
import tempfile

VECTORS = "vectors"

PROBES = [
    # name            edit                              real  clone
    ("test.bkup",     "none",                             0,   0),
    ("nopass.bkup",   "encbackup without -p",             0,   0),
    ("big.bkup",      "payload 5.7KB",                    0,   0),
    ("mid.bkup",      "payload 23KB (multi-chunk)",       0,   0),
    ("trunc.bkup",    "truncated to 0x3FF",               8,   8),
    ("xzero.bkup",    "X (be32@0x400) zeroed",            6,   6),
    ("ct.bkup",       "ciphertext byte 4800 zeroed",      7,   7),
    ("cert.bkup",     "8 cert bytes at 2000 zeroed",      7,   7),
    ("mv3.bkup",      "majversion=2 -> majversion=3",    12,  12),
    ("v9.bkup",       'version="9    " (padded)',         7,   7),
    ("yt.bkup",       "+16 zero bytes appended",         13,  13),
    ("ys.bkup",       "last 16 bytes removed",           13,  13),
    ("mvx.bkup",      "majversion=x (same length)",      13,  13),
    ("v1probe.bkup",  "v1 path, correct key window",      7,   7),
    ("v1badkey.bkup", "v1 path, shifted key window",     13,  13),
    ("extdup.bkup",   "duplicate-extension cert",         7,   7),
    ("lazyparse.bkup","lazy-parsed cert field",           7,   7),
]

ADDITIONAL_REAL_RESULTS = """
Device-only probes (no local vector):
  wrong password                       -> 13
  algo=2                               -> 32
  majversion=1 (v1 path, v2 content)   -> 13
  version=9 with -4 shift (X broken)   -> 12   (version gate precedes X)
  version=1 with -4 shift (X broken)   -> 6
  version=90000 / 10000 (same length)  -> 7    (5-digit ints fall back
                                                to the default, see RECON)
  version=5.1.4 / dotted / alpha       -> pass
  -P without tty                       -> 13   (empty password used)
"""


def main():
    v = pathlib.Path(__file__).parent.parent / "tests" / VECTORS
    import sys
    sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
    from decbackup import decrypt_backup, BackupError

    passwords = {"test.bkup": "testpass", "big.bkup": "BigPass789",
                 "mid.bkup": "MidPass321", "nopass.bkup": ""}
    ok = True
    with tempfile.TemporaryDirectory(prefix="decbackup-probe-") as tmpdir:
        out = str(pathlib.Path(tmpdir) / "probe.out")
        for name, edit, real, clone in PROBES:
            path = v / name
            if not path.exists():
                print(f"{name:14s} MISSING")
                ok = False
                continue
            try:
                decrypt_backup(path, out, passwords.get(name, "testpass"))
                got = 0
            except BackupError as exc:
                got = exc.code
            status = "OK " if got == clone == real else "FAIL"
            if status == "FAIL":
                ok = False
            print(f"{status} {name:14s} real={real:2d} clone={got:2d}  ({edit})")
    print(ADDITIONAL_REAL_RESULTS)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
