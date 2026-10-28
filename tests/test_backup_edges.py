#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed header-parsing edges for decbackup.backup.

Companion to tests/test_decbackup.py (which pins device error-code parity
on the untouched vectors).  Everything here either exercises the header
parsers directly or mutates tests/vectors/test.bkup bytes **in a temp
dir** — the vectors themselves are never touched.  Contract under test:
every input ends in a BackupError with a documented code or success,
never a raw traceback, never a surviving output file on failure.

Exit code = number of failures.
"""

import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

from decbackup import backup, pkcs7  # noqa: E402
from decbackup import crypto as crypto_mod  # noqa: E402
from decbackup.backup import (  # noqa: E402
    MAX_ITERATIONS,
    BackupError,
    _crypto_datas,
    decrypt_backup,
    parse_header,
)
from decbackup.crypto import derive_key_v2  # noqa: E402

V = ROOT / "tests" / "vectors"
TMP = pathlib.Path(tempfile.mkdtemp(prefix="decbackup-edges-"))

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    mark = "ok  " if ok else "FAIL"
    print(f"{mark} {name}" + (f"  [{detail}]" if detail and not ok else ""))


BASE = (V / "test.bkup").read_bytes()
TAR = (V / "test.tar").read_bytes()
BASE_TEXT = BASE[:0x400].split(b"\x00", 1)[0].decode("latin-1")
FIELDS = parse_header(BASE[:0x400])[1]


def rebuild_header(edit):
    """test.bkup with header text = edit(old_text), re-padded with NULs.

    Trailer and payload keep their original bytes.  A header edit breaks
    the messageDigest, so these files exercise pre-verification error
    codes or the verify=False flow.
    """
    new = edit(BASE_TEXT)
    assert new != BASE_TEXT, "header edit was a no-op"
    raw = new.encode("latin-1")
    assert len(raw) <= 0x400, "header overflow"
    return raw + b"\x00" * (0x400 - len(raw)) + BASE[0x400:]


def reencrypt(edit, iterations):
    """test.tar re-encrypted under PBKDF2(testpass, header salt, iterations).

    Keeps the original (stale for this content) signature trailer, so
    containers built here are decrypted with verify=False.
    """
    header = rebuild_header(edit)[:0x400]
    fields = parse_header(header)[1]
    key = derive_key_v2(b"testpass", bytes.fromhex(fields["salt"]), iterations)
    enc = Cipher(algorithms.AES(key), modes.CBC(bytes.fromhex(fields["iv"]))).encryptor()
    pad = 16 - len(TAR) % 16
    ct = enc.update(TAR + bytes([pad]) * pad) + enc.finalize()
    sig_len = int.from_bytes(BASE[0x400:0x404], "big")
    return header + BASE[0x400 : 0x404 + sig_len] + len(ct).to_bytes(4, "big") + ct


def run(name, bkup_bytes, expected, password="testpass", payload=None, verify=True):
    src = TMP / f"{name}.bkup"
    src.write_bytes(bkup_bytes)
    out = TMP / f"{name}.out"
    try:
        decrypt_backup(src, out, password, verify=verify)
        got = 0
    except BackupError as exc:
        got = exc.code
    except BaseException as exc:
        check(name, False, f"raw {type(exc).__name__} escaped: {exc}")
        if not isinstance(exc, Exception):
            raise  # never swallow KeyboardInterrupt/SystemExit into a check row
        return
    check(f"{name}: error code {expected}", got == expected, f"got {got}")
    if expected == 0:
        check(f"{name}: payload", out.exists() and out.read_bytes() == payload)
    else:
        check(f"{name}: no output left", not out.exists())


def iters_code(value):
    """_crypto_datas (v2) with pbkdf_iterations replaced by *value*."""
    try:
        _crypto_datas(dict(FIELDS, pbkdf_iterations=value), 2, "testpass")
        return 0
    except BackupError as exc:
        return exc.code


# --- pbkdf_iterations --------------------------------------------------------
# >= 2**31 would OverflowError inside hashlib on the old parser; the clone
# bounds it at parse time (E_PARSE; device side OpenSSL rejects it too,
# "iteration value is too great" — device's exact code unprobed).
run(
    "iters-overflow",
    rebuild_header(lambda t: t.replace("pbkdf_iterations=10000", "pbkdf_iterations=99999999999")),
    6,
)
check("iters: cap is the INT_MAX boundary", MAX_ITERATIONS == 2**31)
check("iters: 2**31 parse-fails, no OverflowError", iters_code("2147483648") == 6)
# str.isdigit() traps: Unicode digits must NOT parse (documented choice:
# strict ASCII digits -> E_PARSE, not the device's parse-fail->default-1,
# per the fail-closed parsing contract).  Arabic-Indic digits cannot even
# arrive through a latin-1 header; the reachable byte-level trap is 0xB2.
check("iters: Arabic-Indic rejected", iters_code("\u0661\u0660\u0660\u0660") == 6)
check("iters: superscript-two (0xB2) rejected", iters_code("\u00b2") == 6)
run(
    "iters-superscript",
    rebuild_header(lambda t: t.replace("pbkdf_iterations=10000", "pbkdf_iterations=\u00b2")),
    6,
)
# present-but-empty behaves as absent: default 1, not E_PARSE
check("iters: empty parses (default 1)", iters_code("") == 0)
k_empty = _crypto_datas(dict(FIELDS, pbkdf_iterations=""), 2, "testpass")[0]
k_absent = _crypto_datas(
    {k: v for k, v in FIELDS.items() if k != "pbkdf_iterations"}, 2, "testpass"
)[0]
check("iters: empty derives like absent", k_empty == k_absent)
run(
    "iters-empty",
    reencrypt(lambda t: t.replace("pbkdf_iterations=10000", "pbkdf_iterations="), 1),
    0,
    payload=TAR,
    verify=False,
)
run(
    "iters-absent",
    reencrypt(lambda t: t.replace("pbkdf_iterations=10000\n", ""), 1),
    0,
    payload=TAR,
    verify=False,
)

# --- majversion ---------------------------------------------------------------
# same 1-4-digit cap as the version gate; anything non-conforming
# (5+ digits, whitespace) parse-fails to the v1 default — device model per
# RECON §6 mvx.bkup, wrong-key padding failure (13) rather than 12.
run(
    "majversion-space-2",
    rebuild_header(lambda t: t.replace("majversion=2\n", "majversion= 2\n")),
    13,
)
run(
    "majversion-90000",
    rebuild_header(lambda t: t.replace("majversion=2\n", "majversion=90000\n")),
    13,
)

# --- hex fields -----------------------------------------------------------------
# bytes.fromhex tolerates embedded whitespace; the clone must not
run(
    "salt-whitespace",
    rebuild_header(lambda t: t.replace("salt=2c4b", "salt=2c4b ")),
    6,
)
run(
    "iv-8-byte",
    rebuild_header(
        lambda t: t.replace("iv=79275efe2f4648567b6c3679c6e0528c", "iv=79275efe2f464856")
    ),
    6,
)
run(
    "iv-32-byte",
    rebuild_header(
        lambda t: t.replace(
            "iv=79275efe2f4648567b6c3679c6e0528c", "iv=" + "79275efe2f4648567b6c3679c6e0528c" * 2
        )
    ),
    6,
)

# --- duplicate keys ---------------------------------------------------------------
# FIRST occurrence wins (inferred libnbase section-scan behaviour)
dup = parse_header(b"[BACKUP]\nsalt=41414141\nsalt=2c4b2021f41db140aad2f1082a5d0567\n\x00\x00")[1]
check("header: duplicate key first wins", dup.get("salt") == "41414141")
run(
    "dup-salt-first-wins",  # original (correct) salt first, garbage second
    rebuild_header(lambda t: t + "salt=00112233445566778899aabbccddeeff\n"),
    0,
    payload=TAR,
    verify=False,
)
run(
    "dup-salt-last-loses",  # corrupted salt first, correct one appended
    rebuild_header(
        lambda t: t.replace("salt=2c4b", "salt=2d4b")
        + "salt=2c4b2021f41db140aad2f1082a5d0567\n"
    ),
    13,
    verify=False,
)

# --- line splitting ---------------------------------------------------------------
# the C parser ends lines at '\n' only; latin-1 \x0b/\x85 must not split
odd = parse_header(b"[BACKUP]\ndescription=a\x0bb\x85c\nmajversion=2\n\x00\x00")[1]
check("header: \\x0b/\\x85 are not line breaks", odd.get("description") == "a\x0bb\x85c")

# --- every signerInfo is checked ----------------------------------------------------
# device PKCS7_verify verifies ALL signerInfos; a synthetic second signer
# that fails must turn an otherwise-clean vector into 7
class _BadSigner:
    def verify(self, certs, content):
        raise pkcs7.SignatureError("synthetic second signer")


class _P7Stub:
    SignatureError = pkcs7.SignatureError

    @staticmethod
    def parse_signed_data(sig_der):
        certs, signers = pkcs7.parse_signed_data(sig_der)
        return certs, list(signers) + [_BadSigner()]


backup.pkcs7 = _P7Stub
try:
    run("second-signer-fails", BASE, 7)
finally:
    backup.pkcs7 = pkcs7

# --- no output survives ANY failure --------------------------------------------------
# unexpected internals must wrap into E_FILE (never a traceback, never a
# surviving output file), including BaseException like KeyboardInterrupt
class _RaisingCrypto:
    def __init__(self, exc):
        self._exc = exc

    def __getattr__(self, name):
        if name == "aes_cbc_decrypt":
            raise self._exc
        return getattr(crypto_mod, name)


for label, exc in (
    ("internal-error-wrapped", RuntimeError("synthetic internal failure")),
    ("keyboard-interrupt-wrapped", KeyboardInterrupt()),
):
    backup.crypto = _RaisingCrypto(exc)
    try:
        run(label, BASE, 1)
    finally:
        backup.crypto = crypto_mod

# --- header_text in the returned dict --------------------------------------------------
# (raw bytes the signature covered, for the -d dump — no input re-read needed)
res = decrypt_backup(V / "test.bkup", TMP / "header_text.out", "testpass")
check("api: header_text == signed header block text", res.get("header_text") == BASE_TEXT)
check("api: header_text NUL-free", "\x00" not in res.get("header_text", ""))

# --- dead code dropped -----------------------------------------------------------------
check("E_OK constant removed", not hasattr(backup, "E_OK"))
check("_decrypt_backup verify has no default", backup._decrypt_backup.__defaults__ is None)

fails = sum(1 for _, ok in RESULTS if not ok)
print(f"\n{len(RESULTS) - fails}/{len(RESULTS)} checks passed")
sys.exit(fails)
