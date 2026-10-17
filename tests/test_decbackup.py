#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Test suite for the decbackup clone, run against the captured vectors in
tests/vectors/ (produced by encbackup on an SNS 5.1.4 device and validated
against the real decbinary — see RECON.md for the error-code derivation).

Exit code = number of failures.
"""

import hashlib
import pathlib
import subprocess
import sys
import warnings

HERE = pathlib.Path(__file__).parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from cryptography import x509  # noqa: E402

from decbackup import decrypt_backup  # noqa: E402
from decbackup.backup import BackupError, _crypto_datas, parse_header  # noqa: E402
from decbackup.crypto import (  # noqa: E402
    V1_IV_SALT,
    V1_KEY_SALT,
    _sha1_salted,
    derive_iv_v1,
    derive_key_v1,
    derive_key_v2,
)
from decbackup.pkcs7 import parse_signed_data  # noqa: E402
from decbackup.trust import load_trust_store  # noqa: E402

V = ROOT / "tests" / "vectors"
TMP = pathlib.Path("/tmp/opencode")
TMP.mkdir(parents=True, exist_ok=True)

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    mark = "ok  " if ok else "FAIL"
    print(f"{mark} {name}" + (f"  [{detail}]" if detail and not ok else ""))


def run(name, bkup, expected, password, code=0):
    out = TMP / f"{name}.out"
    try:
        decrypt_backup(V / bkup, out, password)
        got = 0
    except BackupError as exc:
        got = exc.code
    check(f"{name}: error code {code}", got == code, f"got {got}")
    if code == 0:
        check(f"{name}: payload", out.read_bytes() == (V / expected).read_bytes())
    else:
        check(f"{name}: no output left", not out.exists())


# --- happy paths -----------------------------------------------------------
run("test", "test.bkup", "test.tar", "testpass")
run("nopass", "nopass.bkup", "t2.tar", "")
run("big", "big.bkup", "big.tar", "BigPass789")
run("mid", "mid.bkup", "mid.tar", "MidPass321")

# --- error-code parity with the real tool ----------------------------------
run("wrongpass", "test.bkup", None, "nope", code=13)
run("trunc", "trunc.bkup", None, "testpass", code=8)
run("xzero", "xzero.bkup", None, "testpass", code=6)
run("ct-tamper", "ct.bkup", None, "testpass", code=7)
run("cert-tamper", "cert.bkup", None, "testpass", code=7)
run("majversion3", "mv3.bkup", None, "testpass", code=12)
run("version-padded-9", "v9.bkup", None, "testpass", code=7)

# --- header ----------------------------------------------------------------
text, fields = parse_header((V / "test.bkup").read_bytes()[:0x400])
check("header: majversion", fields.get("majversion") == "2")
check("header: algo", fields.get("algo") == "1")
check("header: pbkdf", fields.get("pbkdf_iterations") == "10000")
check("header: quoted date", fields.get("date", "").startswith("20"))
check("header: no NUL", "\x00" not in text)

# --- crypto ----------------------------------------------------------------
key = derive_key_v2(b"testpass", bytes.fromhex(fields["salt"]),
                    int(fields["pbkdf_iterations"]))
check("v2 KDF: 16-byte key", len(key) == 16)
k1, iv1, algo = _crypto_datas(fields, 2, "testpass")
check("v2 dispatch matches direct PBKDF2", k1 == key and algo == 1)
check("v2 iv", iv1 == bytes.fromhex(fields["iv"]))

# v1: SHA1(salt || password)[:16] — static RE, not empirically cross-checked
check("v1 key", derive_key_v1(b"x") ==
      hashlib.sha1(V1_KEY_SALT + b"x").digest()[:16])
check("v1 iv", derive_iv_v1(b"x") ==
      hashlib.sha1(V1_IV_SALT + b"x").digest()[:16])
big = _sha1_salted(V1_KEY_SALT, b"x", 32)
check("v1 fill progression", big[20:] == bytes(
    (32 - 1 + (32 - i) * 0xEB) & 0xFF for i in range(20, 32)))

# --- PKCS#7 ----------------------------------------------------------------
data = (V / "test.bkup").read_bytes()
X = int.from_bytes(data[0x400:0x404], "big")
certs, signers = parse_signed_data(data[0x404:0x404 + X])
check("p7: two certificates", len(certs) == 2)
si = signers[0]
check("p7: sig alg rsa", si.sig_alg in ("1.2.840.113549.1.1.1",
                                        "1.2.840.113549.1.1.11"))
check("p7: contentType data", si.content_type == "1.2.840.113549.1.7.1")
check("p7: attrs DER starts with SET", si.attrs_der[0] == 0x31)
leaf = x509.load_der_x509_certificate(certs[0])
check("p7: leaf has backup policy", any(
    p.policy_identifier.dotted_string == "1.3.6.1.4.1.11256.2.3"
    for p in leaf.extensions.get_extension_for_class(
        x509.CertificatePolicies).value))
plaintext = (TMP / "test.out").read_bytes()
check("p7: messageDigest == sha256(header+payload)",
      si.message_digest == hashlib.sha256(data[:0x400] + plaintext).digest())

# --- trust store -----------------------------------------------------------
store = load_trust_store()
check("trust: four embedded CAs", len(store) == 4)
with warnings.catch_warnings():
    warnings.simplefilter("ignore")  # NETASQ CA: non-positive serial
    subs = [x509.load_der_x509_certificate(d).subject.rfc4514_string()
            for d in store]
check("trust: stormshield roots present",
      sum("Stormshield" in s for s in subs) == 3
      and sum("NETASQ" in s for s in subs) == 1)

# --- CLI -------------------------------------------------------------------
PY = sys.executable


def cli(*args, expect_rc=0):
    p = subprocess.run([PY, "-m", "decbackup", *args], capture_output=True,
                       text=True, cwd=ROOT)
    return p


p = cli("-i", str(V / "test.bkup"), "-o", str(TMP / "cli.out"),
        "-p", "testpass")
check("cli: silent success", p.returncode == 0 and not p.stdout
      and not p.stderr)
p = cli()
check("cli: usage without args", p.returncode == 1
      and "Usage : () -i <backup> -o <output archive>" in p.stderr)
p = cli("-i", str(V / "test.bkup"), "-o", str(TMP / "cli2.out"),
        "-p", "a", "-p", "b")
check("cli: -p once", p.returncode == 1
      and "-p can only be specified once" in p.stderr)
p = cli("-i", str(V / "test.bkup"), "-o", str(TMP / "cli3.out"),
        "-p", "testpass", "-d")
check("cli: -d dumps header", p.returncode == 0
      and p.stdout.startswith("Header :\n[BACKUP]\n"))
p = cli("-i", str(V / "test.bkup"), "-o", str(TMP / "cli4.out"),
        "-p", "bad")
check("cli: failure message", p.returncode == 1
      and p.stderr.strip() == "decrypt and/or verify backup failed (13)")

fails = sum(1 for _, ok in RESULTS if not ok)
print(f"\n{len(RESULTS) - fails}/{len(RESULTS)} checks passed")
sys.exit(fails)
