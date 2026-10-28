#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the decbackup clone, run against the captured vectors in
tests/vectors/ (stock encbackup output from an SNS 5.1.4 device plus
clone-crafted byte edits — see tests/vectors/README.md for lineage and
RECON.md for the error-code derivation).

Exit code = number of failures (capped at 254; exit statuses wrap mod 256).
A check that raises is recorded as a FAIL and the run continues.
"""

import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import warnings

HERE = pathlib.Path(__file__).parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from cryptography import x509  # noqa: E402
from cryptography.x509 import DuplicateExtension  # noqa: E402

from decbackup import decrypt_backup  # noqa: E402
from decbackup.backup import BackupError, _crypto_datas, parse_header  # noqa: E402
from decbackup.crypto import (  # noqa: E402
    V1_IV_SALT,
    V1_KEY_SALT,
    _sha1_salted,
    aes_cbc_decrypt,
    derive_iv_v1,
    derive_key_v1,
    derive_key_v2,
    pkcs7_unpad,
)
from decbackup.pkcs7 import parse_signed_data  # noqa: E402
from decbackup.trust import load_trust_store  # noqa: E402

V = ROOT / "tests" / "vectors"
TMP = pathlib.Path(tempfile.mkdtemp(prefix="decbackup-tests-"))
# scratch dir is gone on exit no matter how the run ends
import atexit  # noqa: E402

atexit.register(shutil.rmtree, TMP, ignore_errors=True)

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    mark = "ok  " if ok else "FAIL"
    print(f"{mark} {name}" + (f"  [{detail}]" if detail and not ok else ""))


def block(name, fn):
    """Run one group of checks; an unexpected exception is a FAIL line and
    the rest of the suite still runs (never abort the run on one crash)."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 — runner contract: never propagate
        check(f"{name}: unexpected {type(exc).__name__}", False, repr(exc))


def run(name, bkup, expected, password, code=0, path=None):
    out = TMP / f"{name}.out"
    src = pathlib.Path(path) if path is not None else V / bkup
    got = None
    try:
        decrypt_backup(src, out, password)
        got = 0
    except BackupError as exc:
        got = exc.code
    check(f"{name}: error code {code}", got == code, f"got {got}")
    if got != code:
        return  # content assertions only make sense once the code matches
    if code == 0:
        check(f"{name}: payload", out.read_bytes() == (V / expected).read_bytes())
    else:
        check(f"{name}: no output left", not out.exists())


def err_code(src, out, password="testpass"):
    try:
        decrypt_backup(src, out, password)
        return 0
    except BackupError as exc:
        return exc.code


# --- happy paths -----------------------------------------------------------
for _n, _b, _t, _p in [
    ("test", "test.bkup", "test.tar", "testpass"),
    ("nopass", "nopass.bkup", "t2.tar", ""),
    ("big", "big.bkup", "big.tar", "BigPass789"),
    ("mid", "mid.bkup", "mid.tar", "MidPass321"),
]:
    block(f"run:{_n}", lambda n=_n, b=_b, t=_t, p=_p: run(n, b, t, p))


# --- error-code parity with the real tool ----------------------------------
block(
    "error-parity",
    lambda: [
        run("wrongpass", "test.bkup", None, "nope", code=13),
        run("trunc", "trunc.bkup", None, "testpass", code=8),
        run("xzero", "xzero.bkup", None, "testpass", code=6),
        run("ct-tamper", "ct.bkup", None, "testpass", code=7),
        run("cert-tamper", "cert.bkup", None, "testpass", code=7),
        run("majversion3", "mv3.bkup", None, "testpass", code=12),
        run("version-padded-9", "v9.bkup", None, "testpass", code=7),
    ],
)

# boundary probes, device-validated on the 5.1.4 VM (RECON section 6):
# decryption is filesize-bounded (Y ignored) and non-numeric majversion
# defaults to the v1 path
block(
    "boundary",
    lambda: [
        run("tail-bytes", "yt.bkup", None, "testpass", code=13),
        run("short-of-Y", "ys.bkup", None, "testpass", code=13),
        run("majversion-nonnumeric", "mvx.bkup", None, "testpass", code=13),
    ],
)

# fuzz regressions: trailer bytes that load as certificates but raise on
# lazy field access must fail closed into 7, never a traceback.  extdup
# duplicates the keyUsage extension (2.5.29.15) in the leaf certificate
# (its mutations are derived from cert.bkup); lazyparse shreds the issuer
# Name so parsing it explodes.
def probe_fuzz():
    run("ext-duplication", "extdup.bkup", None, "testpass", code=7)
    run("lazy-field-parse", "lazyparse.bkup", None, "testpass", code=7)
    # extdup's leaf really carries keyUsage twice — the lazily-parsed field
    # whose DuplicateExtension (a bare Exception subclass) crashed the fuzz
    # campaign.  Pin the exact DuplicateExtension detail at the parse
    # boundary; the file-level 7 is run()'s job (which check inside
    # verification trips first is an implementation detail).
    d_ext = (V / "extdup.bkup").read_bytes()
    x_ext = int.from_bytes(d_ext[0x400:0x404], "big")
    ext_certs, _ = parse_signed_data(d_ext[0x404 : 0x404 + x_ext])
    try:
        # newer cryptography parses eagerly and may raise straight from load
        exts = x509.load_der_x509_certificate(ext_certs[0]).extensions
        check(
            "extdup: DuplicateExtension on keyUsage (2.5.29.15)",
            False,
            f"no DuplicateExtension ({len(exts)} exts parsed)",
        )
    except DuplicateExtension as exc:
        check(
            "extdup: DuplicateExtension on keyUsage (2.5.29.15)",
            str(exc).startswith("Duplicate") and "2.5.29.15" in str(exc),
            str(exc),
        )


block("fuzz-regressions", probe_fuzz)

# v1 probes: same-length majversion 2->1 edit of a v4.2.8-style backup with
# a copied (valid) trailer; content re-encrypted under the v1 KDF. Correct
# v1 key -> decrypts, digest check fails (7) exactly as on both devices;
# shifted-salt key -> padding failure (13). Device-validated byte-for-byte.
block(
    "v1-probes",
    lambda: [
        run("v1-probe", "v1probe.bkup", None, "testpass", code=7),
        run("v1-badkey", "v1badkey.bkup", None, "testpass", code=13),
    ],
)

# --- clone-crafted vectors (tests/vectors/README.md for lineage) -----------


def probe_crafted():
    # huge be32 X: trailer can never fit the first 0x4000-byte chunk
    run("xbig", "xbig.bkup", None, "testpass", code=6)
    # algo=2: the version gate runs BEFORE the algo check (RECON §6), so
    # this vector keeps version valid and lands on the algo error
    run("algo2", "algo2.bkup", None, "testpass", code=32)
    # strict version=9 (NOT padded — v9.bkup is the padded accept->7 probe)
    run("version-strict-9", "v9s.bkup", None, "testpass", code=12)
    try:
        decrypt_backup(V / "v9s.bkup", TMP / "v9s2.out", "testpass")
        det = ""
    except BackupError as exc:
        det = str(exc)
    check("v9s: 'Invalid archive' gate detail", det == "(12) Invalid archive", det)
    # iv valid hex but 8 bytes instead of 16: fail closed at parse (6)
    run("ivlen", "ivlen.bkup", None, "testpass", code=6)
    # second (duplicated) SignerInfo with a corrupted signature: PKCS7_verify
    # checks EVERY signerInfo, so the whole container is 7 even though the
    # first signer alone would pass
    run("sig2bad", "sig2bad.bkup", None, "testpass", code=7)


block("crafted-vectors", probe_crafted)

# --- file-level failures (error 1) ------------------------------------------


def probe_file_errors():
    # unwritable output path (missing directory): open fails -> 1
    try:
        decrypt_backup(V / "test.bkup", TMP / "no-such-dir" / "x.out", "testpass")
        got = 0
    except BackupError as exc:
        got = exc.code
    check("lib: unwritable -o path -> failed (1)", got == 1, f"got {got}")

    # missing input file: 1, and no output file survives
    out = TMP / "missing.out"
    check("lib: missing input -> failed (1)", err_code(TMP / "nope.bkup", out) == 1)
    check("lib: missing input leaves no output", not out.exists())

    # unreadable input file (mode 000); root bypasses DAC, so skip there
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        check("lib: unreadable input -> failed (1) (skipped: running as root)", True)
    else:
        src = TMP / "unreadable.bkup"
        src.write_bytes((V / "test.bkup").read_bytes())
        out = TMP / "unreadable.out"
        src.chmod(0o000)
        try:
            check("lib: unreadable input -> failed (1)", err_code(src, out) == 1)
        finally:
            src.chmod(0o644)


block("file-errors", probe_file_errors)

# --- agreed v1-dispatch probes (parse-fail -> default 1 -> wrong key -> 13) --


def edit_header(d, old, new):
    text = d[:0x400].split(b"\x00", 1)[0].decode("latin-1")
    assert text.count(old) == 1, old
    blk = text.replace(old, new).encode("latin-1")
    assert len(blk) < 0x400
    return blk + b"\x00" * (0x400 - len(blk)) + d[0x400:]


def probe_maj_dispatch():
    base = (V / "test.bkup").read_bytes()
    for name, value in [("mvblank", " 2"), ("mvbig", "90000")]:
        src = TMP / f"{name}.bkup"
        src.write_bytes(edit_header(base, "majversion=2", f"majversion={value}"))
        run(name, None, None, "testpass", code=13, path=src)


block("maj-dispatch", probe_maj_dispatch)

# --- header ----------------------------------------------------------------
HEADER_DATA = (V / "test.bkup").read_bytes()
text, fields = parse_header(HEADER_DATA[:0x400])
block(
    "header",
    lambda: [
        check("header: majversion", fields.get("majversion") == "2"),
        check("header: algo", fields.get("algo") == "1"),
        check("header: pbkdf", fields.get("pbkdf_iterations") == "10000"),
        check("header: quoted date", fields.get("date", "").startswith("20")),
    ],
)


def probe_header_block():
    blk = HEADER_DATA[:0x400]
    nul = blk.find(b"\x00")
    # the raw 0x400 block terminates with a NUL run: text, one NUL, all-zero
    # padding to 0x400 (the signature covers these exact bytes, so this is
    # worth pinning on the raw block, not on the already-split text)
    check(
        "header: NUL terminator + all-zero pad in raw 0x400 block",
        0 < nul < 0x400
        and blk[:nul].decode("latin-1") == text
        and blk[nul:] == bytes(0x400 - nul),
        f"first NUL at {nul}",
    )
    # duplicate keys: first occurrence wins
    dup = b"[BACKUP]\n" + blk[9:].split(b"\x00", 1)[0] + b"algo=2\n"
    _t, dup_fields = parse_header(dup + b"\x00" * (0x400 - len(dup)))
    check("header: duplicate keys, first wins", dup_fields.get("algo") == "1")


block("header-block", probe_header_block)

# --- crypto ----------------------------------------------------------------
key = derive_key_v2(
    b"testpass", bytes.fromhex(fields["salt"]), int(fields["pbkdf_iterations"])
)
block(
    "crypto-v2",
    lambda: [
        check("v2 KDF: 16-byte key", len(key) == 16),
        check(
            "v2 dispatch matches direct PBKDF2",
            _crypto_datas(fields, 2, "testpass")[0] == key
            and _crypto_datas(fields, 2, "testpass")[2] == 1,
        ),
        check("v2 iv", _crypto_datas(fields, 2, "testpass")[1] == bytes.fromhex(fields["iv"])),
    ],
)


def probe_crypto_units():
    # v1: SHA1(salt || password)[:16] — empirically confirmed on v4.2.8 and
    # v5.1.4 device binaries (v1 probe matrix: correct salt -> 7, shifted -> 13)
    check("v1 key salt", V1_KEY_SALT == bytes.fromhex("2807a5ef00620c4b62f32e0985e30e4e"))
    check("v1 iv salt", V1_IV_SALT == bytes.fromhex("463538798d48c8c0323df3e75109d221"))
    check("v1 key", derive_key_v1(b"x") == hashlib.sha1(V1_KEY_SALT + b"x").digest()[:16])
    check("v1 iv", derive_iv_v1(b"x") == hashlib.sha1(V1_IV_SALT + b"x").digest()[:16])
    # fill progression for sizes > 20 as LITERAL bytes (RECON §3 formula as
    # recovered from the disassembly), not re-derived from the formula in
    # crypto.py.  Unreachable on the backup path (KEY_LEN=16), pinned so a
    # future rewrite of _sha1_salted cannot silently change the progression.
    digest_x = hashlib.sha1(V1_KEY_SALT + b"x").digest()
    check(
        "v1 fill: size 21 == 20-byte digest + single 0xFF",
        _sha1_salted(V1_KEY_SALT, b"x", 21) == digest_x + b"\xff",
    )
    check(
        "v1 fill: size 32 tail progression",
        _sha1_salted(V1_KEY_SALT, b"x", 32)[20:]
        == bytes.fromhex("23384d62778ca1b6cbe0f50a"),
    )
    # strict header parsing (agreed spec): bytes.fromhex() silently ignores
    # embedded whitespace; the device hex parser does not -> parse error 6
    def expect_parse_error(name, mutate):
        f = dict(fields)
        mutate(f)
        try:
            _crypto_datas(f, 2, "testpass")
            check(name, False, "no BackupError raised")
        except BackupError as exc:
            check(name, exc.code == 6, f"got ({exc.code}) {exc}")

    expect_parse_error(
        "v2 strict hex: whitespace in salt -> 6",
        lambda f: f.update(salt=f["salt"][:8] + " " + f["salt"][8:]),
    )
    expect_parse_error(
        "v2 strict hex: whitespace in iv -> 6",
        lambda f: f.update(iv=f["iv"][:8] + " " + f["iv"][8:]),
    )
    expect_parse_error(
        "v2 strict iv length: 8 bytes -> 6",
        lambda f: f.update(iv=f["iv"][:16]),
    )
    # empty pbkdf_iterations value parses as absent: default 1 (RECON §8)
    f = dict(fields)
    f["pbkdf_iterations"] = ""
    try:
        k, _iv, _algo = _crypto_datas(f, 2, "testpass")
        check(
            "v2 empty pbkdf_iterations defaults like absent (1)",
            k == derive_key_v2(b"testpass", bytes.fromhex(fields["salt"]), 1),
        )
    except BackupError as exc:
        check("v2 empty pbkdf_iterations defaults like absent (1)", False, f"got ({exc.code})")

    # v1 dispatch through _crypto_datas (it is otherwise only ever called
    # with maj=2): key = SHA1(pool+16 || password)[:16], iv = SHA1(pool+0 ||
    # password)[:16] — the salt windows confirmed empirically on both VMs
    # (RECON §10).  Literals pinned for v1probe + "testpass".
    v1 = (V / "v1probe.bkup").read_bytes()
    _t1, f1 = parse_header(v1[:0x400])
    k1, iv1, a1 = _crypto_datas(f1, 1, "testpass")
    check("v1 dispatch: key pinned", k1 == bytes.fromhex("1e7ec182e995b7c31da212ce50af0c11"))
    check("v1 dispatch: iv pinned", iv1 == bytes.fromhex("a0c0e93259a1f234167e3db16ea6a4f4"))
    check("v1 dispatch: algo from header", a1 == 1)
    # device-confirmed oracle: that key/iv decrypts the v1probe ciphertext
    # cleanly (the payload of the backup these vectors were rebuilt from)
    x1 = int.from_bytes(v1[0x400:0x404], "big")
    check(
        "v1 dispatch: pinned key/iv decrypt v1probe payload",
        pkcs7_unpad(aes_cbc_decrypt(k1, iv1, v1[0x408 + x1 :])) == (V / "test.tar").read_bytes(),
    )


block("crypto-v1-units", probe_crypto_units)

# --- PKCS#7 ----------------------------------------------------------------
data = HEADER_DATA
X = int.from_bytes(data[0x400:0x404], "big")


def probe_pkcs7():
    certs, signers = parse_signed_data(data[0x404 : 0x404 + X])
    check("p7: two certificates", len(certs) == 2)
    si = signers[0]
    check("p7: sig alg rsa", si.sig_alg in ("1.2.840.113549.1.1.1", "1.2.840.113549.1.1.11"))
    check("p7: contentType data", si.content_type == "1.2.840.113549.1.7.1")
    check("p7: attrs DER starts with SET", si.attrs_der[0] == 0x31)
    leaf = x509.load_der_x509_certificate(certs[0])
    check(
        "p7: leaf has backup policy",
        any(
            p.policy_identifier.dotted_string == "1.3.6.1.4.1.11256.2.3"
            for p in leaf.extensions.get_extension_for_class(x509.CertificatePolicies).value
        ),
    )
    # the payload decrypted by the happy-path run above: the signature covers
    # header block + plaintext, so the attribute digest must match both
    plaintext = (TMP / "test.out").read_bytes()
    check(
        "p7: messageDigest == sha256(header+payload)",
        si.message_digest == hashlib.sha256(data[:0x400] + plaintext).digest(),
    )
    # the sig2bad vector really carries two signerInfos (the first one still
    # verifies; the container-level 7 is asserted in the crafted-vectors block)
    d2 = (V / "sig2bad.bkup").read_bytes()
    x2 = int.from_bytes(d2[0x400:0x404], "big")
    _c2, s2 = parse_signed_data(d2[0x404 : 0x404 + x2])
    check("p7: sig2bad trailer has two signerInfos", len(s2) == 2)


block("pkcs7", probe_pkcs7)

# --- trust store -----------------------------------------------------------
TRUST_PINS = [
    (
        "stormshield-sns-enrollment-products-ca.der",
        "CN=Stormshield Network Security Enrollment Products CA,"
        "OU=Stormshield Network Security,O=Stormshield,L=Issy-Les-Moulineaux,C=FR",
        2,
    ),
    (
        "netasq-firewall-ca.der",
        "OU=NETASQ Firewall Certification Authority,"
        "O=NETASQ - Secure Internet Connectivity,L=Villeneuve d'Ascq,ST=Nord,C=FR",
        0,  # non-positive serial: real CA's RFC 5280 violation, loads fine
    ),
    (
        "stormshield-products-root-ca.der",
        "CN=Stormshield Products Root CA,OU=Cloud Services,O=Stormshield,"
        "L=Issy-Les-Moulineaux,C=FR",
        10263568167357869717,
    ),
    (
        "stormshield-product-and-services-root-ca.der",
        "CN=Stormshield Product and Services Root CA,OU=Cloud Services,"
        "O=Stormshield,L=Issy-Les-Moulineaux,C=FR",
        9236807107523086887,
    ),
]


def probe_trust():
    with warnings.catch_warnings():
        # the NETASQ CA carries a non-positive serial (RFC 5280 violation
        # in the real CA); the original tool loads it fine
        warnings.simplefilter("ignore")
        store = load_trust_store()
        check("trust: four embedded CAs", len(store) == 4)
        for der, (fname, subject, serial) in zip(store, TRUST_PINS):
            cert = x509.load_der_x509_certificate(der)
            file_der = (ROOT / "decbackup" / "certs" / fname).read_bytes()
            check(
                f"trust: {fname} pinned by subject+serial",
                cert.subject.rfc4514_string() == subject
                and cert.serial_number == serial
                and der == file_der,
            )


block("trust", probe_trust)

# --- CLI -------------------------------------------------------------------
PY = sys.executable


def cli(*args, **kw):
    kw.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.run(
        [PY, "-m", "decbackup", *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=30,
        **kw,
    )


FAIL_FMT = "decrypt and/or verify backup failed ({})"


def cli_fail(name, bkup, code, password="testpass"):
    p = cli("-i", str(V / bkup), "-o", str(TMP / f"{name}.cli.out"), "-p", password)
    check(
        f"cli {name}: failed ({code})",
        p.returncode == 1 and p.stderr.strip() == FAIL_FMT.format(code),
        f"rc {p.returncode}, stderr {p.stderr!r}",
    )


def probe_cli_basics():
    out = TMP / "cli.out"
    p = cli("-i", str(V / "test.bkup"), "-o", str(out), "-p", "testpass")
    check("cli: silent success", p.returncode == 0 and not p.stdout and not p.stderr)
    check("cli: output byte-identical to test.tar", out.read_bytes() == (V / "test.tar").read_bytes())
    p = cli()
    check(
        "cli: usage without args",
        p.returncode == 1 and "Usage : () -i <backup> -o <output archive>" in p.stderr,
    )
    p = cli("-i", str(V / "test.bkup"), "-o", str(TMP / "cli2.out"), "-p", "a", "-p", "b")
    check(
        "cli: -p once",
        p.returncode == 1 and "-p can only be specified once" in p.stderr and "Usage" not in p.stderr,
    )  # device prints no usage here
    p = cli("-z")
    check(
        "cli: illegal option",
        p.returncode == 1 and "illegal option -- z" in p.stderr and "Usage" in p.stderr,
    )
    p = cli("-i", str(V / "test.bkup"), "-o", str(TMP / "cli3.out"), "-p", "testpass", "-d")
    # full dump text: "Header :" line + the raw header block up to its NUL
    # + trailing newline (device format, cli prints it verbatim)
    check(
        "cli: -d dumps the full header",
        p.returncode == 0 and p.stdout == f"Header :\n{text}\n",
        f"rc {p.returncode}",
    )
    p = cli("-i", str(V / "test.bkup"), "-o", str(TMP / "cli4.out"), "-p", "bad")
    check(
        "cli: failure message",
        p.returncode == 1 and p.stderr.strip() == FAIL_FMT.format(13),
    )
    # -P with no controlling terminal: t_getpass cannot reach /dev/tty, the
    # password falls back to empty -> 13 (documented pipe fallback).  A new
    # session detaches the inherited controlling tty, making this
    # deterministic no matter how the suite itself is launched.
    p = cli("-i", str(V / "test.bkup"), "-o", str(TMP / "cliP.out"), "-P", start_new_session=True)
    check(
        "cli: -P without tty uses empty password -> failed (13)",
        p.returncode == 1 and p.stderr.strip() == FAIL_FMT.format(13),
        f"rc {p.returncode}, stderr {p.stderr!r}",
    )


block("cli-basics", probe_cli_basics)


def probe_cli_errors():
    p = cli("-i", str(V / "test.bkup"), "-o", "/nonexistent-dir/x.tar", "-p", "testpass")
    check(
        "cli: unwritable -o path -> failed (1)",
        p.returncode == 1 and p.stderr.strip() == FAIL_FMT.format(1),
        f"rc {p.returncode}, stderr {p.stderr!r}",
    )
    for name, code in [
        ("xbig", 6),
        ("algo2", 32),
        ("v9s", 12),
        ("ivlen", 6),
        ("sig2bad", 7),
    ]:
        cli_fail(name, f"{name}.bkup", code)


block("cli-error-codes", probe_cli_errors)


def probe_itovf():
    # pbkdf_iterations=99999999999 (>= 2**31) must fail closed with 6 BEFORE
    # deriving any key; run as a subprocess so an unfixed implementation that
    # starts a 10^11-iteration PBKDF2 gets killed instead of wedging the run
    p = cli("-i", str(V / "itovf.bkup"), "-o", str(TMP / "itovf.out"), "-p", "testpass")
    check(
        "cli itovf: pbkdf_iterations >= 2**31 -> failed (6)",
        p.returncode == 1
        and p.stderr.strip() == FAIL_FMT.format(6)
        and not (TMP / "itovf.out").exists(),
        f"rc {p.returncode}, stderr {p.stderr!r}",
    )


block("cli-itovf", probe_itovf)

# --- --no-verify (clone extension) ------------------------------------------


def probe_noverify():
    p = cli("-i", str(V / "cert.bkup"), "-o", str(TMP / "nv1.out"), "-p", "testpass", "--no-verify")
    check(
        "cli: --no-verify rescues cert-tamper",
        p.returncode == 0
        and "UNAUTHENTICATED" in p.stderr
        and (TMP / "nv1.out").read_bytes() == (V / "test.tar").read_bytes(),
    )
    p = cli("-i", str(V / "test.bkup"), "-o", str(TMP / "nv2.out"), "-p", "bad", "--no-verify")
    check(
        "cli: --no-verify still needs the password",
        p.returncode == 1
        and p.stderr.splitlines()[-1] == FAIL_FMT.format(13),  # last line after the WARNING
    )
    p = cli("-i", str(V / "trunc.bkup"), "-o", str(TMP / "nv3.out"), "-p", "testpass", "--no-verify")
    check(
        "cli: --no-verify keeps structural floor",
        p.returncode == 1 and p.stderr.splitlines()[-1] == FAIL_FMT.format(8),
    )
    try:
        decrypt_backup(V / "cert.bkup", TMP / "nv4.out", "testpass", verify=False)
        ok = (TMP / "nv4.out").read_bytes() == (V / "test.tar").read_bytes()
    except BackupError:
        ok = False
    check("lib: verify=False kwarg", ok)


block("no-verify", probe_noverify)

fails = sum(1 for _, ok in RESULTS if not ok)
print(f"\n{len(RESULTS) - fails}/{len(RESULTS)} checks passed")
# exit statuses wrap mod 256: cap so a mass failure never looks like success
sys.exit(min(fails, 254))
