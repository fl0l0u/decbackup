#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the fail-closed DER / PKCS#7 parsers (RECON §7b).

Complements tests/test_decbackup.py (end-to-end, vector driven): this file
pokes der.py with hand-built malformed inputs and pkcs7.py with same-length
mutations of the genuine tests/vectors/test.bkup trailer slice (persisted
under a /tmp workdir for inspection), so every hardened path keeps its own
regression guard.  The genuine trailer must still parse cleanly.

Exit code = number of failures.
"""

import hashlib
import pathlib
import re
import sys
import tempfile

HERE = pathlib.Path(__file__).parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from cryptography import x509  # noqa: E402

from decbackup import pkcs7 as p7  # noqa: E402
from decbackup.der import DERError, children, oid_str, read_tlv  # noqa: E402
from decbackup.pkcs7 import SignatureError, parse_signed_data  # noqa: E402

V = ROOT / "tests" / "vectors"
TMP = pathlib.Path(tempfile.mkdtemp(prefix="decbackup-der-units-"))

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    mark = "ok  " if ok else "FAIL"
    print(f"{mark} {name}" + (f"  [{detail}]" if detail and not ok else ""))


def check_raises(name, exc_type, fn, match=None):
    """fn() must raise exc_type (a subclass of it is fine, its base classes
    are not — DERError must not be satisfied by a plain ValueError)."""
    try:
        fn()
        check(name, False, "no exception raised")
    except exc_type as exc:
        ok = match is None or re.search(match, str(exc)) is not None
        check(name, ok, f"wrong message: {exc!r}" if not ok else "")
    except Exception as exc:
        check(name, False, f"wrong exception {type(exc).__name__}: {exc}")


# --- der.py: malformed primitives -------------------------------------------
# a negative index used to index from the buffer end and decode garbage
check_raises(
    "der: negative index rejected",
    DERError,
    lambda: read_tlv(b"\x30\x03\x01\x01\x01", -4),
    r"negative offset",
)
# truncated long-form length octets used to clamp and report "truncated value"
check_raises(
    "der: truncated long-form length",
    DERError,
    lambda: read_tlv(b"\x30\x82\x00", 0),
    r"truncated TLV",
)
check_raises(
    "der: truncated short-form value",
    DERError,
    lambda: read_tlv(b"\x04\x05AB", 0),
    r"truncated value",
)
check_raises(
    "der: indefinite length still rejected",
    DERError,
    lambda: read_tlv(b"\x30\x80\x00\x00", 0),
    r"indefinite length",
)
check_raises(
    "der: null filler still rejected",
    DERError,
    lambda: read_tlv(b"\x00\x00\x00\x00", 0),
    r"null filler",
)
# child TLV declaring a length past the parent's end must not swallow siblings
check_raises(
    "der: child beyond parent rejected",
    DERError,
    lambda: list(children(b"\x30\x06\x04\x04AABBCCDD", 2, 6)),
    r"child exceeds parent",
)
check(
    "der: child ending exactly at parent end accepted",
    len(list(children(b"\x30\x06\x04\x02AB\x05\x00", 2, 8))) == 2,
)
# 5000-byte continuation component: must be DERError, not str()'s ValueError
big = b"\x2a" + b"\x81" * 5000
check_raises(
    "der: 5000-byte OID component -> DERError not ValueError",
    DERError,
    lambda: oid_str(big, 0, len(big)),
    r"overlong OID component",
)
check_raises(
    "der: five-octet OID component rejected",
    DERError,
    lambda: oid_str(b"\x2a\x81\x81\x81\x81\x01", 0, 6),
    r"overlong OID component",
)
check(
    "der: four-octet OID component still accepted",
    oid_str(b"\x2a\x88\x87\x86\x45", 0, 5)
    == "1.2." + str((0x08 << 21) | (0x07 << 14) | (0x06 << 7) | 0x45),
)
check_raises(
    "der: OID cut mid-component rejected",
    DERError,
    lambda: oid_str(b"\x2a\x81", 0, 2),
    r"truncated OID component",
)
check(
    "der: valid OID decodes",
    oid_str(bytes.fromhex("2a864886f70d010101"), 0, 9) == "1.2.840.113549.1.1.1",
)


# --- pkcs7.py: mutations of the genuine test.bkup trailer --------------------
def trailer_of(bkup: str) -> bytes:
    data = (V / bkup).read_bytes()
    x = int.from_bytes(data[0x400:0x404], "big")
    return data[0x404 : 0x404 + x]


def signer_fields(buf: bytes):
    """Absolute TLV spans of the first SignerInfo's fields in *buf*."""
    _t, vs, _l, ni = read_tlv(buf, 0)
    ci = list(children(buf, vs, ni))
    inner = read_tlv(buf, ci[1][1])  # SignedData SEQUENCE
    sfields = list(children(buf, inner[1], inner[3]))
    signer = next(iter(children(buf, sfields[-1][1], sfields[-1][3])))
    return list(children(buf, signer[1], signer[3]))


def attr_spans(buf: bytes, attrs_tlv):
    """Absolute (start, end) of each attribute SEQUENCE under [0]."""
    inner = buf[attrs_tlv[1] : attrs_tlv[3]]
    start, end = 0, len(inner)
    if inner and inner[0] == 0x31:  # SET wrapper present
        _, start, _, end = read_tlv(inner, 0)
    return [(attrs_tlv[1] + vs, attrs_tlv[1] + ni) for _t, vs, _l, ni in children(inner, start, end)]


def attr_by_oid(buf: bytes, attrs_tlv, oid: str):
    for a0, a1 in attr_spans(buf, attrs_tlv):
        vals = list(children(buf, a0, a1))
        if vals and oid_str(buf, vals[0][1], vals[0][3]) == oid:
            return a0, a1, vals
    return None


def mut_byte(buf: bytes, off: int, val: int) -> bytes:
    m = bytearray(buf)
    m[off] = val
    return bytes(m)


TR = trailer_of("test.bkup")
certs, signers = parse_signed_data(TR)
check("p7: genuine test.bkup trailer parses cleanly", len(certs) == 2 and len(signers) == 1)
si = signers[0]
check(
    "p7: genuine attributes intact",
    si.content_type == "1.2.840.113549.1.7.1"
    and si.digest_alg == "2.16.840.1.101.3.4.2.1"
    and len(si.message_digest) == 32
    and si.sig_alg in ("1.2.840.113549.1.1.1", "1.2.840.113549.1.1.11")
    and si.attrs_der[0] == 0x31,
)
try:
    picked = si.find_signer_cert(certs)
    ok = picked in certs and x509.load_der_x509_certificate(picked).serial_number == si.sid_serial
except Exception:  # noqa: BLE001
    ok = False
check("p7: signer cert resolves by serial + issuer", ok)
check("p7: ecdsa-with-SHA224 admitted", p7._SIG_ALGS.get("1.2.840.10045.4.3.1") == "ecdsa")

sf = signer_fields(TR)
ct = attr_by_oid(TR, sf[3], "1.2.840.113549.1.9.3")
md = attr_by_oid(TR, sf[3], "1.2.840.113549.1.9.4")
check("p7: contentType + messageDigest located", ct is not None and md is not None)

# duplicated messageDigest (contentType OID retyped to ...1.9.4 keeps the
# edit the same length so all ancestor TLV lengths stay intact): last-wins
# must raise instead (the extdup bug class)
dup = mut_byte(TR, ct[2][0][3] - 1, 0x04)
(TMP / "dup-msgdigest.p7").write_bytes(dup)
check_raises(
    "p7: duplicated messageDigest -> SignatureError",
    SignatureError,
    lambda: parse_signed_data(dup),
    r"duplicate 1\.2\.840\.113549\.1\.9\.4",
)

# missing contentType: retyped to the unknown OID ...1.9.42 (skipped, like
# OpenSSL tolerates) -> verification must demand the attribute
noct = mut_byte(TR, ct[2][0][3] - 1, 0x2A)
(TMP / "no-contenttype.p7").write_bytes(noct)
_ct_certs, ct_signers = parse_signed_data(noct)
check_raises(
    "p7: missing contentType -> SignatureError",
    SignatureError,
    lambda: ct_signers[0].verify(certs, b""),
    r"missing contentType",
)

# empty digestAlgorithm SEQUENCE used to make _oid_span read the OID out of
# the NEXT field; the OID must lie inside the AlgorithmIdentifier
pad = bytes.fromhex("3000") + b"\x05\x00" * 5 + bytes.fromhex("06012a")  # 15 bytes
ed = bytearray(TR)
ed[sf[2][1] - 2 : sf[2][3]] = pad
check("p7: empty-digestAlg edit keeps trailer length", len(ed) == len(TR))
ed = bytes(ed)
(TMP / "empty-digestalg.p7").write_bytes(ed)
check_raises(
    "p7: empty digestAlgorithm -> SignatureError",
    SignatureError,
    lambda: parse_signed_data(ed),
    r"empty digest AlgorithmIdentifier",
)

# unknown signature algorithm OID used to default to "rsa"; rsaEncryption
# retyped to 1.2.840.113549.1.1.2.  The messageDigest is retyped to
# SHA256(b"") so verification reaches the algorithm dispatch with b"".
sv = list(children(TR, sf[4][1], sf[4][3]))
check("p7: signature AlgorithmIdentifier holds an OID", sv and TR[sv[0][1] - 2] == 0x06)
check("p7: messageDigest is a 32-byte OCTET STRING", TR[md[1] - 34] == 0x04 and TR[md[1] - 33] == 0x20)
u = bytearray(mut_byte(TR, sv[0][3] - 1, 0x02))
u[md[1] - 32 : md[1]] = hashlib.sha256(b"").digest()
u = bytes(u)
(TMP / "unknown-sigalg.p7").write_bytes(u)
_u_certs, u_signers = parse_signed_data(u)
check_raises(
    "p7: unknown signature algorithm OID -> SignatureError",
    SignatureError,
    lambda: u_signers[0].verify(certs, b""),
    r"unsupported signature algorithm",
)

# primitive [0] value element is not the constructed authenticatedAttributes
prim = mut_byte(TR, sf[3][1] - 2, 0x80)
(TMP / "primitive-attrs.p7").write_bytes(prim)
check_raises(
    "p7: primitive [0] authenticatedAttributes rejected",
    SignatureError,
    lambda: parse_signed_data(prim),
    r"authenticatedAttributes",
)

# a serial mismatch must not be masked by the sole-certificate fallback:
# hand find_signer_cert only the signer certificate — the old fallback
# returned it even though the SID declared a different serial
nsf = signer_fields(TR)
sidc = list(children(TR, nsf[1][1], nsf[1][3]))
check("p7: SID is issuerAndSerialNumber", len(sidc) == 2 and TR[sidc[1][1] - 2] == 0x02)
check("p7: genuine signer resolves against sole certificate", si.find_signer_cert(certs[:1]) == certs[0])
sm_arr = bytearray(TR)
sm_arr[sidc[1][3] - 1] ^= 0xFF  # flip the serial's last content byte
sm = bytes(sm_arr)
(TMP / "serial-mismatch.p7").write_bytes(sm)
_s_certs, sm_signers = parse_signed_data(sm)
si_bad = sm_signers[0]
check(
    "p7: mutated SID carries a (wrong) serial",
    si_bad.sid_serial is not None
    and si_bad.sid_serial != x509.load_der_x509_certificate(certs[0]).serial_number,
)
check_raises(
    "p7: serial mismatch with sole cert -> SignatureError",
    SignatureError,
    lambda: si_bad.find_signer_cert(certs[:1]),
    r"signer certificate not found",
)

fails = sum(1 for _, ok in RESULTS if not ok)
print(f"\n{len(RESULTS) - fails}/{len(RESULTS)} checks passed")
sys.exit(fails)
