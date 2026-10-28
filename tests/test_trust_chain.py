#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Chain-building regressions for decbackup.trust.

Everything here is synthesised with the ``cryptography`` library: attacker
keypairs, forged roots, CA:FALSE intermediates, SHA-1 links and malformed
extensions.  The anchor case is the security regression: the pre-fix code
accepted a self-signed chain terminator on subject+serial equality alone
against the embedded store (fully forgeable); it must now be a byte-for-byte
copy of an embedded certificate, which is what the device's OpenSSL store
lookup does.

Exit code = number of failures.
"""

import contextlib
import datetime
import pathlib
import sys
import tempfile
import warnings

HERE = pathlib.Path(__file__).parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

# synthesised certs are deliberately expired (NO_CHECK_TIME parity) and the
# NETASQ CA has a non-positive serial; both only ever warn.
warnings.simplefilter("ignore")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from decbackup import decrypt_backup, trust  # noqa: E402
from decbackup.backup import BackupError  # noqa: E402
from decbackup.pkcs7 import parse_signed_data  # noqa: E402
from decbackup.trust import ChainError, load_trust_store, verify_chain  # noqa: E402

V = ROOT / "tests" / "vectors"
CERTS = ROOT / "decbackup" / "certs"
TMP = pathlib.Path(tempfile.mkdtemp(prefix="decbackup-trust-"))

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    mark = "ok  " if ok else "FAIL"
    print(f"{mark} {name}" + (f"  [{detail}]" if detail and not ok else ""))


def rejected(fn):
    """Run *fn*; return (rejected?, reason).  Chain build failures must
    always surface as ChainError (backup.py maps those onto exit code 7)."""
    try:
        fn()
    except ChainError as exc:
        return True, str(exc)
    except Exception as exc:  # a traceback escaping trust.py is itself a bug
        return False, f"{type(exc).__name__}: {exc}"
    return False, "accepted"


@contextlib.contextmanager
def fake_store(roots):
    """Swap the embedded trust store for synthesised roots (test-local)."""
    orig = trust.load_trust_store
    trust.load_trust_store = lambda: list(roots)
    try:
        yield
    finally:
        trust.load_trust_store = orig


NOW = datetime.datetime(2020, 1, 1)


def keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def cn(text):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])


def make_cert(subject, issuer, subject_key, issuer_key, *, ca=False,
              path_length=None, policy_ids=("1.3.6.1.4.1.11256.2.3",), serial=None):
    """DER of a synthesised certificate.  Dates are long expired (the
    device ignores them); policy_ids=() omits the extension entirely."""
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .serial_number(x509.random_serial_number() if serial is None else serial)
        .not_valid_before(NOW)
        .not_valid_after(NOW + datetime.timedelta(days=3650))
        .public_key(subject_key.public_key())
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=ca)
    )
    if policy_ids:
        b = b.add_extension(
            x509.CertificatePolicies(
                [x509.PolicyInformation(x509.ObjectIdentifier(p), None) for p in policy_ids]
            ),
            critical=False,
        )
    return b.sign(issuer_key, hashes.SHA256()).public_bytes(Encoding.DER)


# This cryptography build refuses SHA-1 in the certificate builder, so
# genuine SHA-1-signed certs are re-signed by hand: re-hash the TBS and
# rebuild the Certificate with the matching AlgorithmIdentifier.
_SIG_ALGID = {
    hashes.SHA1: "06092a864886f70d010105",  # sha1WithRSAEncryption
    hashes.SHA256: "06092a864886f70d01010b",  # sha256WithRSAEncryption
}


def der_tlv(tag, content):
    n = len(content)
    if n < 128:
        head = bytes([tag, n])
    elif n < 256:
        head = bytes([tag, 0x81, n])
    else:
        head = bytes([tag, 0x82, n >> 8, n & 0xFF])
    return head + content


def resign(der, issuer_key, sig_alg, *, label_oid_hex=None):
    """Return *der* re-signed over its own TBS with *sig_alg*.

    *label_oid_hex* lets the AlgorithmIdentifier claim a different
    algorithm than the signature really uses (label/identity tests)."""
    cert = x509.load_der_x509_certificate(der)
    sig = issuer_key.sign(cert.tbs_certificate_bytes, padding.PKCS1v15(), sig_alg())
    algid = der_tlv(0x30, bytes.fromhex(label_oid_hex or _SIG_ALGID[sig_alg]) + bytes.fromhex("0500"))
    body = cert.tbs_certificate_bytes + algid + der_tlv(0x03, b"\x00" + sig)
    return der_tlv(0x30, body)


def tamper_ext_value(der, oid_hex, payload):
    """Replace an extension's extnValue in place.  *payload* must keep the
    original byte length so the enclosing DER lengths stay valid."""
    i = der.index(bytes.fromhex(oid_hex))
    j = i + len(bytes.fromhex(oid_hex))
    if der[j] == 0x01:  # optional critical BOOLEAN
        j += 2 + der[j + 1]
    assert der[j] == 0x04 and der[j + 1] == len(payload), "extnValue size drifted"
    return der[: j + 2] + payload + der[j + 2 + len(payload) :]


# --- 1. trust anchor: exact DER match, not subject+serial -------------------
real_root = x509.load_der_x509_certificate(
    (CERTS / "stormshield-products-root-ca.der").read_bytes()
)
atk_key = keypair()
forged_root = make_cert(
    real_root.subject,  # identity copied from the embedded CA
    real_root.subject,
    atk_key,
    atk_key,  # but a fresh attacker keypair signs it
    ca=True,
    serial=real_root.serial_number,  # serial copied too
)
forged_leaf = make_cert(cn("VMSNSX00ZDEADBEEF"), real_root.subject, keypair(), atk_key)
ok, why = rejected(lambda: verify_chain(forged_leaf, [forged_root]))
check("anchor: forged root with copied subject+serial rejected", ok and "trusted" in why, why)

ok, why = rejected(lambda: verify_chain(forged_leaf, []))
check("anchor: forged chain without the fake root still rejected", ok, why)

root_der = (CERTS / "stormshield-products-root-ca.der").read_bytes()
try:
    chain = verify_chain(root_der, [])
    ok, why = chain == [root_der], ""
except ChainError as exc:
    ok, why = False, str(exc)
check("anchor: genuine embedded root still accepted (DER-identical)", ok, why)

# --- 2. issuer links: CA:TRUE required, pathLen honoured ---------------------
r_key, i_key, l_key = keypair(), keypair(), keypair()
root = make_cert(cn("FAKE TEST ROOT CA"), cn("FAKE TEST ROOT CA"), r_key, r_key, ca=True)
leaf = make_cert(cn("VMSNSX00Z000001"), cn("FAKE ISSUING CA"), l_key, i_key)

bad_inter = make_cert(cn("FAKE ISSUING CA"), cn("FAKE TEST ROOT CA"), i_key, r_key, ca=False)
with fake_store([root]):
    ok, why = rejected(lambda: verify_chain(leaf, [bad_inter]))
check("issuer: CA:FALSE intermediate rejected as issuer", ok, why)

with fake_store([root]):
    ok, why = rejected(lambda: verify_chain(leaf, [bad_inter, root]))
check("issuer: CA:FALSE link rejected even with its root present", ok, why)

good_inter = make_cert(cn("FAKE ISSUING CA"), cn("FAKE TEST ROOT CA"), i_key, r_key, ca=True)
with fake_store([root]):
    try:
        chain = verify_chain(leaf, [good_inter])
        ok, why = len(chain) == 3, ""
    except ChainError as exc:
        ok, why = False, str(exc)
check("issuer: CA:TRUE intermediate accepted", ok, why)

no_bc = (
    x509.CertificateBuilder()
    .subject_name(cn("FAKE ISSUING CA"))
    .issuer_name(cn("FAKE TEST ROOT CA"))
    .serial_number(x509.random_serial_number())
    .not_valid_before(NOW)
    .not_valid_after(NOW + datetime.timedelta(days=3650))
    .public_key(i_key.public_key())
    .add_extension(
        x509.CertificatePolicies(
            [x509.PolicyInformation(x509.ObjectIdentifier("1.3.6.1.4.1.11256.2.3"), None)]
        ),
        critical=False,
    )
    .sign(r_key, hashes.SHA256())
    .public_bytes(Encoding.DER)
)
with fake_store([root]):
    ok, why = rejected(lambda: verify_chain(leaf, [no_bc]))
check("issuer: intermediate without basicConstraints rejected", ok, why)

i1_key, i2_key = keypair(), keypair()
i2 = make_cert(cn("FAKE SUB CA"), cn("FAKE PATHLEN CA"), i2_key, i1_key, ca=True)
leaf2 = make_cert(cn("VMSNSX00Z000002"), cn("FAKE SUB CA"), l_key, i2_key)
tight = make_cert(cn("FAKE PATHLEN CA"), cn("FAKE TEST ROOT CA"), i1_key, r_key, ca=True,
                  path_length=0)
with fake_store([root]):
    ok, why = rejected(lambda: verify_chain(leaf2, [i2, tight]))
check("issuer: pathLen=0 with an intermediate below rejected",
      ok and "pathlen" in why.lower(), why)

loose = make_cert(cn("FAKE PATHLEN CA"), cn("FAKE TEST ROOT CA"), i1_key, r_key, ca=True,
                  path_length=1)
with fake_store([root]):
    try:
        chain = verify_chain(leaf2, [i2, loose])
        ok, why = len(chain) == 4, ""
    except ChainError as exc:
        ok, why = False, str(exc)
check("issuer: pathLen=1 with one intermediate below accepted", ok, why)

# shape of the real chain: embedded enrollment CA is pathLen=0 and only ever
# signs leaves — that must keep verifying
inter0 = make_cert(cn("FAKE ISSUING CA"), cn("FAKE TEST ROOT CA"), i_key, r_key, ca=True,
                   path_length=0)
with fake_store([root]):
    try:
        chain = verify_chain(leaf, [inter0])
        ok, why = len(chain) == 3, ""
    except ChainError as exc:
        ok, why = False, str(exc)
check("issuer: pathLen=0 with only the leaf below accepted", ok, why)

# --- 3. signature algorithm table --------------------------------------------
from decbackup.trust import _RSA_HASHES  # noqa: E402

check("sigalg: 1.2.840.113549.1.1.5 maps to SHA1", _RSA_HASHES["1.2.840.113549.1.1.5"] is hashes.SHA1)
check("sigalg: MD5 not in the table", all(h is not hashes.MD5 for h in _RSA_HASHES.values()))

sha1_inter = resign(
    make_cert(cn("FAKE ISSUING CA"), cn("FAKE TEST ROOT CA"), i_key, r_key, ca=True),
    r_key,
    hashes.SHA1,
)
check("sigalg: synthesised intermediate really is sha1WithRSAEncryption",
      x509.load_der_x509_certificate(sha1_inter).signature_algorithm_oid.dotted_string
      == "1.2.840.113549.1.1.5")
with fake_store([root]):
    try:
        chain = verify_chain(leaf, [sha1_inter])
        ok, why = len(chain) == 3, ""
    except ChainError as exc:
        ok, why = False, str(exc)
check("sigalg: SHA-1-signed intermediate accepted (chain end to end)", ok, why)

# valid SHA-256 signature labelled md5WithRSAEncryption (1.2.840.113549.1.1.1):
# the OID lookup must reject the link before the hash guess could ever match
md5_label = resign(
    make_cert(cn("FAKE ISSUING CA"), cn("FAKE TEST ROOT CA"), i_key, r_key, ca=True),
    r_key,
    hashes.SHA256,
    label_oid_hex="06092a864886f70d010101",
)
with fake_store([root]):
    ok, why = rejected(lambda: verify_chain(leaf, [md5_label]))
check("sigalg: md5WithRSAEncryption label rejected", ok and "algorithm" in why.lower(), why)

# any other unknown OID fails closed too (1.2.840.113549.1.1.14, sha224)
unk_label = resign(
    make_cert(cn("FAKE ISSUING CA"), cn("FAKE TEST ROOT CA"), i_key, r_key, ca=True),
    r_key,
    hashes.SHA256,
    label_oid_hex="06092a864886f70d01010e",
)
with fake_store([root]):
    ok, why = rejected(lambda: verify_chain(leaf, [unk_label]))
check("sigalg: unknown signature OID rejected (fail closed)", ok and "algorithm" in why.lower(), why)

# --- 4. certificatePolicies: unparsable body must not pass as satisfied ------
# one PolicyInformation with the backup OID serialises to exactly 15 bytes;
# swap in a same-length SEQUENCE-of-garbage that the parser chokes on lazily,
# then re-sign the tampered TBS so the chain would otherwise build — only the
# policy check can stop it
leaf_p = make_cert(cn("VMSNSX00Z000003"), cn("FAKE TEST ROOT CA"), l_key, r_key)
junk_policy = resign(
    tamper_ext_value(leaf_p, "0603551d20", b"\x30\x0d\x30\x0b\x05\x00" + b"\x00" * 9),
    r_key,
    hashes.SHA256,
)
with fake_store([root]):
    ok, why = rejected(lambda: verify_chain(junk_policy, []))
check("policy: unparsable certificatePolicies rejected", ok and "polic" in why.lower(), why)

leaf_any = make_cert(cn("VMSNSX00Z000004"), cn("FAKE TEST ROOT CA"), l_key, r_key,
                     policy_ids=("2.5.29.32.0",))  # anyPolicy, like the real roots
with fake_store([root]):
    try:
        verify_chain(leaf_any, [])
        ok, why = True, ""
    except ChainError as exc:
        ok, why = False, str(exc)
check("policy: anyPolicy still accepted", ok, why)

leaf_none = make_cert(cn("VMSNSX00Z000005"), cn("FAKE TEST ROOT CA"), l_key, r_key,
                      policy_ids=())  # absent extension stays unconstrained
with fake_store([root]):
    try:
        verify_chain(leaf_none, [])
        ok, why = True, ""
    except ChainError as exc:
        ok, why = False, str(exc)
check("policy: absent extension stays accepted", ok, why)

leaf_wrong = make_cert(cn("VMSNSX00Z000006"), cn("FAKE TEST ROOT CA"), l_key, r_key,
                       policy_ids=("1.3.6.1.4.1.9999.1",))
with fake_store([root]):
    ok, why = rejected(lambda: verify_chain(leaf_wrong, []))
check("policy: foreign policy OID still rejected", ok, why)

# --- 5. the genuine chain keeps verifying -------------------------------------
data = (V / "test.bkup").read_bytes()
X = int.from_bytes(data[0x400:0x404], "big")
certs, _ = parse_signed_data(data[0x404 : 0x404 + X])
try:
    chain = verify_chain(certs[0], certs)
    ok, why = len(chain) >= 2 and chain[0] == certs[0], ""
except ChainError as exc:
    ok, why = False, str(exc)
check("genuine: test.bkup chain verifies against the real store", ok, why)

out = TMP / "genuine.out"
try:
    decrypt_backup(V / "test.bkup", out, "testpass")
    code = 0
except BackupError as exc:
    code = exc.code
check("genuine: decrypt_backup(test.bkup) exit code 0", code == 0, f"got {code}")
check("genuine: payload matches test.tar",
      code == 0 and out.read_bytes() == (V / "test.tar").read_bytes())

# tampered trailer cert still lands in 7 territory via ChainError
tampered = bytearray(certs[0])
tampered[-32:-16] = bytes(16)
ok, why = rejected(lambda: verify_chain(bytes(tampered), certs))
check("genuine: tampered leaf rejected", ok, why)

# trust store untouched: four embedded CAs
check("store: four embedded CAs", len(load_trust_store()) == 4)

fails = sum(1 for _, ok in RESULTS if not ok)
print(f"\n{len(RESULTS) - fails}/{len(RESULTS)} checks passed")
sys.exit(fails)
