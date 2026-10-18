"""Chain verification against the CAs embedded in ``libncrypto.so``.

``fw_libcrypto_get_trust_store`` (backup type) installs four hard-coded CA
certificates found in the library's .rodata at 0x8890, 0x6b40, 0x8f40 and
0x6f60, sets ``X509_V_FLAG_NO_CHECK_TIME`` (expired device certificates
still verify — backups stay readable forever) and adds the policy OID
``1.3.6.1.4.1.11256.2.3`` to the verify parameters.  The verify callback
accepts error codes 0, 9, 10 and 43 (NETASQ-issued), which boils down to:
build a signature-valid chain to one of the embedded roots, ignore dates.
"""

from __future__ import annotations

import warnings
from collections.abc import Callable
from functools import lru_cache
from importlib import resources

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

#: certificatePolicies OID the verify parameters require (EXPLICIT_POLICY)
BACKUP_POLICY_OID = "1.3.6.1.4.1.11256.2.3"

EXT_CERTIFICATE_POLICIES = "2.5.29.32"

_MAX_DEPTH = 8

_RSA_HASHES: dict[str, Callable[[], hashes.HashAlgorithm]] = {
    "1.2.840.113549.1.1.5": hashes.MD5,
    "1.2.840.113549.1.1.11": hashes.SHA256,
    "1.2.840.113549.1.1.12": hashes.SHA384,
    "1.2.840.113549.1.1.13": hashes.SHA512,
}

_ECDSA_HASHES: dict[str, Callable[[], hashes.HashAlgorithm]] = {
    "1.2.840.10045.4.3.2": hashes.SHA256,
    "1.2.840.10045.4.3.3": hashes.SHA384,
    "1.2.840.10045.4.3.4": hashes.SHA512,
}


class ChainError(Exception):
    """Chain construction failed (original error code 7)."""


def load_trust_store() -> list[bytes]:
    """DER blobs of the four CA certificates embedded in libncrypto."""
    store = resources.files(__package__).joinpath("certs")
    names = (
        "stormshield-sns-enrollment-products-ca.der",
        "netasq-firewall-ca.der",
        "stormshield-products-root-ca.der",
        "stormshield-product-and-services-root-ca.der",
    )
    with warnings.catch_warnings():
        # the NETASQ CA carries a non-positive serial (RFC 5280 violation
        # in the real CA); the original tool loads it fine.
        warnings.simplefilter("ignore")
        return [store.joinpath(n).read_bytes() for n in names]


@lru_cache(maxsize=1)
def _netasq_subject_der() -> bytes:
    der = (
        resources.files(__package__)
        .joinpath("certs")
        .joinpath("netasq-firewall-ca.der")
        .read_bytes()
    )
    return _load_cert(der).subject.public_bytes()


def _netasq_issued(cert: x509.Certificate) -> bool:
    """``fw_libcrypto_is_netasq_issued``: DER memcmp of the issuer Name."""
    return cert.issuer.public_bytes() == _netasq_subject_der()


def _verify_cert_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    """Check *cert*'s signature against *issuer*'s public key."""
    sig, tbs = cert.signature, cert.tbs_certificate_bytes
    alg = cert.signature_algorithm_oid.dotted_string
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            if alg == "1.2.840.113549.1.1.10":  # rsassa-pss
                key.verify(
                    sig,
                    tbs,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256(),
                )
            else:
                key.verify(sig, tbs, padding.PKCS1v15(), _RSA_HASHES.get(alg, hashes.SHA256)())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(sig, tbs, ec.ECDSA(_ECDSA_HASHES.get(alg, hashes.SHA256)()))
        else:
            raise ChainError(f"unsupported issuer key type: {type(key)}")
    except ChainError:
        raise
    except Exception as exc:
        raise ChainError(f"certificate signature check failed: {exc}") from exc


def _load_cert(der: bytes) -> x509.Certificate:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return x509.load_der_x509_certificate(der)
        except ValueError as exc:
            raise ChainError(f"unparsable certificate: {exc}") from exc


def verify_chain(leaf_der: bytes, untrusted: list[bytes]) -> list[bytes]:
    """Build and cryptographically verify a chain from the leaf certificate
    to one of the embedded trust anchors.

    *untrusted* holds the extra certificates carried in the SignedData.
    Validity dates are ignored, mirroring the original's NO_CHECK_TIME.
    Returns the chain (leaf first, DER blobs).
    """
    trusted = load_trust_store()
    trusted_certs = [_load_cert(der) for der in trusted]
    others = [_load_cert(der) for der in untrusted]

    leaf = _load_cert(leaf_der)
    try:
        _check_policy(leaf)
    except ChainError:
        # the verify callback accepts error 43 (no matching policy) only
        # for NETASQ-issued certs (fw_libcrypto_is_netasq_issued)
        if not _netasq_issued(leaf):
            raise

    chain = [leaf_der]
    cur = leaf
    for _ in range(_MAX_DEPTH):
        if cur.issuer == cur.subject:  # self-signed: must be an anchor
            for anchor in trusted_certs:
                if anchor.subject == cur.subject and anchor.serial_number == cur.serial_number:
                    _verify_cert_signature(cur, cur)
                    return chain
            raise ChainError("self-signed certificate is not trusted")
        found: tuple[x509.Certificate, bytes] | None = None
        for der, cand in zip(untrusted + trusted, others + trusted_certs):
            if cand.subject == cur.issuer:
                try:
                    _verify_cert_signature(cur, cand)
                except ChainError:
                    continue
                found = (cand, der)
                break
        if found is None:
            raise ChainError(f"unable to get issuer certificate: {cur.issuer.rfc4514_string()}")
        cur, der = found
        chain.append(der)
    raise ChainError("maximum chain depth exceeded")


def _check_policy(cert: x509.Certificate) -> None:
    """The verify parameters require the Stormshield backup policy OID."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.CertificatePolicies).value
    except x509.ExtensionNotFound:
        return  # no policy extension: unconstrained, OpenSSL accepts it
    try:
        ids = [p.policy_identifier.dotted_string for p in ext]
    except Exception:
        return
    if BACKUP_POLICY_OID in ids or "2.5.29.32.0" in ids:  # anyPolicy
        return
    raise ChainError(f"certificate policy {BACKUP_POLICY_OID} not satisfied")
