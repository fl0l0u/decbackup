"""Chain verification against the CAs embedded in ``libncrypto.so``.

``fw_libcrypto_get_trust_store`` (backup type) installs four hard-coded CA
certificates found in the library's .rodata at 0x8890, 0x6b40, 0x8f40 and
0x6f60, sets ``X509_V_FLAG_NO_CHECK_TIME`` (expired device certificates
still verify — backups stay readable forever) and adds the policy OID
``1.3.6.1.4.1.11256.2.3`` to the verify parameters.  The verify callback
accepts error codes 0, 9, 10 and 43 (NETASQ-issued), which boils down to:
build a signature-valid chain to one of the embedded roots, ignore dates.

Device-fidelity rules this module enforces, mirroring the OpenSSL defaults
that survive the verify callback's accept-list:

* the self-signed chain terminator must be byte-for-byte identical to one
  of the embedded anchors — the store lookup binds the chain to the genuine
  trusted certificate, subject+serial equality alone is forgeable;
* every certificate used as an issuer link needs ``basicConstraints``
  ``CA:TRUE`` (OpenSSL aborts with INVALID_CA, an error code 19 the
  callback does not accept) and a present ``pathLenConstraint`` is honoured
  (RFC 5280 4.2.1.9);
* an unknown signature algorithm OID fails closed instead of guessing a
  hash.
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

#: certificatePolicies extension OID
EXT_CERTIFICATE_POLICIES = "2.5.29.32"

#: anyPolicy — the policyInformation id that matches every required policy
ANY_POLICY_OID = f"{EXT_CERTIFICATE_POLICIES}.0"

_MAX_DEPTH = 8

_RSA_HASHES: dict[str, Callable[[], hashes.HashAlgorithm]] = {
    # 1.1.5 is sha1WithRSAEncryption.  1.1.1 (md5WithRSAEncryption) stays
    # unlisted on purpose: MD5 signatures are rejected as unknown algs.
    "1.2.840.113549.1.1.5": hashes.SHA1,
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
            elif alg in _RSA_HASHES:
                key.verify(sig, tbs, padding.PKCS1v15(), _RSA_HASHES[alg]())
            else:
                raise ChainError(f"unknown RSA signature algorithm OID: {alg}")
        elif isinstance(key, ec.EllipticCurvePublicKey):
            if alg in _ECDSA_HASHES:
                key.verify(sig, tbs, ec.ECDSA(_ECDSA_HASHES[alg]()))
            else:
                raise ChainError(f"unknown ECDSA signature algorithm OID: {alg}")
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


def _require_usable_issuer(issuer: x509.Certificate, issuers_below: int) -> None:
    """Reject a certificate OpenSSL would refuse as a chain builder.

    Missing or ``CA:FALSE`` ``basicConstraints`` fails the device verify
    with INVALID_CA (error 19, which the callback does not accept), so the
    link must not be built either.  A ``pathLenConstraint`` bounds the
    number of issuing certificates between this CA and the leaf (RFC 5280
    4.2.1.9); the self-signed chain terminator is exempt, mirroring
    OpenSSL's habit of not checking trust-anchor extensions.  The leaf
    itself is never checked here — only certificates acting as issuers.
    """
    try:
        bc = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        raise ChainError(
            f"issuer certificate without basicConstraints: {issuer.subject.rfc4514_string()}"
        ) from None
    except Exception as exc:  # tampered extension bytes: fail closed
        raise ChainError(f"unparsable basicConstraints extension: {exc}") from exc
    if not bc.ca:
        raise ChainError(
            f"issuer certificate is not a CA (basicConstraints CA:FALSE): "
            f"{issuer.subject.rfc4514_string()}"
        )
    if bc.path_length is not None and issuer.issuer != issuer.subject:
        if issuers_below > bc.path_length:
            raise ChainError(
                f"pathlen constraint violated: {issuer.subject.rfc4514_string()} "
                f"permits {bc.path_length} intermediate certificate(s), chain has {issuers_below}"
            )


def verify_chain(leaf_der: bytes, untrusted: list[bytes]) -> list[bytes]:
    """Build and cryptographically verify a chain from the leaf certificate
    to one of the embedded trust anchors.

    *untrusted* holds the extra certificates carried in the SignedData.
    Validity dates are ignored, mirroring the original's NO_CHECK_TIME.
    Returns the chain (leaf first, DER blobs).
    """
    try:
        return _verify_chain_inner(leaf_der, untrusted)
    except ChainError:
        raise
    except Exception as exc:
        # lazy field parsing in tampered certificates raises assorted
        # classes (ValueError, UnsupportedAlgorithm, DuplicateExtension,
        # ...); everything must fail closed into the original's error 7
        raise ChainError(f"certificate field error: {exc}") from exc


def _verify_chain_inner(leaf_der: bytes, untrusted: list[bytes]) -> list[bytes]:
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
            # The device's OpenSSL store lookup binds the chain terminator
            # to the genuine trusted certificate; matching an embedded CA
            # on subject+serial alone lets an attacker forge a root with
            # copied identity fields and verify it with its own key.  Only
            # a byte-for-byte copy of an embedded anchor is trusted.
            if chain[-1] in trusted:
                _verify_cert_signature(cur, cur)
                return chain
            raise ChainError("self-signed certificate is not trusted")
        found: tuple[x509.Certificate, bytes] | None = None
        rejected: list[str] = []
        for der, cand in zip(untrusted + trusted, others + trusted_certs):
            if cand.subject != cur.issuer:
                continue
            try:
                _require_usable_issuer(cand, issuers_below=len(chain) - 1)
                _verify_cert_signature(cur, cand)
            except ChainError as exc:
                rejected.append(str(exc))
                continue
            found = (cand, der)
            break
        if found is None:
            msg = f"unable to get issuer certificate: {cur.issuer.rfc4514_string()}"
            if rejected:
                msg += " (candidates rejected: " + "; ".join(rejected) + ")"
            raise ChainError(msg)
        cur, der = found
        chain.append(der)
    raise ChainError("maximum chain depth exceeded")


def _check_policy(cert: x509.Certificate) -> None:
    """The verify parameters require the Stormshield backup policy OID."""
    try:
        try:
            ext = cert.extensions.get_extension_for_oid(
                x509.ObjectIdentifier(EXT_CERTIFICATE_POLICIES)
            )
            ids = [p.policy_identifier.dotted_string for p in ext.value]
        except x509.ExtensionNotFound:
            return  # no policy extension: unconstrained, OpenSSL accepts it
    except Exception as exc:
        # known extensions are parsed lazily, so a certificatePolicies body
        # the parser chokes on raises right here; treating that as
        # "policy satisfied" would fail open — reject instead
        raise ChainError(f"unparsable certificatePolicies extension: {exc}") from exc
    if BACKUP_POLICY_OID in ids or ANY_POLICY_OID in ids:  # anyPolicy
        return
    raise ChainError(f"certificate policy {BACKUP_POLICY_OID} not satisfied")
