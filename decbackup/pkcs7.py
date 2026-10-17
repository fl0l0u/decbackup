"""Detached PKCS#7 SignedData verification for Stormshield backups.

Recovered from ``libncrypto.so`` (``VerifyMajSignatureInit`` /
``VerifySignatureFinal`` and the OpenSSL 3 ``PKCS7_*`` helpers they call):

* the trailer is a detached ``SignedData`` — the content itself is not
  encapsulated;
* the signed content is the **full 0x400-byte header block** (text plus
  NUL padding) followed by the decrypted payload;
* the signature is RSA/ECDSA over the DER of the authenticated attributes
  with the ``[0]`` context tag replaced by ``SET`` (``0x31``); Stormshield's
  encoder stores the attribute SEQUENCEs directly under ``[0]`` without a
  SET wrapper, so the tag swap also has to re-emit the length;
* the ``messageDigest`` attribute must equal ``SHA256(content)``.
"""

from __future__ import annotations

import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding

from .der import DERError, children, encode_len, oid_str, read_tlv

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_PKCS7_DATA = "1.2.840.113549.1.7.1"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"

_HASHES = {
    "1.2.840.113549.1.1.14": hashes.SHA224,
    "1.2.840.113549.1.1.12": hashes.SHA256,
    "2.16.840.1.101.3.4.2.1": hashes.SHA256,
    "2.16.840.1.101.3.4.2.2": hashes.SHA384,
    "2.16.840.1.101.3.4.2.3": hashes.SHA512,
}

_SIG_ALGS = {
    # rsaEncryption: the DigestInfo lives in the padding, so the digest
    # algorithm comes from the SignerInfo's digestAlgorithm field.
    "1.2.840.113549.1.1.1": "rsa",
    "1.2.840.113549.1.1.10": "rsa-pss",
    "1.2.840.113549.1.1.11": "rsa",
    "1.2.840.113549.1.1.12": "rsa",
    "1.2.840.113549.1.1.13": "rsa",
    "1.2.840.10045.4.3.2": "ecdsa",
    "1.2.840.10045.4.3.3": "ecdsa",
    "1.2.840.10045.4.3.4": "ecdsa",
}


class SignatureError(Exception):
    """Signature/attribute verification failed (original error code 7)."""


class SignerInfo:
    """One parsed ``SignerInfo`` with its raw DER pieces."""

    def __init__(self, buf: bytes, start: int, end: int):
        fields = list(children(buf, start, end))
        if len(fields) < 6:
            raise SignatureError("truncated SignerInfo")
        self.version = int.from_bytes(buf[fields[0][1]:fields[0][3]], "big")
        self.sid = fields[1]
        self.digest_alg = oid_str(buf, *_oid_span(buf, fields[2]))
        # fields[3] is [0] authenticatedAttributes, fields[4] the signature
        # AlgorithmIdentifier and fields[5] the OCTET STRING signature.
        self.sig_alg = oid_str(buf, *_oid_span(buf, fields[4]))
        attrs = fields[3]
        if attrs[0] & 0xC0 != 0x80:
            raise SignatureError("authenticatedAttributes missing")
        # PKCS#7 signs the attributes as a SET OF.  Stormshield stores them
        # bare under the [0] tag; a standard encoder nests a SET inside.
        value = buf[attrs[1]:attrs[3]]
        if value and value[0] == 0x31:
            self.attrs_der = value
        else:
            self.attrs_der = b"\x31" + encode_len(len(value)) + value
        self.signature = buf[fields[5][1]:fields[5][3]]
        self._attributes(buf, attrs)
        self._sid(buf, self.sid)

    def _attributes(self, buf: bytes, attrs) -> None:
        self.content_type: str | None = None
        self.message_digest: bytes | None = None
        inner = buf[attrs[1]:attrs[3]]
        start, end = 0, len(inner)
        if inner and inner[0] == 0x31:  # SET wrapper present
            _, start, _, end = read_tlv(inner, 0)
        for _tag, vs, _ln, ni in children(inner, start, end):
            vals = list(children(inner, vs, ni))
            if len(vals) < 2:
                continue
            oid = oid_str(inner, vals[0][1], vals[0][3])
            # vals[1] is the SET OF holding the actual value TLV
            try:
                value = list(children(inner, vals[1][1], vals[1][3]))[0]
            except (DERError, IndexError):
                continue  # noqa: B904
            if oid == OID_CONTENT_TYPE:
                self.content_type = oid_str(inner, value[1], value[3])
            elif oid == OID_MESSAGE_DIGEST:
                self.message_digest = inner[value[1]:value[3]]

    def _sid(self, buf: bytes, sid) -> None:
        """Extract issuer DER bytes + serial (issuerAndSerialNumber form)."""
        self.sid_serial: int | None = None
        self.sid_issuer_der: bytes | None = None
        inner = list(children(buf, sid[1], sid[3]))
        if len(inner) == 2:
            # the issuer Name TLV starts right at the SID value start
            self.sid_issuer_der = buf[sid[1]:inner[0][3]]
            self.sid_serial = int.from_bytes(buf[inner[1][1]:inner[1][3]],
                                             "big", signed=False)

    def find_signer_cert(self, certs: list[bytes]) -> bytes:
        """Pick the certificate the SID designates.

        Serial numbers are unique per issuer, so the serial match pins the
        signer; a wrong pick would fail signature verification anyway.
        """
        for der in certs:
            if self.sid_serial is None:
                continue
            cert = x509.load_der_x509_certificate(der)
            if cert.serial_number == self.sid_serial:
                return der
        if len(certs) == 1:  # no usable SID match; single candidate
            return certs[0]
        raise SignatureError("signer certificate not found in SignedData")

    def verify(self, certs: list[bytes], content: bytes) -> bytes:
        """Verify attributes signature + messageDigest over *content*.

        Returns the signer certificate DER on success.
        """
        signer_der = self.find_signer_cert(certs)
        if self.content_type not in (None, OID_PKCS7_DATA):
            raise SignatureError("unexpected contentType")
        if self.message_digest is None:
            raise SignatureError("missing messageDigest attribute")
        hasher = _HASHES.get(self.digest_alg)
        if hasher is None:
            raise SignatureError(
                f"unsupported digest algorithm {self.digest_alg}")
        if hashlib.new(hasher().name, content).digest() != self.message_digest:
            raise SignatureError("messageDigest mismatch")
        cert = x509.load_der_x509_certificate(signer_der)
        _verify(cert.public_key(), self.signature, self.attrs_der,
                self.sig_alg, hasher)
        return signer_der


def _oid_span(buf: bytes, alg_tlv):
    """(value_start, value_end) of the OID inside an AlgorithmIdentifier."""
    _, vs, _, ni = alg_tlv
    oid = read_tlv(buf, vs)  # first child is the algorithm OID
    return oid[1], oid[3]


def _verify(pubkey, signature: bytes, signed: bytes, sig_alg: str, hasher):
    kind = _SIG_ALGS.get(sig_alg, "rsa")
    try:
        if kind == "rsa":
            pubkey.verify(signature, signed, padding.PKCS1v15(), hasher())
        elif kind == "rsa-pss":
            pubkey.verify(signature, signed,
                          padding.PSS(mgf=padding.MGF1(hasher()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          hasher())
        else:  # ecdsa
            pubkey.verify(signature, signed, ec.ECDSA(hasher()))
    except SignatureError:
        raise
    except Exception as exc:  # includes InvalidSignature / UnsupportedAlgorithm
        raise SignatureError(f"signature verification failed: {exc}") from exc


def parse_signed_data(sig_der: bytes):
    """Parse a DER ``ContentInfo`` of type signedData.

    Returns ``(certs, signers)`` — certificate DER blobs and
    :class:`SignerInfo` objects.  Raises :class:`SignatureError` on any
    structural problem (original fail-closed behaviour, error code 6).
    """
    try:
        tag, vs, ln, ni = read_tlv(sig_der, 0)
        content_info = list(children(sig_der, vs, ni))
        if oid_str(sig_der, content_info[0][1],
                   content_info[0][3]) != OID_SIGNED_DATA:
            raise SignatureError("trailer is not a SignedData")
        sd = content_info[1]  # [0] EXPLICIT SignedData
        inner = read_tlv(sig_der, sd[1])  # the SignedData SEQUENCE itself
        fields = list(children(sig_der, inner[1], inner[3]))
    except (DERError, IndexError) as exc:
        raise SignatureError(f"cannot parse PKCS#7 trailer: {exc}") from exc

    certs: list[bytes] = []
    signers: list[SignerInfo] = []
    # SignedData field order is fixed: version, digestAlgorithms,
    # encapContentInfo, [certificates], [crls], signerInfos (last).
    for f in fields:
        if f[0] == 0xA0:  # certificates [0] — cert SEQUENCEs stored bare
            i = f[1]
            while i < f[3]:
                t, vs, ln, ni = read_tlv(sig_der, i)
                if t != 0x30:
                    break
                certs.append(sig_der[i:ni])
                i = ni
    if fields and fields[-1][0] in (0x30, 0x31):
        for si in children(sig_der, fields[-1][1], fields[-1][3]):
            signers.append(SignerInfo(sig_der, si[1], si[3]))
    if not signers:
        raise SignatureError("SignedData has no signerInfos")
    return certs, signers
