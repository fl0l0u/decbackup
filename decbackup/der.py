"""Minimal DER (ASN.1 TLV) reader.

Just enough to walk PKCS#7 SignedData structures. Every function works on
plain ``bytes`` and offsets; a TLV is described by the tuple
``(tag, value_start, length, next)`` where ``next == value_start + length``.

Fail-closed discipline (RECON §7b): every malformed input raises
:class:`DERError` — nothing is clamped, skipped or silently defaulted.
"""

from __future__ import annotations

#: X.690 8.19.2 caps an OID subidentifier at four content octets; anything
#: longer is malformed (and would turn decoding into O(n^2) bigint math).
_MAX_OID_OCTETS = 4


class DERError(ValueError):
    """Raised when a buffer is not well-formed DER."""


def read_tlv(buf: bytes, i: int) -> tuple[int, int, int, int]:
    """Read one TLV at offset *i*; return ``(tag, value_start, length, next)``."""
    if i < 0:
        raise DERError("negative offset")
    try:
        tag = buf[i]
        j = i + 1
        if tag == 0x00:  # padding
            raise DERError("null filler")
        if tag == 0xFF:
            raise DERError("bad tag")
        if tag & 0x1F == 0x1F:  # high tag number form
            while buf[j] & 0x80:
                j += 1
            j += 1
        first = buf[j]
        j += 1
        if first < 0x80:
            length = first
        elif first == 0x80:
            raise DERError("indefinite length not supported")
        else:
            nbytes = first & 0x7F
            if nbytes > 8:
                raise DERError("overlong length")
            if j + nbytes > len(buf):
                raise DERError("truncated TLV")
            length = int.from_bytes(buf[j : j + nbytes], "big")
            j += nbytes
        if j + length > len(buf):
            raise DERError("truncated value")
        return tag, j, length, j + length
    except IndexError as exc:
        raise DERError("truncated TLV") from exc


def children(buf: bytes, start: int, end: int):
    """Yield every TLV between *start* and *end* as
    ``(tag, value_start, length, next)`` tuples.

    Every child must lie fully inside ``[start, end)``: a child declaring
    a length past the parent's end would silently swallow its siblings'
    bytes, so it raises :class:`DERError` instead.
    """
    i = start
    while i < end:
        tlv = read_tlv(buf, i)
        if tlv[3] > end:
            raise DERError("child exceeds parent")
        yield tlv
        i = tlv[3]


def encode_len(length: int) -> bytes:
    """DER length encoding of an integer."""
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def oid_str(buf: bytes, start: int, end: int) -> str:
    """Decode an OBJECT IDENTIFIER value to dotted form.

    A subidentifier whose continuation exceeds the four-octet X.690
    limit, or one cut off at the end of the value, raises
    :class:`DERError`; no component is ever silently dropped.
    """
    if start >= end:
        return ""
    first = buf[start]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    octets = 0
    for byte in buf[start + 1 : end]:
        value = (value << 7) | (byte & 0x7F)
        octets += 1
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
            octets = 0
        elif octets >= _MAX_OID_OCTETS:
            raise DERError("overlong OID component")
    if octets:
        raise DERError("truncated OID component")
    return ".".join(parts)
