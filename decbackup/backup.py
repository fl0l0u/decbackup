"""Stormshield SNS backup container (``.bkup``) reader.

Layout, recovered from ``libncrypto.so`` ``fwcrypto_upd_update`` (flags=2,
the backup path) and cross-checked against ``encbackup``-produced files::

    offset           size    contents
    ------------------------------------------------------
    0x000            0x400   ``[BACKUP]`` header, key=value lines,
                             NUL terminated, zero padded to 0x400
    0x404            4       be32 *X* — length of the PKCS#7 trailer
    0x404+4          X       detached PKCS#7 SignedData (signature over
                             the full header block + plaintext, device
                             certificate, CA intermediate)
    0x404+X          4       be32 *Y* — plaintext/ciphertext length
    0x408+X          Y       AES-128-CBC ciphertext (PKCS#7 padding)

The original processes the file in 0x4000-byte chunks and only verifies
the signature when the trailer fits inside the first chunk; anything that
does not fit is rejected fail-closed (error 6), so the clone can simply
read the whole file.

Error codes are those printed by ``decbackup``'s
``decrypt and/or verify backup failed (%d)`` message; see RECON.md for the
empirical derivation of each.
"""

from __future__ import annotations

import contextlib
import os
import re
from pathlib import Path

from . import crypto, pkcs7, trust

HEADER_LEN = 0x400
CHUNK_LEN = 0x4000

# Error codes as reported by the original tool (0 = success is main()'s
# return value, not an error constant, so there is no E_OK).
E_FILE = 1  # input/output could not be opened (also: unexpected failure)
E_PARSE = 6  # signature trailer / crypto parameters unparsable
E_VERIFY = 7  # signature, chain or content digest verification failed
E_HEADER = 8  # file shorter than the 0x400 header block
E_MAJVERSION = 12  # unknown backup majversion / "Invalid archive"
E_DECRYPT = 13  # decryption failed (in practice: wrong password)
E_ALGO = 32  # unsupported cipher algorithm

_INT_RE = re.compile(r"[0-9]{1,4}\Z")
# unbounded digit / hex runs; \Z-anchored, ASCII only — str.isdigit() is
# unusable here because latin-1 headers can carry codepoints like "\u00b2"
# whose .isdigit() is True but which int() rejects, and str.fromhex()
# silently accepts embedded whitespace.
_DIGITS_RE = re.compile(r"[0-9]+\Z")
_HEX_RE = re.compile(r"[0-9A-Fa-f]+\Z")

#: AES-128-CBC block size; the v2 header ``iv`` must decode to exactly this
IV_LEN = 16

#: Upper bound for ``pbkdf_iterations``: OpenSSL's PKCS5_PBKDF2_HMAC
#: rejects iteration counts that do not fit a C int ("iteration value is
#: too great"), so a header value >= 2**31 can never succeed on the
#: device.  The exact code the device prints there is unprobed; the clone
#: fails closed at parse time with E_PARSE rather than letting hashlib
#: raise OverflowError.  Inferred deviation.
MAX_ITERATIONS = 2**31


class BackupError(Exception):
    """Decryption/verification failure carrying the original error code."""

    def __init__(self, code: int, detail: str = ""):
        super().__init__(f"({code}) {detail}" if detail else f"({code})")
        self.code = code


def parse_header(block: bytes) -> tuple[str, dict[str, str]]:
    """Split the header block at its NUL and parse ``key=value`` lines.

    Values may be double-quoted (``description="..."``).  Returns the raw
    text and an ordered mapping of the parameters; for duplicate keys the
    first occurrence wins.
    """
    text = block.split(b"\x00", 1)[0].decode("latin-1")
    fields: dict[str, str] = {}
    # Split on '\n' only.  The C section parser terminates lines at '\n'
    # (and the block at NUL); str.splitlines() would additionally honour
    # \x0b, \x0c, \x85 etc. in the latin-1-decoded text and over-split
    # headers the device reads as single lines.
    for line in text.split("\n"):
        key, _, value = line.partition("=")
        if not _:
            continue
        # values stay verbatim (the original's str_get_int_ex tolerates
        # leading but not trailing whitespace, so keep it observable)
        if len(value) >= 2 and value[0] == '"' == value[-1]:
            value = value[1:-1]
        # FIRST occurrence of a duplicate key wins: a libnbase section
        # scan that stops at the first match is the likelier behaviour of
        # the original parser, but this ordering is inferred, not probed
        # against the device.
        fields.setdefault(key.strip(), value)
    return text, fields


def _be32(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off : off + 4], "big")


def _version_ok(value: str | None) -> bool:
    """The original gate at 0x1318e (``Invalid archive``).

    ``fwcrypto_maj_get_version`` runs the parsed value through
    ``str_get_int_ex``, which skips *leading* whitespace but fails on
    trailing characters (strict mode).  Empirically a pure decimal value
    of up to four digits is compared against 1 and anything else (dotted
    versions, longer digit strings, trailing spaces) falls back to the
    default of 1 and passes.  See RECON.md: probes ``version=9`` → 12,
    ``version="9    "`` → 7 (accepted), ``version=90000`` → 7 (accepted),
    ``version=5.1.4`` → accepted.
    """
    m = _INT_RE.match((value or "").lstrip())
    return m is None or int(m.group()) == 1


def _ascii_int(value: str) -> int | None:
    """Strict ASCII-decimal parse (None = would not parse on the device)."""
    return int(value) if _DIGITS_RE.match(value) else None


def _parse_hex(value: str, name: str, size: int | None = None) -> bytes:
    """Strict hex decode of a header field, fail-closed with E_PARSE.

    ``bytes.fromhex()`` silently ignores embedded whitespace (``"aa bb"``
    decodes fine), which the device's hex parser has no equivalent of; any
    character outside ``[0-9A-Fa-f]`` is therefore a parse failure here.
    A *wrong-length* but otherwise valid value (e.g. a short iv) would
    only surface late on the device (EVP failure → 13); fail closed at
    parse time with E_PARSE instead — inferred, exact device code for a
    malformed iv length unprobed.
    """
    if not _HEX_RE.match(value):
        raise BackupError(E_PARSE, f"bad {name}: not strict ASCII hex")
    raw = bytes.fromhex(value)
    if size is not None and len(raw) != size:
        raise BackupError(E_PARSE, f"bad {name}: expected {size} bytes, got {len(raw)}")
    return raw


def _crypto_datas(fields: dict[str, str], maj_v: int, password: str) -> tuple[bytes, bytes, int]:
    """``fwcrypto_get_backup_crypto_datas`` + key derivation."""
    algo = _ascii_int(fields.get("algo", ""))
    if maj_v == 2:
        if algo is None:
            raise BackupError(E_PARSE, "missing algo")
        salt = _parse_hex(fields["salt"], "salt")
        iv = _parse_hex(fields["iv"], "iv", IV_LEN)
        # An empty value parses as absent: under the device's
        # parse-fail→default model both yield the same default of 1
        # (RECON §8: ``mov esi, 1`` near the getter).
        iterations = fields.get("pbkdf_iterations") or "1"
        iters = _ascii_int(iterations)
        if iters is None:
            raise BackupError(E_PARSE, "bad pbkdf_iterations")
        if iters >= MAX_ITERATIONS:
            raise BackupError(E_PARSE, "pbkdf_iterations too large")
        key = crypto.derive_key_v2(password.encode(), salt, iters)
    else:  # v1: salted SHA1, no parameters in the header
        if algo is None:
            algo = crypto.ALGO_AES_128_CBC
        pwd = password.encode()
        key = crypto.derive_key_v1(pwd)
        iv = crypto.derive_iv_v1(pwd)
    return key, iv, algo


def decrypt_backup(
    input_path: str | os.PathLike,
    output_path: str | os.PathLike,
    password: str = "",
    *,
    verify: bool = True,
) -> dict[str, str]:
    """Decrypt and (by default) verify a backup, mirroring ``decbackup``.

    On success returns the parsed header fields plus the key
    ``header_text``: the latin-1-decoded raw header block up to the first
    NUL — the exact bytes the signature covered, so callers (``-d``) need
    not re-open the input file.  Raises :class:`BackupError` with the
    original's numeric code otherwise.  No output file survives a
    failure — the original deletes it on every error path, and any
    unexpected internal failure is wrapped as E_FILE rather than
    surfacing as a traceback.

    ``verify=False`` is a clone extension (no such option exists on the
    device): it skips PKCS#7 trailer parsing and chain/signature
    verification entirely — the trailer length field is still required to
    locate the payload.  The output is then UNAUTHENTICATED plaintext;
    successful decryption alone says nothing about origin or integrity.
    """
    out = Path(output_path)
    try:
        # The original fopen()s the output early ("wb", truncating any
        # existing file) and removes it again on every error path.  Until
        # this truncate succeeds nothing may be unlinked: a failed open
        # must leave whatever was already there untouched.
        out.write_bytes(b"")
    except OSError as exc:
        raise BackupError(E_FILE, str(exc)) from exc

    try:
        return _decrypt_backup(input_path, out, password, verify)
    except BaseException as exc:
        # Structural guarantee, not per-error-path bookkeeping: once the
        # output has been created, NO failure leaves it behind.
        with contextlib.suppress(OSError):
            out.unlink(missing_ok=True)
        if isinstance(exc, BackupError):
            raise
        if isinstance(exc, OSError):
            raise BackupError(E_FILE, str(exc)) from exc
        raise BackupError(E_FILE, f"unexpected failure: {exc!r}") from exc


def _decrypt_backup(
    input_path: str | os.PathLike, out: Path, password: str, verify: bool
) -> dict[str, str]:
    try:
        data = Path(input_path).read_bytes()
    except OSError as exc:
        raise BackupError(E_FILE, str(exc)) from exc

    if len(data) < HEADER_LEN:
        raise BackupError(E_HEADER, "file shorter than backup header")

    block = data[:HEADER_LEN]
    text, fields = parse_header(block)

    # Empirically the version gate fires before the trailer-fit check:
    # a length-shifted file with a bad version yields 12, not 6 (§6).
    if not _version_ok(fields.get("version")):
        raise BackupError(E_MAJVERSION, "Invalid archive")

    # The signature trailer must fit in the first 0x4000-byte chunk the
    # original reads; otherwise verification can never run and the file
    # is rejected fail-closed (fwcrypto_upd_get_signature failed).
    first_len = min(CHUNK_LEN, len(data))
    sig_len = _be32(data, HEADER_LEN)
    if sig_len + HEADER_LEN + 4 >= first_len:
        raise BackupError(E_PARSE, "fwcrypto_upd_get_signature failed")

    # fwcrypto_get_backup_majversion: defaults to 1 when the key is
    # absent *or does not parse* (RECON §6 mvx.bkup).  Same shape as the
    # version gate's rule — 1–4 ASCII digits, cap included so a 5+ digit
    # value parses-fails to the default (device probe: 90000 → v1 path)
    # — but *without* the leading-whitespace skip: a whitespace-padded
    # value (e.g. " 2") parse-fails to the v1 default here.  Leading
    # whitespace is unprobed for this field either way; treating it as a
    # parse failure matches the device's default-on-parse-fail model and
    # lands " 2" on the v1 KDF (wrong key → 13).
    maj = fields.get("majversion")
    m = _INT_RE.match(maj) if maj is not None else None
    maj_v = int(m.group()) if m else 1
    if maj_v not in (1, 2):
        raise BackupError(E_MAJVERSION, f"Unknown backup majversion: {maj_v}")

    if verify:
        try:
            certs, signers = pkcs7.parse_signed_data(
                data[HEADER_LEN + 4 : HEADER_LEN + 4 + sig_len]
            )
        except pkcs7.SignatureError as exc:
            # fail closed: unparsable trailer means no verification possible
            raise BackupError(E_PARSE, str(exc)) from exc

    try:
        key, iv, algo = _crypto_datas(fields, maj_v, password)
    except BackupError:
        raise
    except (ValueError, KeyError) as exc:
        raise BackupError(E_PARSE, f"fwcrypto_get_backup_crypto_datas: {exc}") from exc

    if algo != crypto.ALGO_AES_128_CBC:
        raise BackupError(E_ALGO, f"unsupported algo ({algo})")

    off = HEADER_LEN + 4 + sig_len + 4
    if off >= len(data):
        raise BackupError(E_PARSE, "fwcrypto_upd_get_data_size failed")
    # The device decrypts filesize - off bytes and ignores the be32 Y
    # field (device probes: +16 trailing bytes -> 13; 16 bytes short -> 13).
    ciphertext = data[off:]
    if len(ciphertext) % 16:
        raise BackupError(E_DECRYPT, "EVP_CipherFinal (maj) failed")

    try:
        plaintext = crypto.pkcs7_unpad(crypto.aes_cbc_decrypt(key, iv, ciphertext))
    except ValueError as exc:
        raise BackupError(E_DECRYPT, f"decrypt failed: {exc}") from exc

    if verify:
        # PKCS7_verify checks EVERY signerInfo, not just the first: any
        # signer failing its attribute/digest check or chain build is
        # error 7.
        content = block + plaintext
        try:
            for signer in signers:
                signer_der = signer.verify(certs, content)
                trust.verify_chain(signer_der, certs)
        except (pkcs7.SignatureError, trust.ChainError) as exc:
            raise BackupError(E_VERIFY, f"invalid backup: {exc}") from exc

    try:
        out.write_bytes(plaintext)
    except OSError as exc:
        raise BackupError(E_FILE, str(exc)) from exc
    # Raw signature-verified header text for callers (-d), so they never
    # have to re-read the input file after decryption (TOCTOU).
    fields["header_text"] = text
    return fields
