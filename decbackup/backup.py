"""Stormshield SNS backup container (``.bkup``) reader.

Layout, recovered from ``libncrypto.so`` ``fwcrypto_upd_update`` (flags=2,
the backup path) and cross-checked against ``encbackup``-produced files::

    offset           size    contents
    ------------------------------------------------------
    0x000            0x400   ``[BACKUP]`` header, key=value lines,
                             NUL terminated, zero padded to 0x400
    0x400            4       be32 *X* — length of the PKCS#7 trailer
    0x404            X       detached PKCS#7 SignedData (signature over
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

# Error codes as reported by the original tool.
E_OK = 0
E_FILE = 1  # input/output could not be opened
E_PARSE = 6  # signature trailer / crypto parameters unparsable
E_VERIFY = 7  # signature, chain or content digest verification failed
E_HEADER = 8  # file shorter than the 0x400 header block
E_MAJVERSION = 12  # unknown backup majversion / "Invalid archive"
E_DECRYPT = 13  # decryption failed (in practice: wrong password)
E_ALGO = 32  # unsupported cipher algorithm

_INT_RE = re.compile(r"[0-9]{1,4}\Z")


class BackupError(Exception):
    """Decryption/verification failure carrying the original error code."""

    def __init__(self, code: int, detail: str = ""):
        super().__init__(f"({code}) {detail}" if detail else f"({code})")
        self.code = code


def parse_header(block: bytes) -> tuple[str, dict[str, str]]:
    """Split the header block at its NUL and parse ``key=value`` lines.

    Values may be double-quoted (``description="..."``).  Returns the raw
    text and an ordered mapping of the parameters.
    """
    text = block.split(b"\x00", 1)[0].decode("latin-1")
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if not _:
            continue
        # values stay verbatim (the original's str_get_int_ex tolerates
        # leading but not trailing whitespace, so keep it observable)
        if len(value) >= 2 and value[0] == '"' == value[-1]:
            value = value[1:-1]
        fields[key.strip()] = value
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


def _crypto_datas(fields: dict[str, str], maj_v: int, password: str) -> tuple[bytes, bytes, int]:
    """``fwcrypto_get_backup_crypto_datas`` + key derivation."""
    algo = int(fields["algo"]) if fields.get("algo", "").isdigit() else None
    if maj_v == 2:
        if algo is None:
            raise BackupError(E_PARSE, "missing algo")
        try:
            salt = bytes.fromhex(fields["salt"])
            iv = bytes.fromhex(fields["iv"])
        except (KeyError, ValueError) as exc:
            raise BackupError(E_PARSE, f"bad salt/iv: {exc}") from exc
        iterations = fields.get("pbkdf_iterations", "1")
        if not iterations.isdigit():
            raise BackupError(E_PARSE, "bad pbkdf_iterations")
        key = crypto.derive_key_v2(password.encode(), salt, int(iterations))
    else:  # v1: salted SHA1, no parameters in the header
        if algo is None:
            algo = crypto.ALGO_AES_128_CBC
        pwd = password.encode()
        key = crypto.derive_key_v1(pwd)
        iv = crypto.derive_iv_v1(pwd)
    return key, iv, algo


def decrypt_backup(
    input_path: str | os.PathLike, output_path: str | os.PathLike, password: str = ""
) -> dict[str, str]:
    """Decrypt and verify a backup, mirroring ``decbackup``.

    Returns the parsed header fields on success; raises :class:`BackupError`
    with the original's numeric code otherwise.  No output file survives a
    failure — the original deletes it on every error path.
    """
    out = Path(output_path)
    try:
        # The original fopen()s the output early ("wb", truncating any
        # existing file) and removes it again on every error path.
        out.write_bytes(b"")
        return _decrypt_backup(input_path, out, password)
    except BackupError:
        with contextlib.suppress(OSError):
            out.unlink(missing_ok=True)
        raise
    except OSError as exc:
        raise BackupError(E_FILE, str(exc)) from exc


def _decrypt_backup(input_path, out: Path, password: str) -> dict[str, str]:
    try:
        data = Path(input_path).read_bytes()
    except OSError as exc:
        raise BackupError(E_FILE, str(exc)) from exc

    if len(data) < HEADER_LEN:
        raise BackupError(E_HEADER, "file shorter than backup header")

    block = data[:HEADER_LEN]
    _text, fields = parse_header(block)

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

    # fwcrypto_get_backup_majversion: defaults to 1 when the key is absent.
    maj = fields.get("majversion")
    if maj is None:
        maj_v = 1
    elif re.fullmatch(r"[0-9]+", maj):
        maj_v = int(maj)
    else:
        maj_v = 1
    if maj_v not in (1, 2):
        raise BackupError(E_MAJVERSION, f"Unknown backup majversion: {maj_v}")

    try:
        certs, signers = pkcs7.parse_signed_data(data[HEADER_LEN + 4 : HEADER_LEN + 4 + sig_len])
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

    content = block + plaintext
    try:
        signer_der = signers[0].verify(certs, content)
        trust.verify_chain(signer_der, certs)
    except (pkcs7.SignatureError, trust.ChainError) as exc:
        raise BackupError(E_VERIFY, f"invalid backup: {exc}") from exc

    try:
        out.write_bytes(plaintext)
    except OSError as exc:
        raise BackupError(E_FILE, str(exc)) from exc
    return fields
