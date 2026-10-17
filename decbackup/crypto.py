"""Key derivation and ciphers recovered from ``libncrypto.so``.

Two password-based schemes exist, selected by the backup header's
``majversion`` field:

* **v1** (``fwcrypto_keyfrompasswd`` / ``fwcrypto_ivfrompasswd``):
  ``SHA1(salt_constant || password)``, truncated/padded to the wanted
  length.  Only reachable by reading old backups; the 5.1.4 tools always
  write v2.
* **v2** (``fwcrypto_derivekey``): PBKDF2-HMAC-SHA256 over the password
  with the header's ``salt``/``pbkdf_iterations``; the IV is stored in the
  header in hex.

Both feed AES-128-CBC (``algo=1``) with standard PKCS#7 padding.
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#: AES-128-CBC
ALGO_AES_128_CBC = 1

#: salt constants embedded in libncrypto.so .rodata at 0x1b41f / 0x1b40f
V1_KEY_SALT = bytes.fromhex("212807a5ef00620c4b62f32e0985e30e")
V1_IV_SALT = bytes.fromhex("00463538798d48c8c0323df3e75109d2")

#: key length actually requested by the backup path (``mov esi, 0x10``)
KEY_LEN = 16


def _sha1_salted(salt: bytes, password: bytes, size: int) -> bytes:
    """``fwcrypto_keyfrompasswd``/``ivfrompasswd`` body.

    ``SHA1(salt || password)``; when the requested size exceeds the 20-byte
    digest the tail is filled with a byte progression (only relevant for
    key sizes > 20, which the backup path never requests).
    """
    digest = hashlib.sha1(salt + password).digest()
    if size <= len(digest):
        return digest[:size]
    buf = bytearray(digest) + bytes(size - len(digest))
    for i in range(len(digest), size):
        buf[i] = (size - 1 + (size - i) * 0xEB) & 0xFF
    return bytes(buf)


def derive_key_v1(password: bytes, size: int = KEY_LEN) -> bytes:
    return _sha1_salted(V1_KEY_SALT, password, size)


def derive_iv_v1(password: bytes, size: int = KEY_LEN) -> bytes:
    return _sha1_salted(V1_IV_SALT, password, size)


def derive_key_v2(password: bytes, salt: bytes, iterations: int,
                  size: int = KEY_LEN) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, size)


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(data) % 16:
        raise ValueError("ciphertext is not a multiple of the AES block size")
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def pkcs7_unpad(data: bytes) -> bytes:
    """Strip PKCS#7 padding; raises ``ValueError`` on malformed padding.

    Mirrors OpenSSL's ``EVP_CipherFinal`` behaviour: a bad padding check is
    what makes a wrong password surface as error code 13.
    """
    if not data:
        raise ValueError("empty plaintext")
    pad = data[-1]
    if not 1 <= pad <= 16 or len(data) < pad:
        raise ValueError("bad PKCS#7 padding")
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS#7 padding")
    return data[:-pad]
