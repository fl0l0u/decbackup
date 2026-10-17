<h1 align="center">
  <br>
  decbackup
  <br>
</h1>

<h4 align="center">Python clone of Stormshield SNS's backup decryption utility, built from a full reverse-engineering of decbackup + libncrypto.so</h4>

<p align="center">
  <a href="https://pypi.org/project/decbackup/">
    <img src="https://img.shields.io/pypi/v/decbackup?style=flat-square" alt="PyPI">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License">
  </a>
  <img src="https://img.shields.io/badge/platform-any-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/python-3.9%2B-yellow?style=flat-square" alt="Python">
  <a href="https://github.com/fl0l0u/decbackup/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/fl0l0u/decbackup/ci.yml?style=flat-square&label=CI" alt="CI">
  </a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#the-format">The Format</a> •
  <a href="#development">Development</a> •
  <a href="#license">License</a>
</p>

---

**decbackup** decrypts and verifies Stormshield Network Security (SNS)
backup files (`.bkup`) — no appliance required. It is a faithful Python
reimplementation of `/usr/Firewall/sbin/decbackup` and the backup container
code of `libncrypto.so`, derived from SNS **v5.1.4** by static analysis
plus an empirical error-code matrix against a live device (see
[RECON.md](RECON.md)).

## Features

| Feature | Description |
|---------|-------------|
| **Byte-exact format support** | `[BACKUP]` header, detached PKCS#7 trailer, AES-128-CBC payload |
| **Both password schemes** | v2 (PBKDF2-HMAC-SHA256) and legacy v1 (salted-SHA1) key derivation |
| **Full signature verification** | RSA over PKCS#7 authAttrs, messageDigest over header+payload, chain to the four CAs embedded in libncrypto, policy 1.3.6.1.4.1.11256.2.3, dates ignored (as on the device) |
| **Original CLI parity** | same flags (`-i -o -p -P -d`), same messages, same numeric error codes (0/1/6/7/8/12/13/32) — validated against the real binary on device |
| **Tiny dependency set** | `cryptography` only; DER/PKCS#7 parsing is in-tree (`decbackup/der.py`, `pkcs7.py`) |

## Installation

```bash
pip install decbackup
```

Or from a checkout:

```bash
pip install .
```

The wheel bundles everything needed at runtime: the package code, the
four CA certificates extracted from `libncrypto.so` (`decbackup/certs/`),
and a `decbackup` console script. The only dependency is
`cryptography`.

## Usage

```
Usage : () -i <backup> -o <output archive>
                    [-p <password>] [-d : dump backup header]
                    [-P : prompt for password]
```

```bash
decbackup -i firewall.bkup -o archive.tar -p 's3cret'
tar tf archive.tar
```

Success is silent (exit 0), exactly like the original; failure prints
`decrypt and/or verify backup failed (%d)` with the appliance's own error
code. `-d` prints the decoded header block after a successful run.

Library use:

```python
from decbackup import decrypt_backup, BackupError
try:
    header = decrypt_backup("firewall.bkup", "archive.tar", "s3cret")
    print(header["model"], header["date"])
except BackupError as e:
    print("failed:", e.code)
```

## The Format

```
0x000   0x400   [BACKUP] key=value header, NUL-terminated, zero-padded
0x400   4       be32 X — PKCS#7 trailer length
0x404   X       detached PKCS#7 SignedData (device cert + CA intermediate)
0x404+X 4       be32 Y — payload length
0x408+X Y       AES-128-CBC ciphertext (PBKDF2-SHA256 key, PKCS#7 padding)
```

The signature covers the **full 0x400-byte header block plus the decrypted
payload**; it chains device cert → *Stormshield Network Security Products
CA* → *Stormshield Products Root CA* (embedded). Expired device
certificates still verify — the appliance ignores dates, so backups stay
readable forever. Full details in [RECON.md](RECON.md).

## Development

```
decbackup/        the package (cli, backup format, crypto, pkcs7, der, trust, certs/)
analysis/         RE tooling: disassembler, strings, symbol lists, the device
                  extraction script and the empirical error-code matrix
tests/vectors/    real encbackup-produced backups + expected payloads
                  (created on an SNS 5.1.4 device, cross-validated against
                  the stock decbackup)
legacy/           the earlier single-file iteration (kept for reference)
```

```bash
python tests/test_decbackup.py        # exit code = number of failures
python analysis/probes.py             # real-vs-clone error-code parity table
```

## Releasing

Tagged pushes (`v*`) build an sdist + wheel, smoke-test the wheel against
the bundled device vectors, and publish to PyPI via trusted publishing
(see `.github/workflows/release.yml`). Pushes and PRs run lint + the
error-code parity suite on Python 3.9–3.13
(`.github/workflows/ci.yml`).

```bash
git tag v0.1.0 && git push origin v0.1.0   # → PyPI
```

## License

MIT — see [LICENSE](LICENSE).

*Stormshield* is a trademark of Stormshield. This project is unaffiliated
with Stormshield; it exists so that backups you own remain readable.
