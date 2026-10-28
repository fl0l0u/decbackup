# Test vectors (`tests/vectors/`)

Backup containers (`.bkup`) and their expected plaintexts (`.tar`) for
`tests/test_decbackup.py`. Passwords are the test values below; no private
key material is in any file. Error-code meanings: 0 ok, 1 file, 6 parse,
7 verify, 8 header-too-short, 12 version gate, 13 decrypt, 32 algo
(see `RECON.md` §6).

Three provenance classes:

* **stock** — produced on the lab SNS 5.1.4 device with
  `encbackup -i <tar> -o <bkup> -t all -p <pass>`, exfiltrated by
  base64-over-ssh, sha256-checked on both ends, cross-validated against
  the real `decbackup` (RECON §9).
* **probe** — surgical single-region byte patches of a stock vector,
  applied *on the device* with `dd conv=notrunc` and run there first
  (`analysis/probes.py`); the local files are byte-identical to the
  device-side probes, so the device-observed codes apply.
* **clone-crafted** — byte-edited in memory against `test.bkup` (or its
  trailer) on this machine. Their *class* of edit is device-observed in
  some cases (noted per vector); the file itself was never on a device.

## Happy paths (stock)

| vector | payload | password | code |
|---|---|---|---|
| `test.bkup` | `test.tar` (2 KiB) | `testpass` | 0 |
| `nopass.bkup` | `t2.tar` (2 KiB) | (empty — `encbackup` without `-p`) | 0 |
| `big.bkup` | `big.tar` (5.7 KiB) | `BigPass789` | 0 |
| `mid.bkup` | `mid.tar` (23 KiB, exercises the original's 0x4000-byte chunk loop) | `MidPass321` | 0 |

## Device probes (patched, device-validated code)

Base for all of them is `test.bkup` unless noted. Edits keep byte length
and the trailer length `X` (be32 @ 0x400) intact unless stated — a
length-changing edit shifts the trailer and confounds the probe (RECON §7).

| vector | exact edit | password | code | observed detail |
|---|---|---|---|---|
| `trunc.bkup` | file truncated to 0x3FF (1023 B) | `testpass` | 8 | header-too-short |
| `xzero.bkup` | X zeroed: 2 bytes at 0x402–0x403 (`0x0E60` → `0x0000`) | `testpass` | 6 | `fwcrypto_upd_get_signature failed` |
| `ct.bkup` | 1 byte zeroed at 0x12c0 (ciphertext byte 4800) | `testpass` | 7 | `messageDigest mismatch` |
| `cert.bkup` | 8 bytes zeroed at 0x7d0 (inside the leaf cert DER, 0x404–0x946; breaks the leaf signature so chain building refuses the issuer step) | `testpass` | 7 | unable to get issuer certificate |
| `mv3.bkup` | 1 byte at 0x14: `majversion=2` → `majversion=3` | `testpass` | 12 | `Unknown backup majversion: 3` |
| `v9.bkup` | 5 bytes at 0x4b–0x50: `5.1.4` → `9····` (nine + four **spaces**) — padded, so the strict version-gate parse fails and falls back to the default (accept); the header edit then trips the digest | `testpass` | 7 | `messageDigest mismatch` |
| `yt.bkup` | 16 zero bytes **appended** | `testpass` | 13 | trailing garbage lands in the last CBC block → padding fails |
| `ys.bkup` | last 16 bytes **removed** | `testpass` | 13 | decryption is filesize-bounded, no separate Y error |
| `mvx.bkup` | 1 byte at 0x14: `majversion=2` → `majversion=x` — non-numeric parse-fails to the **v1 default**, wrong key | `testpass` | 13 | bad PKCS#7 padding |

`yt`/`ys` are the device evidence that the be32 **Y field is ignored**: the
stock vectors' Y values are exact (`filesize − 0x408 − X`, written by the
device), and after these length edits Y is stale (2064 vs 2080/2048) or,
for `xzero` (X=0 shifts Y's read position to 0x404), straight garbage
(813829724) — yet the codes stay exactly the same, on device and clone.

## Fuzz regression vectors (clone-crafted lineage: fuzz corpus)

Seeds from `analysis/fuzz.py`; pinned as vectors in commit *5577f27*
("Fail closed on lazily-parsed certificate fields"). `cryptography`
parses certificate fields lazily, so these load fine and explode only on
field access — both must fail closed into 7, never a traceback. Neither
was ever run on a device; the fail-closed code parity is with the
device's cert-tamper behavior (`cert.bkup`).

| vector | lineage / exact edits (file offsets, vs `test.bkup` unless noted) | password | code |
|---|---|---|---|
| `extdup.bkup` | **derived from `cert.bkup`** — embeds its 8-zeroed-bytes-at-0x7d0 tamper, PLUS: 1 byte at 0x69f and 8 bytes at 0x745–0x74d (leaf certificate extensions region; the net effect is the leaf carrying **keyUsage 2.5.29.15 twice** → `DuplicateExtension`, a bare-`Exception` subclass, on `.extensions`), PLUS 1 byte at 0x1083 (SignerInfo region) | `testpass` | 7 |
| `lazyparse.bkup` | direct mutation of `test.bkup`: 26 bytes at 0x4d7–0x4f1 replaced with random data (inside the leaf certificate's **issuer Name**) → unparsable under lazy access | `testpass` | 7 |

## v1 KDF probes (rebuilt clone-side, device-validated)

No released SNS `encbackup` emits majversion 1, so these were **built
locally and re-validated on both lab VMs (4.2.8 and 5.1.4)** — codes 7
and 13 reproduced byte-for-byte (commit *f7abdc4*; matrix in RECON §10).
Construction: `test.bkup` header with the same-length `majversion=2→1`
edit at 0x14, **trailer copied unchanged** (still a valid signature over
the *original* content), and the ciphertext region (0x1268 onward)
re-encrypted under each candidate v1 KDF. The confirmed v1 KDF:
`key = SHA1(2807a5ef00620c4b62f32e0985e30e4e ‖ password)[:16]`
(shared 48-byte pool +16), `iv = SHA1(463538798d48c8c0323df3e75109d221 ‖
password)[:16]` (pool +0).

| vector | ciphertext made with | password | code | observed detail |
|---|---|---|---|---|
| `v1probe.bkup` | the correct pool+16 key | `testpass` | 7 | decrypts cleanly, copied trailer's digest covers the old content → `messageDigest mismatch` |
| `v1badkey.bkup` | the off-by-one shifted key `212807a5…` | `testpass` | 13 | `bad PKCS#7 padding` |

## Clone-crafted hardening vectors (byte-edited here, clone-only)

Pinned by the test-suite hardening pass. **No device validated these
files**; expected codes are the clone's agreed contract (some are
deliberate clone deviations from the device, noted below). All are
single-region edits of `test.bkup` with password `testpass`; header-text
edits stay inside the NUL-padded 0x400 block so the trailer never shifts.

| vector | exact edit | code | observed detail | notes |
|---|---|---|---|---|
| `xbig.bkup` | X @ 0x400 set to `0xFFFFFFFF` | 6 | `fwcrypto_upd_get_signature failed` | trailer can never fit the first 0x4000-byte chunk; same fail-closed class as the device-validated `xzero`/sed-shift probes |
| `algo2.bkup` | header digit at 0x1b: `algo=1` → `algo=2` (version left valid — the version gate runs **before** the algo check, RECON §6) | 32 | `unsupported algo (2)` | the algo=2 → 32 mapping is device-observed (`analysis/probes.py`, device-only list); this file is not that probe |
| `v9s.bkup` | `version=5.1.4` → `version=9` (strict, **no** padding spaces) | 12 | `Invalid archive` | the strict counterpart of `v9.bkup` (padded → parse-fails → accepted → 7); device matrix observed strict `9` → 12 |
| `itovf.bkup` | `pbkdf_iterations=10000` → `pbkdf_iterations=99999999999` (≥ 2³¹) | 6 | `pbkdf_iterations too large` | **clone deviation**: the device trusts the header and stalls in a 10¹¹-round PBKDF2 (shared DoS, RECON §8); the clone rejects at parse time instead. Tested via the CLI with a 30 s timeout so an unfixed implementation cannot wedge the suite |
| `ivlen.bkup` | `iv=` hex truncated to `79275efe2f464856` — **valid hex, 8 bytes** instead of 16 | 6 | `bad iv: expected 16 bytes, got 8` | clone fail-closed at parse (device would only surface a late EVP-level failure; unprobed) |
| `sig2bad.bkup` | trailer surgery on `test.bkup`: the single `SignerInfo` is **duplicated** into the `signerInfos` SET with the **last byte of the copy's signature flipped**; the four ancestor DER length fields are bumped (encoded widths preserved), X grows 3680 → 4249, Y kept consistent (plaintext length unchanged), ciphertext untouched | 7 | `signature verification failed` | pins "EVERY signerInfo is verified": the first signer alone verifies and chains cleanly — pre-hardening builds decrypted this to exit 0 |

Run `python tests/test_decbackup.py` (from the repo root) to exercise
every vector with its expected code; failure vectors additionally assert
that no output file survives.
