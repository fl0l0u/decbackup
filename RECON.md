# decbackup / Stormshield SNS backup Reverse-Engineering Recon

Target: `/usr/Firewall/sbin/decbackup` + `libncrypto.so` from **Stormshield
Network Security v5.1.4** (SNS-BSD 5.1.4, EVA1 XL-VM). All addresses below
are file offsets in the extracted binaries (`bin/` on the VM, mirrored under
`analysis/` tooling paths).

## 1. Environment & extraction workflow

* SNS **v5.1.4** lab VM; admin shell is a **restricted csh whitelist**:
  no `cat`, `od`, `printf`, `for`, no `2>` redirection (csh: `2>&1` =
  "Ambiguous output redirect"). `ls`, `stat`, `sed`, `dd`, `bsdtar`,
  `openssl`, `md5`, `encbackup`, `decbackup` *are* available.
* SCP/SFTP is blocked. Files exfiltrate via
  `ssh admin@vm 'openssl base64 -in /path/file' | base64 -d`
  (`analysis/extract.sh`). Integrity confirmed with `md5` on both ends.
* Analysis tooling: `analysis/disasm.py` (capstone + pyelftools function
  disassembler with PLT-resolved call targets and string annotations),
  `analysis/strings.py`, `analysis/symbols.py`.

### Binaries that matter

| file | role |
|---|---|
| `sbin/decbackup` | CLI front-end: getopt, password handling, `-d` dump |
| `sbin/encbackup` | creates backups (`-i archive -o bkup -t all -p pass`) |
| `sbin/backuprestore`, `sbin/backupinfo` | other consumers of the format |
| `lib/libncrypto.so` | the whole format: `fwcrypto_upd_*`, KDF, PKCS#7 |
| `lib/libnbase.so` | section/key-value parser (`str_get_int_ex` etc.) |

## 2. Container format (CONFIRMED, byte-exact)

```
offset        size     contents
0x000         0x400    [BACKUP] header: key=value lines, NUL-terminated,
                       zero-padded to 1 KiB
0x400         4        be32 X — length of the PKCS#7 trailer
0x404         X        detached PKCS#7 SignedData (signature + certs)
0x404+X       4        be32 Y — plaintext length (== filesize - 0x408 - X)
0x408+X       Y        AES-128-CBC ciphertext, PKCS#7 padding
```

Header keys seen: `majversion=2`, `algo=1`, `date="…"`, `model`, `version`,
`serial`, `advanced`, `description`, `content`, `iv` (hex), `salt` (hex),
`pbkdf_iterations=10000`, `type=PASSWORD`, `validated`, `IPv6State`.
Values may be double-quoted; the text block ends at the first NUL.

Parsing path: `fwcrypto_upd_update` (libncrypto 0x12860, flags=2 backup
path). The file is read in **0x4000-byte chunks**; the signature trailer
must fit inside the first chunk (`X + 0x404 >= chunk_len → error 6`,
`fwcrypto_upd_get_signature failed`) — a fail-closed design, so whole-file
processing is behaviourally equivalent.

**Quirk (not reproduced):** if the filesize is an exact multiple of
0x4000, the streaming loop's EOF detection hits the zero-length-read path
and the tool fails. A bug; the clone simply reads the whole file.

## 3. Key derivation (CONFIRMED v2 and v1)

Selected by header `majversion` (`fwcrypto_get_backup_majversion`,
default 1 when the key is absent; 1 or 2 accepted, anything else → error 12
`Unknown backup majversion`).

* **v2** (`fwcrypto_derivekey`): `key = PBKDF2-HMAC-SHA256(password,
  unhex(salt), pbkdf_iterations, 16)`; `iv = unhex(iv)`.
* **v1**: `key = SHA1(2807a5ef00620c4b62f32e0985e30e4e || password)[:16]`,
  `iv = SHA1(463538798d48c8c0323df3e75109d221 || password)[:16]`. The two
  salts are consecutive 16-byte windows of one 48-byte pool
  (`463538798d…09d221` + `2807a5ef00…0e4e`); the getters' `lea` targets
  resolve to pool+0 and pool+16 in *both* the 5.1.4 and 4.2.8 binaries.
  An earlier reading (`212807a5…` / `0046353879…`) was a one-byte
  vaddr→file-offset slip, corrected in §10 by direct experiment.
  For sizes >20 the fill is
  `buf[i] = (size-1 + (size-i)*0xEB) & 0xFF` — unreachable for AES-128.
  5.1.4 `encbackup` cannot emit v1 (no version flag in getopt
  `i:o:p:c:t:n:P`), but the **key derivation is now empirically confirmed**
  (§10): a v1-header archive whose ciphertext was made with these
  constants decrypts cleanly on both VMs (reaches the digest check → 7),
  while the shifted-salt variant fails at padding (→ 13) on both.

Cipher: `algo=1` → AES-128-CBC (`EVP_aes_128_cbc`); anything else → error
32 `unsupported algo`.

## 4. Signature scheme (CONFIRMED end-to-end)

Detached PKCS#7 SignedData (OpenSSL 3 `PKCS7_*` via
`VerifyMajSignatureInit` 0x14a5x / `VerifySignatureFinal`):

* **Signed content** = full 0x400-byte header block (text + NUL padding —
  implemented as `strlen` + zero-pad loop) **followed by the decrypted
  payload**. Proven: `messageDigest` attribute ==
  `sha256(header_block + plaintext)` on every vector.
* The trailer's SignedData quirks:
  * certificates sit under `[0]` as bare `SEQUENCE` TLVs (no SET wrapper);
  * `signerInfos` is a plain `0x31` SET;
  * authenticatedAttributes are stored bare under the `[0]` tag — the
    signed DER is the tag-swapped form `0x31 + DER-length + value`
    (Stormshield's encoder omits the SET, so the length must be re-encoded;
    for the 105-byte value the short form `0x69` matches byte-exactly);
  * signature AlgorithmIdentifier is `rsaEncryption` (1.2.840.113549.1.1.1,
    hash from digestAlgorithm = sha256) — classic PKCS#7 DigestInfo.
* Attributes: contentType (1.9.3) = pkcs7-data, signingTime (1.9.5),
  messageDigest (1.9.4).
* Signer: device certificate (leaf carries certificatePolicies
  **1.3.6.1.4.1.11256.2.3**), SID = issuerAndSerialNumber.

### Trust store (`fw_libcrypto_get_trust_store`, backup type)

Four CA certs hard-coded in libncrypto .rodata, extracted to
`decbackup/certs/`:

| .rodata off | size | subject |
|---|---|---|
| 0x8890 | 0x6b0 | Stormshield Network Security Enrollment Products CA |
| 0x6b40 | 0x418 | NETASQ Firewall Certification Authority |
| 0x8f40 | 0x601 | Stormshield Products Root CA |
| 0x6f60 | 0x606 | Stormshield Product and Services Root CA |

Verify parameters: `X509_V_FLAG_NO_CHECK_TIME` (expired device certs still
verify — backups stay readable forever), explicit policy
1.3.6.1.4.1.11256.2.3. The callback `fwcrypto_verify_any_nodate_callback`
(0x11150) accepts errors {0, 9, 10} and 43 when
`fw_libcrypto_is_netasq_issued` (issuer DER memcmp vs the NETASQ root).
Net effect: signature-valid chain from leaf to an embedded root, dates
ignored. Chain in vectors: device ← Stormshield Network Security Products
CA (in the trailer) ← Stormshield Products Root CA (embedded).

## 5. CLI grammar (`decbackup` main)

getopt string `Pi:p:o:d`; usage (stderr, exit 1 when missing args/options):

```
Usage : () -i <backup> -o <output archive>
                    [-p <password>] [-d : dump backup header]
                    [-P : prompt for password]
```

(The empty parens are faithful: both `%s` args point at an empty string.)

* `-p` more than once → `-p can only be specified once`, exit 1.
* Password selection: `-p x` → x; `-P` → `t_getpass` prompt
  `Enter backup password (<Enter> for none): ` which reads **/dev/tty**
  (piped stdin is ignored: `-P` over a pipe with no tty → empty password →
  13); no `-p`/`-P` on a tty → same prompt; otherwise empty password.
* `-d` → on success prints `Header :\n<text up to NUL>\n`. Success is
  otherwise silent (exit 0); failure prints
  `decrypt and/or verify backup failed (%d)` (stderr) and exits 1.
* Output file is created early (`fopen wb`) and **removed on every error
  path**.

## 6. Error codes (empirical matrix, real device vs clone — parity)

| code | meaning | proven by |
|---|---|---|
| 0 | success | all vectors |
| 1 | input/output open failure | code path |
| 6 | signature trailer unparsable / doesn't fit first chunk; crypto params missing | X=0 → 6; sed-shifted files → 6 |
| 7 | verification failed (content digest, attribute signature, chain) | 1-byte ciphertext tamper → 7; cert bytes zeroed → 7; header edit → 7 |
| 8 | file shorter than 0x400 | trunc.bkup → 8 |
| 11 | short write to the output file (residual default err; seen when `-o /dev/stdout` truncates the stream) | 4.2.8 binary, v1 probe to /dev/stdout |
| 12 | unknown majversion (`Unknown backup majversion: %d`) or version gate (`Invalid archive`) | majversion=3 → 12; version=9 → 12 |
| 13 | decrypt failed — in practice wrong password (EVP_CipherFinal padding) | wrongpass → 13 |
| 32 | unsupported algo | algo=2 → 32 |

**Verification is enforced**: an early "tampering is accepted" conclusion
was an artifact of csh mangling `dd … 2>/dev/null` (all those tamper
commands were silent no-ops). With surgical `dd conv=notrunc` patches the
tool fails closed on every corrupted byte in the ciphertext, signature,
attributes, or certificate regions.

### The version gate (`fwcrypto_maj_get_version`, 0x11820)

`cmp ax,1 → error 12 ("Invalid archive")` at 0x13194 on the flags&2 backup
path. Observations (all same-length edits, X intact unless noted):

| header `version` | real code | interpretation |
|---|---|---|
| `5.1.4` (real) | pass | parse fails → default 1 |
| `1` | pass | parses to 1 |
| `9` (−4 shift) | 12 | parses to 9 → gate **before** the X check |
| `9    ` (padded) | 7 | trailing spaces → parse fails → default |
| `10000`/`90000` | 7 | 5-digit values → parse fails → default |
| `abcde`, `2.0.0` | 7 | parse fails → default |

Empirical rule implemented: value **parses** only when it is leading
whitespace + 1–4 digits + end (strict, no trailing chars); a parsed value
≠ 1 → error 12. The digit-count cap (why 5-digit strings fail) is inferred,
not read off `str_get_int_ex` conclusively — the 4-vs-3 boundary is
untested. Real backups always carry dotted versions → always pass.

## 7. Methodology gotchas (for future probes)

1. **csh eats `2>/dev/null`** — `dd`/redirects with `2>` become silent
   no-ops ("Unknown operand"). Tamper commands *must* omit it.
2. **sed edits change file length** → everything after the header shifts →
   the X field at 0x400 reads garbage → you measure the X check, not the
   thing you probed. Only same-length substitutions, or patch with
   `dd conv=notrunc`.
3. `cmp` is not whitelisted; csh reports command-not-found as exit 1,
   which looks exactly like "files differ". Use `openssl dgst -sha256`.
4. Probe files: byte-identical local/VM copies verified by sha256
   (see `analysis/probes.py`) so device-observed codes apply to the vectors.

## 8. Open items / uncertainties

* v1 KDF **empirically confirmed** on both VMs (§10). The IV window is
  static-confirmed (identical `lea`-pool layout in both binaries) but
  RC-invisible in probes (CBC padding ignores the IV and the digest can
  never match a copied trailer); it is the pool[0:16] window.
* Exact digit-count cap of the version gate parser (implemented ≤4).
* Error code when the *output* file can't be created: assumed 1.
* `pbkdf_iterations` default when the key is missing: assumed 1
  (`mov esi, 1` near the getter); real files always carry the key.

## 9. Test vectors (`tests/vectors/`)

Made with `encbackup -i <tar> -o <bkup> -t all -p <pass>` on the device,
fetched by base64-over-ssh, and cross-validated against the real
`decbackup` output. Error vectors are byte-identical to the device-side
probe files (sha256 listed in `analysis/probes.py` history).

Privacy note: the vectors are real device output and cannot be edited
without breaking the signature they exercise, so they carry the lab
device's certificate (public by design) and the default evaluation-VM
serial; the payload tars are synthetic and the passwords are the test
values shown below. No private key material is present in any vector.

| vector | payload | password | code |
|---|---|---|---|
| test.bkup | test.tar (2 KiB) | `testpass` | 0 |
| nopass.bkup | t2.tar | (empty) | 0 |
| big.bkup | big.tar | `BigPass789` | 0 |
| mid.bkup | mid.tar (23 KiB, multi-chunk) | `MidPass321` | 0 |
| trunc/xzero/ct/cert/mv3/v9 | — | `testpass` | 8/6/7/7/12/7 |
| v1probe.bkup / v1badkey.bkup | test.tar (§10, v1-encrypted) | `testpass` | 7 / 13 |

## 10. Second VM: SNS v4.2.8

Older box, same EVA1-VM hardware line, the same default evaluation-VM
serial as the 5.1.4 box, clock
pinned to 2020. All four binaries differ from 5.1.4
(`decbackup fca8df91…`, `libncrypto.so ddca97b1…`). Its `decbackup` usage
string lacks the `-P` line; `encbackup` still writes **majversion=2**
(PBKDF2, 10000 iterations) with the identical container layout — so no
release in this VM line emits v1.

* **Cross-version compatibility (CONFIRMED)**: the clone decrypts a
  v4.2.8-produced backup byte-exactly, and the v4.2.8 device `decbackup`
  reproduces the same sha256. Same PKI chain as 5.1.4
  (device ← Products CA ← Products Root CA).
* **v1 path present and identical in structure**: `upd_update` (flags&2)
  → `fwcrypto_get_backup_majversion` → `==1` branch calls
  `fwcrypto_keyfrompasswd(pass, 0x10)` + `fwcrypto_ivfrompasswd(pass, 0x10)`
  (0xd692/0xd6ac), then the same streaming decrypt + `VerifySignatureFinal`
  tail — v1 archives are signed containers too, and VSI failure is still
  fail-closed (error 6). The version gate (`cmp ax,1` → 12) is the same.
* **v1 salt windows**: both binaries read the *same* windows of the shared
  48-byte pool (key = pool+16, iv = pool+0). Resolved by `lea`
  instruction-by-instruction in both (`sns` 0x16d8d→file 0x1b420,
  0x16ac4→0x1b410; `sns428` 0x10d98→0x18030, 0x10aaf→0x18020), and
  confirmed empirically with the probe matrix below.
* **v1 KDF probe matrix** (v1 header via same-length `majversion=2→1`
  edit of a real v4.2.8 backup, copied valid trailer, content re-encrypted
  under each salt×iv combination; padding validity is the key oracle, CBC
  IV cannot affect it):

  | ciphertext made with | old-VM (4.2.8) | 5.1.4 VM |
  |---|---|---|
  | pool+16 key (correct) | 7 (both IVs) | 7 |
  | shifted key `212807a5…` | 13 | 13 |

  `7` = decryption succeeded, digest check failed (expected: the trailer's
  messageDigest covers the original v2 content). This proves the key
  window on both binaries; the IV window follows from the identical
  `lea`-pool layout (RC-invisible by construction).
* **4.2.8 embedded trust blobs** (libncrypto .data, six certs): the two
  5.1.4 roots + Enrollment Products CA, **no NETASQ root**, plus three
  service certs for the update path (`firmware.sns.local`,
  `update.sns.local`, `signvmkit.sns.local`, issued by "Stormshield
  Network Security CA"). The NETASQ-issuer special case in the verify
  callback therefore postdates 4.2.8. 4.2.8 also exposes older API
  surface (`fwcrypto_dec_maj_file`, `fwcrypto_check_maj`,
  `fwcrypto_backup_read_algo`, 3DES/Blowfish/DES helpers).
* **Error 11** appears on the old binary: the stream loop sets
  `[err]=11` as the default before each output `fwrite` and a failing
  `EVP_CipherFinal`/short-write path leaves it in place. Observed when
  pointing `-o` at `/dev/stdout` (pipe semantics + `remove()` of the
  symlink); a regular output file behaves as on 5.1.4.
* **Ingestion channel** (SCP blocked, echo-chunks proved lossy — csh
  `echo` corrupted some base64 payloads at identical length): pipe bytes
  straight through ssh stdin into `dd of=/tmp/x bs=<len> count=1`, then
  `openssl base64 -A -d -in /tmp/x -out /tmp/y`. The `-A` flag is
  required on this box's OpenSSL 1.1.1k for single-line payloads;
  verify with `md5` on both ends.
