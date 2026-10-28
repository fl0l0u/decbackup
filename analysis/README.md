# `analysis/` — reverse-engineering tooling

Helper scripts used to produce [../RECON.md](../RECON.md). The target
binaries (`decbackup`, `encbackup`, `libncrypto.so`, …) are **not in
this repo** — pull your own copies off a lab VM with `extract.sh`. All
addresses in RECON.md are file offsets into those extracted artifacts.

```bash
pip install capstone pyelftools   # for disasm.py and symbols.py
```

`sshpass` is a **system** package (`apt install sshpass`), not a pip one.
`strings.py` and `probes.py` need only the standard library plus this
checkout.

## extract.sh — pull files off the device

SCP/SFTP is blocked on SNS and the admin shell is a restricted csh
whitelist without `cat`/`od`, so the exfil channel is OpenSSL's base64
filter over ssh stdout:

```bash
VM=admin@192.168.1.99 SSHPASS='...' ./analysis/extract.sh \
    /usr/Firewall/sbin/decbackup out/decbackup
```

`VM` and `SSHPASS` are required env vars (`sshpass -e` reads the
password from the environment), and the remote path must be absolute.
Caveat: the script passes `StrictHostKeyChecking=no -o
UserKnownHostsFile=/dev/null` — it accepts any host key, so it is for an
isolated lab VM you control, never a routable host. The script prints
the local md5 at the end; compare it against `md5 <path>` on the device
(`md5` is whitelisted there, `ls -l` gives sizes).

## disasm.py — function disassembler

capstone + pyelftools; resolves PLT/`jmp [rip+…]` call targets to symbol
names and annotates RIP-relative `lea` string references:

```bash
python analysis/disasm.py out/libncrypto.so fwcrypto_upd_update
python analysis/disasm.py out/decbackup --all
```

## strings.py — strings with file offsets

```bash
python analysis/strings.py out/libncrypto.so 6
```

Prints `offset "string"` for printable runs (min length 4 by default) —
offsets are file offsets, which is what RECON.md cites.

## symbols.py — relevant symbol names

Dumps `.dynsym` function symbols matching crypto/backup/fwcrypto:

```bash
python analysis/symbols.py out/libncrypto.so
```

## probes.py — static error-code parity table

Renders the RECON.md §6 matrix and runs the **clone** half locally — no
device needed; the `real` column holds codes recorded on the device.
`python analysis/probes.py` exits non-zero on any clone/device mismatch
of the covered vectors. The maintained parity check is
`tests/test_decbackup.py` (run in CI).

## fuzz.py — robustness contract fuzzer

```bash
python analysis/fuzz.py 30000        # 30k iterations, default seed
python analysis/fuzz.py 30000 1234   # reproducible run
```

Contract: any input → documented `BackupError` code, no traceback, no
surviving output file, no hang. Crash inputs accumulate in
`$TMPDIR/opencode/fuzz_failures/` (in practice `/tmp/opencode/…`) as
regression seeds — that directory is machine-local and volatile (lost on
reboot, not versioned); the durable pinned regressions are the
`extdup.bkup` / `lazyparse.bkup` vectors in `tests/vectors/`.
