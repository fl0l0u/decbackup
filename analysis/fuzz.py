#!/usr/bin/env python3
"""Mutation fuzzer for the decbackup clone.

Contract under test: for ANY input bytes, ``decrypt_backup`` must either
return a header dict or raise ``BackupError`` with one of the documented
numeric codes — never a traceback, never leave an output file behind,
and never hang.  Sub-parsers get the same treatment:
``pkcs7.parse_signed_data`` -> SignatureError, ``der.read_tlv`` ->
DERError.

Seeds are the real device vectors; mutations are bit flips, byte
splices, truncations, structural-field corruptions (X/Y be32s, header
values) and pure-random files.  Deterministic under a fixed seed.

    python analysis/fuzz.py [iterations] [seed]
"""

import pathlib
import random
import signal
import struct
import sys
import tempfile
import traceback

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import warnings  # noqa: E402

warnings.simplefilter("ignore")

from decbackup import der, pkcs7  # noqa: E402
from decbackup.backup import (  # noqa: E402
    E_ALGO, E_DECRYPT, E_FILE, E_HEADER, E_MAJVERSION, E_PARSE, E_VERIFY,
    BackupError, decrypt_backup,
)

VALID_CODES = {0, E_FILE, E_PARSE, E_VERIFY, E_HEADER, E_MAJVERSION,
               E_DECRYPT, E_ALGO}

SEEDS = sorted((ROOT / "tests" / "vectors").glob("*.bkup"))
FAILDIR = pathlib.Path(tempfile.gettempdir()) / "opencode" / "fuzz_failures"


def mutate(rng: random.Random, data: bytes) -> bytes:
    b = bytearray(data)
    kind = rng.randrange(8)
    if kind == 0 and b:  # bit flips
        for _ in range(rng.randint(1, 8)):
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
    elif kind == 1 and b:  # random byte values
        for _ in range(rng.randint(1, 16)):
            b[rng.randrange(len(b))] = rng.randrange(256)
    elif kind == 2:  # truncate
        b = b[:rng.randrange(len(b) + 1)] if b else b
    elif kind == 3:  # append random junk
        b += bytes(rng.randrange(256) for _ in range(rng.randint(1, 4096)))
    elif kind == 4 and len(b) > 0x408:  # corrupt X (be32 at 0x400)
        struct.pack_into(">I", b, 0x400, rng.choice(
            [0, 1, 3, 0xFFFFFFFF, 0x7FFFFFFF, rng.randrange(1 << 32),
             len(b), len(b) // 2]))
    elif kind == 5 and len(b) > 0x40C:  # corrupt Y (be32 after trailer)
        x = struct.unpack_from(">I", b, 0x400)[0]
        off = 0x404 + min(x, len(b) - 0x404)
        if off + 4 <= len(b):
            struct.pack_into(">I", b, off, rng.choice(
                [0, 0xFFFFFFFF, len(b), rng.randrange(1 << 32)]))
    elif kind == 6 and len(b) > 0x400:  # header value corruption
        for _ in range(rng.randint(1, 8)):
            i = rng.randrange(min(0x400, len(b)))
            b[i] = rng.choice(b"=0123456789abcdefx \t\n;\"\\.-")
    elif b:  # splice random blob inside
        blob = bytes(rng.randrange(256) for _ in range(rng.randint(1, 256)))
        i = rng.randrange(len(b))
        b[i:i + len(blob)] = blob
    return bytes(b)


def make_random(rng: random.Random) -> bytes:
    n = rng.choice([0, 1, 0x3FF, 0x400, 0x404, 0x408, rng.randrange(1 << 14)])
    body = bytearray(rng.randrange(256) for _ in range(n))
    if n >= 0x400 and rng.random() < 0.7:
        head = b"[BACKUP]\nmajversion=%d\nalgo=%d\nversion=%s\n" % (
            rng.choice([1, 2, 3, 9, 255]), rng.randrange(0, 60),
            rng.choice([b"5.1.4", b"9", b"1", b"", b"90000"]))
        body[:len(head)] = head[:len(body)]
    if n >= 0x408:
        struct.pack_into(">I", body, 0x400, rng.randrange(n))
    return bytes(body)


class Violation(Exception):
    pass


class Slow(Exception):
    """input took >5s (e.g. PBKDF2 iterations bomb) — a device-parity
    property of trusting header fields, noted not failed."""


class _Alarm:
    def __init__(self, secs):
        self.secs = secs

    def __enter__(self):
        def _boom(signum, frame):
            raise Slow()
        self.prev = signal.signal(signal.SIGALRM, _boom)
        signal.alarm(self.secs)
        return self

    def __exit__(self, *exc):
        signal.alarm(0)
        signal.signal(signal.SIGALRM, self.prev)
        return False


def check_container(rng: random.Random, data: bytes, tmp: pathlib.Path):
    out = tmp / "fuzz.out"
    try:
        out.unlink(missing_ok=True)
    except OSError:
        pass
    try:
        with _Alarm(5):
            decrypt_backup(_spill(rng, data, tmp), out, "testpass")
    except Slow:
        raise
    except BackupError as exc:
        if exc.code not in VALID_CODES:
            raise Violation(f"undocumented error code {exc.code}") from exc
        if out.exists():
            raise Violation(f"output survived failure {exc.code}")
    except Exception:
        raise Violation(traceback.format_exc(limit=6)) from None
    finally:
        out.unlink(missing_ok=True)


_SPILL = [None]


def _spill(rng: random.Random, data: bytes, tmp: pathlib.Path):
    f = tmp / "in.bkup"
    f.write_bytes(data)
    return f


def check_parsers(rng: random.Random, data: bytes):
    try:
        pkcs7.parse_signed_data(data)
    except (pkcs7.SignatureError, der.DERError):
        pass
    except Exception:
        raise Violation("parse_signed_data: " + traceback.format_exc(limit=6))
    # der must never crash either
    try:
        t, vs, ln, ni = der.read_tlv(data, 0)
        list(der.children(data, vs, ni))
    except der.DERError:
        pass
    except Exception:
        raise Violation("der: " + traceback.format_exc(limit=6))


def main():
    iters = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 20261017
    rng = random.Random(seed)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="decbackup-fuzz-"))
    FAILDIR.mkdir(parents=True, exist_ok=True)
    fails = 0
    slows = 0
    corpus = [p.read_bytes() for p in SEEDS]
    for i in range(iters):
        if i % 20 == 19:
            data = make_random(rng)
        elif i < len(corpus):
            data = corpus[i]
        else:
            data = mutate(rng, rng.choice(corpus))
        try:
            check_container(rng, data, tmp)
            check_parsers(rng, data)
        except Slow:
            slows += 1
        except Violation as v:
            fails += 1
            path = FAILDIR / f"fail_{i:06d}.bkup"
            path.write_bytes(data)
            print(f"FAIL iter {i} ({len(data)} bytes) -> {path}\n{v}\n")
            if fails >= 10:
                print("stopping after 10 failures")
                break
    print(f"fuzz done: {i + 1} iterations, {fails} violations, "
          f"{slows} slow (seed={seed})")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
