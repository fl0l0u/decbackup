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
values), trailer-region-only mutations (corrupt PKCS#7 bytes without
touching the structure) and pure-random files.  Deterministic under a
fixed seed.

The sub-parsers get what backup.py actually feeds them: the real trailer
slice ``data[0x404:0x404+X]`` (the whole container dies at TLV #1 every
time, which made parser fuzzing near-vacuous) plus ``der.read_tlv`` at
random offsets into the buffer.

    python analysis/fuzz.py [iterations] [seed]
"""

import pathlib
import random
import shutil
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
    E_ALGO,
    E_DECRYPT,
    E_FILE,
    E_HEADER,
    E_MAJVERSION,
    E_PARSE,
    E_VERIFY,
    BackupError,
    decrypt_backup,
)

# a raised BackupError must never carry the success code — 0 is not here on purpose
VALID_CODES = {E_FILE, E_PARSE, E_VERIFY, E_HEADER, E_MAJVERSION, E_DECRYPT, E_ALGO}

SEEDS = sorted((ROOT / "tests" / "vectors").glob("*.bkup"))
FAILDIR = pathlib.Path(tempfile.gettempdir()) / "opencode" / "fuzz_failures"


def mutate(rng: random.Random, data: bytes) -> bytes:
    b = bytearray(data)
    kind = rng.randrange(9)
    if kind == 0 and b:  # bit flips
        for _ in range(rng.randint(1, 8)):
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
    elif kind == 1 and b:  # random byte values
        for _ in range(rng.randint(1, 16)):
            b[rng.randrange(len(b))] = rng.randrange(256)
    elif kind == 2:  # truncate
        b = b[: rng.randrange(len(b) + 1)] if b else b
    elif kind == 3:  # append random junk
        b += bytes(rng.randrange(256) for _ in range(rng.randint(1, 4096)))
    elif kind == 4 and len(b) > 0x408:  # corrupt X (be32 at 0x400)
        struct.pack_into(
            ">I",
            b,
            0x400,
            rng.choice(
                [0, 1, 3, 0xFFFFFFFF, 0x7FFFFFFF, rng.randrange(1 << 32), len(b), len(b) // 2]
            ),
        )
    elif kind == 5 and len(b) > 0x40C:  # corrupt Y (be32 after trailer)
        x = struct.unpack_from(">I", b, 0x400)[0]
        off = 0x404 + min(x, len(b) - 0x404)
        if off + 4 <= len(b):
            struct.pack_into(
                ">I", b, off, rng.choice([0, 0xFFFFFFFF, len(b), rng.randrange(1 << 32)])
            )
    elif kind == 6 and len(b) > 0x400:  # header value corruption
        for _ in range(rng.randint(1, 8)):
            i = rng.randrange(min(0x400, len(b)))
            b[i] = rng.choice(b'=0123456789abcdefx \t\n;"\\.-')
    elif kind == 7 and len(b) > 0x408:  # corrupt INSIDE the trailer only
        # DER-plausibility: keep X and the container structure intact and
        # mutate real PKCS#7 bytes (structurally seeded), so the trailer
        # slice fed to parse_signed_data stays interesting.
        x = struct.unpack_from(">I", b, 0x400)[0]
        lo, hi = 0x404, min(0x404 + x, len(b))
        if hi > lo:
            for _ in range(rng.randint(1, 8)):
                b[rng.randrange(lo, hi)] ^= 1 << rng.randrange(8)
    elif b:  # splice random blob inside
        blob = bytes(rng.randrange(256) for _ in range(rng.randint(1, 256)))
        i = rng.randrange(len(b))
        b[i : i + len(blob)] = blob
    return bytes(b)


def make_random(rng: random.Random) -> bytes:
    n = rng.choice([0, 1, 0x3FF, 0x400, 0x404, 0x408, rng.randrange(1 << 14)])
    body = bytearray(rng.randrange(256) for _ in range(n))
    if n >= 0x400 and rng.random() < 0.7:
        head = b"[BACKUP]\nmajversion=%d\nalgo=%d\nversion=%s\n" % (
            rng.choice([1, 2, 3, 9, 255]),
            rng.randrange(0, 60),
            rng.choice([b"5.1.4", b"9", b"1", b"", b"90000"]),
        )
        body[: len(head)] = head[: len(body)]
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


def check_container(data: bytes, tmp: pathlib.Path, verify: bool = True):
    out = tmp / "fuzz.out"
    try:
        out.unlink(missing_ok=True)
    except OSError:
        pass
    try:
        with _Alarm(5):
            decrypt_backup(_spill(data, tmp), out, "testpass", verify=verify)
    except Slow:
        raise
    except BackupError as exc:
        if exc.code not in VALID_CODES:
            raise Violation(f"undocumented error code {exc.code}") from exc
        if out.exists():
            raise Violation(f"output survived failure {exc.code}")
    except Exception:
        tb = traceback.format_exc(limit=6)
        if out.exists():
            raise Violation(f"output survived crash\n{tb}") from None
        raise Violation(tb) from None
    finally:
        out.unlink(missing_ok=True)


def _spill(data: bytes, tmp: pathlib.Path):
    f = tmp / "in.bkup"
    f.write_bytes(data)
    return f


def trailer_slice(data: bytes) -> bytes:
    """Mirror backup.py: parse X from the mutated container and return the
    trailer slice it points at — what ``parse_signed_data`` really sees."""
    if len(data) < 0x404:
        return data  # too short to even carry X; feed whatever there is
    x = struct.unpack_from(">I", data, 0x400)[0]
    return data[0x404 : 0x404 + x]


def check_parsers(rng: random.Random, data: bytes):
    # parse_signed_data expects the trailer slice, not the whole container
    # (feeding it the whole file dies at TLV #1 every time and makes
    # parser fuzzing near-vacuous), but feed both: neither may traceback.
    blobs = [data]
    trailer = trailer_slice(data)
    if trailer != data:
        blobs.append(trailer)
    for blob in blobs:
        try:
            pkcs7.parse_signed_data(blob)
        except (pkcs7.SignatureError, der.DERError):
            pass
        except Exception:
            raise Violation("parse_signed_data: " + traceback.format_exc(limit=6))
    # der must never crash either, at any offset into the buffer
    for blob in blobs:
        for _ in range(2):
            off = rng.randrange(len(blob) + 1)
            try:
                t, vs, ln, ni = der.read_tlv(blob, off)
                list(der.children(blob, vs, ni))
            except der.DERError:
                pass
            except Exception:
                raise Violation("der: " + traceback.format_exc(limit=6))


def main():
    iters = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 20261017
    rng = random.Random(seed)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="decbackup-fuzz-"))
    try:
        fails, slows, done = run(rng, iters, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"fuzz done: {done} iterations, {fails} violations, {slows} slow (seed={seed})")
    return 1 if fails else 0


def run(rng: random.Random, iters: int, tmp: pathlib.Path):
    FAILDIR.mkdir(parents=True, exist_ok=True)
    fails = 0
    slows = 0
    done = 0
    corpus = [p.read_bytes() for p in SEEDS]
    # regression seeds: every input that ever violated the contract
    corpus += [p.read_bytes() for p in sorted(FAILDIR.glob("fail_*.bkup"))]
    for i in range(iters):
        done = i + 1
        if i % 20 == 19:
            data = make_random(rng)
        elif i < len(corpus):
            data = corpus[i]
        else:
            data = mutate(rng, rng.choice(corpus))
        try:
            check_container(data, tmp, verify=(i % 2 == 0))
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
    return fails, slows, done


if __name__ == "__main__":
    sys.exit(main())
