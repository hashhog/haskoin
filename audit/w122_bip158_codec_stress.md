# W122 BIP-158 GCS codec stress-vector audit — haskoin

**Date:** 2026-05-17
**Status:** VERIFIED CLEAN POST-FIX-69 — no new bugs found
**Scope:** Adjacent-boundary stress vectors beyond FIX-69's four q>=64 tests
**Result:** 15/15 new W122 stress tests PASS, FIX-69 + BIP-158 reference
vectors regression-clean

## Context

W121 (commit `79a6dac`) discovered BUG-16 P0: `bitWriterWrite` silently
dropped bits when `numBits + bwBits > 64`.  FIX-69 (commit `4a2de0f`)
fixed it by splitting cross-Word64-boundary writes into a low-half +
recursive high-half write that matches Core's `streams.h
BitStreamWriter::Write` per-octet shape.

FIX-69 added 4 stress tests (q=64, q=100, mixed 0/30/65/120, source-level
regression).  This audit checks for ADJACENT boundary bugs that the
existing `blockfilters.json` reference vectors + the 4 FIX-69 stress
tests do not exercise.

## What FIX-69 already covers

- `q=64` exactly at the 1-bit-over boundary
- `q=100` well over the boundary
- Mixed stream q=0/30/65/120 (in-buffer + cross-boundary in one stream)
- Source-level regression guard (BUG-16 literal failure mode)

## New W122 stress dimensions added

| # | Test | Dimension exercised |
|---|------|---------------------|
| W122-1 | q=1023 (near 10-bit boundary, 15 boundary crossings) | Large-q class, many sequential cross-boundary writes |
| W122-2 | 7-bit warmup + q=70 (cross-boundary short remainder) | bwBits=7 misalignment with short second chunk (distinct from FIX-69's bwBits=3) |
| W122-3a | All-zeros element set (10x identical) | Zero-delta unary path, gcsFilterNew contract |
| W122-3b | All-0xFF element set (10x identical) | Max-Hamming-weight SipHash input |
| W122-3c | Mixed extremes (0x00 + 0xFF) | Two-element delta with extreme key inputs |
| W122-4 | Very large filter (100,000 elements) | Long stream + compact-size varint at 0xFD..0xFE boundary + sort scale |
| W122-5a | SipHash key=u64max, msg=u64max | Round-loop overflow on max-weight inputs |
| W122-5b | SipHash key=0, msg=empty | Initialization XOR-with-constants only |
| W122-6a | FastRange64 max hash + max range | 128-bit intermediate product overflow |
| W122-6b | FastRange64 range=1 | High-half always 0 invariant |
| W122-6c | FastRange64 x_lo=n_lo=2^32-1 | Piecewise 32x32 multiply carry boundary |
| W122-7 | Three consecutive q=64 writes | Back-to-back-to-back boundary state |
| W122-8 | bitReaderRead at numBits>56 | Reader pre-load limitation documented |
| W122-9 | bitWriterWrite numBits<=0 / negative | No-op guard path |
| W122-10 | mask helper at n=64 | maxBound (0xFF..FF) yield via encoded bytes |

All 15 PASS.

## Findings

### Finding 1: bitReaderRead 56-bit ceiling (DOCUMENTED LIMITATION, not a bug)

`bitReaderRead` (`src/Haskoin/Index.hs:348-367`) pre-loads bytes into
`brBuffer` only while `brBits < 56` (line 338, 360).  A direct call with
`numBits=64` will always throw `"Not enough bits in reader"` because the
buffer caps at 56 bits.

This is **asymmetric to `bitWriterWrite`**, which (post-FIX-69) handles
a full 64-bit write by splitting at the Word64 boundary.

**Production impact:** ZERO.  BIP-158 only calls `bitReaderRead` with
`p` (gcsP=19 for basic filters) or `1` (unary-bit-read in `readUnary`).
Both are well under 56.

**Audit posture:** Test W122-8 pins the current behavior (it throws on
numBits>56).  This is intentional documentation, not a fix request.
Core's `BitStreamReader::Read` handles 64-bit reads via a per-byte inner
loop; haskoin's optimized reader trades that capability for fewer
bit-shifts per byte (a reasonable speed/flexibility trade-off).

**Recommendation:** If a future caller adds a >56-bit read site, they
must either restructure to use multiple smaller reads (W122-8 shows the
pattern) or rewrite the reader's fillBuffer ceiling.  The W122-8 test
will alert on any drive-by change here.

### Finding 2: gcsFilterNew does NOT dedup; caller responsibility (DOCUMENTED CONTRACT)

`gcsFilterNew` (`src/Haskoin/Index.hs:489-507`) takes a `[ByteString]`
and treats every list element as distinct.  Passing 10 identical
elements yields a filter with N=10 (over-sized but functionally correct).

Production dedup happens in `computeBlockFilter`
(`src/Haskoin/Index.hs:700-705`) via `Set.toList . Set.fromList`,
matching Core's `BasicFilterElements` use of `unordered_set`
(`blockfilter.cpp:190`).

**Production impact:** ZERO.  Every production caller goes through
`computeBlockFilter` which dedups.

**Audit posture:** Tests W122-3a/3b document the codec's correctness on
degenerate inputs (zero-delta unary path) without asserting dedup behavior
that the codec doesn't promise.  W121 G8 separately tests
`computeBlockFilter`'s dedup contract.

### Finding 3: mask(64) yields maxBound via explicit FIX-69 helper (VERIFIED)

`bitWriterWrite`'s `mask` helper (`src/Haskoin/Index.hs:305-307`)
explicitly returns `maxBound` for `n=64`, matching Core's `~0ULL`
idiom.  The naive `(1 `shiftL` n) - 1` would collapse to `0 - 1 =
0xFFFF...FFFF` by GHC's modular semantics, but spelling it explicitly
avoids relying on that.

W122-10 verifies this: writing a full 64-bit `0xFFFFFFFFFFFFFFFF`
through `bitWriterWrite` and then flushing produces eight 0xFF bytes
(verified directly on `encoded`, since W122-8's reader-limitation
prevents a single 64-bit read-back).

### Finding 4: FastRange64 piecewise multiply is correct at boundaries

W122-6a/6b/6c verify three FastRange64 corners:

- max*max yields 0xFFFFFFFFFFFFFFFE (the analytic high 64 bits of
  `(2^64-1)^2 = 2^128 - 2^65 + 1`)
- range=1 always yields 0 (analytic: high 64 bits of `x * 1` = 0)
- carry boundary `x_lo=n_lo=2^32-1` yields 0 (product `2^64 - 2^33 + 1`
  fits in 64 bits, so high half is 0)

All three pass.  The piecewise 32x32 multiply in `mulWord64`
(`src/Haskoin/Index.hs:419-434`) handles carry propagation correctly.

### Finding 5: SipHash-2-4 is deterministic on max-weight + zero-input edges

W122-5a/5b verify SipHash determinism at:

- key=u64max, msg=16 bytes of 0xFF (max Hamming weight)
- key=0, msg=empty (initialization XOR-with-constants only)

Both produce non-zero deterministic output.  Combined with the
pre-existing spec vectors in `test/Spec.hs:13324` (0-byte, 1-byte,
7-byte, 8-byte, 15-byte inputs vs Aumasson/Bernstein paper), the
SipHash impl is well-covered.

### Finding 6: Large filter (100,000 elements) encodes + decodes round-trip

W122-4 builds a 100k-element filter, asserts N=100000, asserts a
known-present element matches, and asserts an absent element does not
match.  Then decodes the full encoded stream and asserts N agrees.

This exercises:
- many cross-Word64-boundary writes inside the encoder (each ~20-bit
  delta has ~5% chance of triggering one)
- compact-size varint at the 0xFD..0xFE boundary (100000 > 65535 →
  three-byte 0xFE form)
- the decoder over a long Golomb-Rice stream
- Data.List.sort at scale (100k Word64s)

Runtime ~1.5s on a Ryzen 9.

## Verdict

**VERIFIED CLEAN POST-FIX-69.**  No new bugs.  Two documented limitations
(reader 56-bit ceiling, gcsFilterNew non-dedup contract) are pre-existing
shape choices that match production usage and Core's idioms; they are
now pinned by W122-8 and W122-3a/3b tests so any future drive-by change
fails loud.

## Test counts

| | Before W122 | After W122 |
|---|---|---|
| W121 spec total | 81 examples (2 pending) | 96 examples (2 pending) |
| Codec stress tests | 6 (FIX-69) | 21 (FIX-69 + W122) |
| BIP-158 reference vectors | 9 (Spec.hs:13191) | 9 (unchanged) |

## References

- `src/Haskoin/Index.hs` — codec source
- `test/W121CompactFiltersSpec.hs` — codec stress tests
- `test/Spec.hs:13191` — BIP-158 reference vectors (blockfilters.json)
- `bitcoin-core/src/streams.h` BitStreamWriter::Write — reference shape
- `bitcoin-core/src/util/golombrice.h` — GolombRiceEncode/Decode
- `bitcoin-core/src/util/fastrange.h` — FastRange64
- `bitcoin-core/src/crypto/siphash.{h,cpp}` — SipHash-2-4
- `bitcoin-core/src/blockfilter.{h,cpp}` — GCSFilter
- Commit `3f0cde8` — W121 addendum (BUG-16 discovery)
- Commit `4a2de0f` — FIX-69 (BUG-16 fix)
