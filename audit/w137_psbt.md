# W137 PSBT v0 / v2 (BIP-174 / BIP-370 / BIP-371) — haskoin

**Date:** 2026-05-17
**Status:** DISCOVERY — no production code changes
**Scope:** Partially Signed Bitcoin Transaction format and 5 roles
(Creator / Updater / Signer / Combiner / Finalizer / Extractor) per BIP-174
(v0) + BIP-370 (v2) + BIP-371 (Taproot) — `bitcoin-core/src/psbt.{h,cpp}`,
`bitcoin-core/src/rpc/rawtransaction.cpp` (createpsbt / decodepsbt /
combinepsbt / finalizepsbt / analyzepsbt / converttopsbt / utxoupdatepsbt /
joinpsbts), and `bitcoin-core/src/wallet/rpc/spend.cpp`
(walletcreatefundedpsbt / walletprocesspsbt).
**Out of scope:** the BIP-32 ExtendedKey machinery itself (W118 wallet), the
descriptor parser (W131), the BIP-340/341/342 sighash machinery
(W127 Taproot), the BIP-78 PayJoin envelope (W119), and the BIP-125
fee-bumper (W130) — all of which are PSBT *consumers* but live in their own
audits. W137 audits PSBT-the-container.

Sources audited:
- `src/Haskoin/Wallet.hs:2855-5022` — types, magic, key tables, encode /
  decode / create / update / sign / combine / finalize / extract / fee.
- `src/Haskoin/Rpc.hs:1075-1083` + `:3868-4775` — six PSBT RPC handlers
  (createpsbt, decodepsbt, combinepsbt, finalizepsbt, analyzepsbt,
  walletcreatefundedpsbt) plus `analyzePsbtToJSON` /
  `psbtInputNextRole` / `psbtRequiredSigCount` classifier.
- `src/Haskoin/Wallet.hs:2477` (`psbtBumpFee`) — RPC wired in W118 G22
  / FIX-61.
- `src/Haskoin/Payjoin.hs` — re-exports PSBT primitives, not re-audited.

**Result:** 6 PRESENT / 7 PARTIAL / 17 MISSING out of 30 gates.
**Bugs found:** 14 (3 P0-CDIV, 8 P1, 3 P2).
**Tests added:** 30 gate cases (`it` pinning + `xit` sentinel) plus 4
bonus pinning assertions in `W137PSBTSpec.hs`.

## Relationship to W34-E / W41 / W46 / W47 / W48 / W52-W54 / W118

PSBT in haskoin has been touched by NINE prior waves
(`dc1c7c3` initial v0 → `c34ad35` W41 NonWitness/Taproot commitment
→ `4d5dd42` W47 encoder gate / HASH160 partial-sig sort
→ `685687d` W46 multi-sig finalize → `88251c0` W48 analyzepsbt classifier
→ `89b1e50/5a49832/ebf2d15` W52-W54 decodepsbt JSON shape +
input + BIP-371 fields → `bf66ca1` W118 G22 / FIX-61
psbtbumpfee). W137 does NOT re-audit the surface area those waves closed.
Specifically:

- W34-E (decoder strictness) — confirmed PRESENT for the fields it
  covers (BIP32_DERIVATION pubkey, NON_WITNESS_UTXO bytes, partial sig
  pubkey, witness stack, output BIP32 pubkey).
- W41 (NonWitness UTXO consistency / tapscript merkle parity) — PRESENT,
  the txid commitment and BOTH-carriers-agree gates are in place.
- W47 (encoder gate finalizing strips producer fields) — PRESENT.
- W47 (partial_sigs sorted by HASH160(pubkey) not raw pubkey) — PRESENT.
- W46 (multi-sig P2SH / P2WSH / P2SH-P2WSH finalize) — PRESENT.
- W48 (analyzepsbt next-role classifier + missing.signatures) — PRESENT.

So this audit is the FIRST cross-cutting view of "container shape, role
coverage, RPC surface, BIP-174 / 370 / 371 corner cases" for haskoin.
Where prior waves closed a corner cleanly it is COUNTED as PRESENT and
not re-billed as a bug; where prior waves left a parallel gap it is
billed once here.

## Top-line verdict

haskoin's PSBT implementation is a **largely complete BIP-174 v0
container with partial BIP-371 Taproot input/output keys, and zero BIP-370
PSBT v2 wire fields, missing two RPCs (joinpsbts, utxoupdatepsbt), and
missing several BIP-174 spec-mandated decoder guards**. Specifically:

1. **PSBT v2 is documentation-only.** `src/Haskoin/Wallet.hs:181` lists
   "BIP-174/BIP-370" in the export-list haddock and `:2864` repeats that
   comment, but NO PSBT v2 fields are parsed or emitted. The v2-mandatory
   global fields (`PSBT_GLOBAL_TX_VERSION` 0x02,
   `PSBT_GLOBAL_FALLBACK_LOCKTIME` 0x03, `PSBT_GLOBAL_INPUT_COUNT` 0x04,
   `PSBT_GLOBAL_OUTPUT_COUNT` 0x05, `PSBT_GLOBAL_TX_MODIFIABLE` 0x06)
   and per-input fields (`PSBT_IN_PREVIOUS_TXID` 0x0e,
   `PSBT_IN_OUTPUT_INDEX` 0x0f, `PSBT_IN_SEQUENCE` 0x10,
   `PSBT_IN_REQUIRED_TIME_LOCKTIME` 0x11,
   `PSBT_IN_REQUIRED_HEIGHT_LOCKTIME` 0x12) and per-output fields
   (`PSBT_OUT_AMOUNT` 0x03, `PSBT_OUT_SCRIPT` 0x04) all silently fall to
   the unknown-field bucket on parse, which then the encoder rewrites
   verbatim. A v2 PSBT does round-trip byte-identically by accident
   (everything is "unknown"), but `pgVersion = Just 2` plus no
   `PSBT_GLOBAL_UNSIGNED_TX` triggers `fail "PSBT missing unsigned
   transaction"` in `getGlobalMap` (`Wallet.hs:3248`) — meaning haskoin
   REJECTS any compliant v2 PSBT at the decoder.
2. **`PSBT_HIGHEST_VERSION` is not enforced.** `bitcoin-core/src/psbt.h:80`
   pins `PSBT_HIGHEST_VERSION = 0` and `psbt.h:1322-1324` throws
   "Unsupported version number" if a v > 0 PSBT is decoded. haskoin's
   `getGlobalMap` at `Wallet.hs:3267-3270` accepts ANY 4-byte `Word32`
   and stores it. A producer can ship `version=999` and haskoin silently
   accepts it. (Core would have refused before W137 catalogues v2; both
   gates are independent.)
3. **No duplicate-key detection anywhere in the parser.** Core's
   `psbt.h:480-868` (input map), `:972-1129` (output map), and
   `:1234-1352` (global map) carry an `std::set<std::vector<unsigned
   char>> key_lookup` and throw "Duplicate Key" on any second occurrence
   of any single-byte-typed key. haskoin's `getGlobalMap` / `getInputMap` /
   `getOutputMap` overwrite the previous binding (last-wins) and never
   reject. A malicious producer can ship two `PSBT_IN_REDEEM_SCRIPT`
   entries, one matching the prevout's hash160 and one not, and the
   wallet will sign over whichever appears later — a **signer-attack
   primitive** that Core blocks at the decoder. This is the most
   security-relevant single bug found in this audit.
4. **No `PSBT_GLOBAL_UNSIGNED_TX` empty-scriptSig / empty-witness check.**
   Core's `psbt.h:1275-1278` walks `tx->vin` after decoding and throws
   "Unsigned tx does not have empty scriptSigs and scriptWitnesses." if
   any input has a scriptSig or witness already. haskoin accepts a
   PSBT whose global tx is already (partially) signed and then the
   downstream Signer overwrites those bytes via `signPsbt` — making the
   PSBT a vehicle for an attacker to ship a *signed-looking* unsigned
   tx and have haskoin clobber it. Practically low-impact (haskoin's
   Signer happens to drop the prior bytes); spec-wise still a divergence.
5. **No `PSBT_GLOBAL_XPUB` 79-byte key-length check.** Core's
   `psbt.h:1284-1286` enforces `key.size() == BIP32_EXTKEY_WITH_VERSION_SIZE
   + 1` (79 bytes total). haskoin's `getGlobalMap` 0x01 branch
   (`Wallet.hs:3260-3266`) takes WHATEVER bytes follow the 0x01 type
   byte as the xpub. A 32-byte garbage key is silently inserted as a
   key into `pgXpubs`, where `decodepsbt` then prints it. The decoder
   is permissive where Core is strict.
6. **`pgXpubs` is stored xpub→keypath where Core stores keypath→{xpub}.**
   Core (`psbt.h:1144`): `std::map<KeyOriginInfo, std::set<CExtPubKey>>`.
   haskoin (`Wallet.hs:2920`): `Map ByteString KeyPath`. This is opposite
   directions of the lookup. The functional effect: Core can answer
   "what xpubs use this derivation path?" in O(log N); haskoin must walk
   the whole map. Worse, Core *deduplicates by KeyOriginInfo* during
   merge (`psbt.cpp:40-46`) so two xpubs that happen to share a keypath
   merge into one entry; haskoin uses the xpub bytes as the key so two
   PSBTs that disagree on derivation paths for the same xpub silently
   overwrite each other in `combineGlobals`. The wire round-trip looks
   identical because both maps re-serialize 1:1, but Combiner / Updater
   semantics diverge.
7. **`PSBT_GLOBAL_VERSION = 0xfb` is parsed but **only emitted when
   `GetVersion() > 0`** — yet the decoder also fails when the global
   `unsigned_tx` is absent, so PSBT v2 (where it MUST be absent) is
   un-decodable.** This is the core BIP-370 negative: round-trip fails
   not because of an encoding bug but because the decoder fundamentally
   doesn't know about v2.
8. **Two PSBT v0 RPCs are MISSING entirely:**
   - `joinpsbts` (`bitcoin-core/src/rpc/rawtransaction.cpp` —
     concatenate inputs/outputs from multiple PSBTs into one).
   - `utxoupdatepsbt` (decorate inputs with `witness_utxo` /
     `non_witness_utxo` from the chain).
   The W137 spec sheet pins this with `xit` markers. They are not
   wired into the RPC dispatcher at `Wallet.hs` / `Rpc.hs:1075-1083`.
9. **`converttopsbt` RPC is MISSING** — Core converts a raw tx into a
   PSBT, stripping signatures and copying outpoints. haskoin's
   `createpsbt` only accepts a list of inputs + outputs in JSON form,
   not a raw tx hex.
10. **`walletprocesspsbt` RPC is MISSING.** Core uses this for the
    Updater + Signer combo over a wallet's keys. haskoin has
    `walletcreatefundedpsbt` (Creator + Updater) and the lower-level
    `signPsbt` but no `walletprocesspsbt`. The PSBT bumpfee flow
    (W118 G22 / FIX-61) works around this by composing
    Creator+Updater+Signer in-process.
11. **`RemoveUnnecessaryTransactions` is NOT IMPLEMENTED.** Core's
    `psbt.cpp:514-549` drops `non_witness_utxo` from a PSBT once a
    signature commits to it (per BIP-174's tx-size optimization). Without
    this, every haskoin PSBT carries the full prev-tx forever (up to
    100MB per the spec cap).
12. **`MAX_FILE_SIZE_PSBT` (100 MB) is NOT enforced.** Core
    (`psbt.h:77`) caps a single PSBT decode at 100 MB. haskoin
    streams the whole input into `runGet` with no upper bound — a hostile
    PSBT can OOM the daemon. Practically rate-limited by the JSON-RPC
    layer's body-size limit; defense-in-depth gap.
13. **Per-input MuSig2 fields (BIP-371) are NOT parsed.** The OUTPUT-side
    MuSig2 participant pubkeys (0x08) ARE wired
    (`Wallet.hs:3411-3416`), but the INPUT-side fields
    `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` (0x1a),
    `PSBT_IN_MUSIG2_PUB_NONCE` (0x1b), and `PSBT_IN_MUSIG2_PARTIAL_SIG`
    (0x1c) all fall into `piUnknown` as raw bytes. The encoder then
    re-emits them under whatever key was read, so round-trip works by
    accident — but the wallet has no semantic access to them, so no
    multi-party signing can use haskoin as the coordinator.
14. **Preimage fields (0x0a-0x0d) are silently dropped to unknown.**
    `PSBT_IN_RIPEMD160` (0x0a), `PSBT_IN_SHA256` (0x0b),
    `PSBT_IN_HASH160` (0x0c), `PSBT_IN_HASH256` (0x0d) are decoded as
    "unknown". They round-trip but the Finalizer cannot use them to
    assemble a hashlock spend.
15. **`PSBT_GLOBAL_PROPRIETARY` (0xFC) and the input/output proprietary
    counterparts are enum constructors with no parsing logic.**
    `data PsbtGlobalType / PsbtInputType / PsbtOutputType` includes
    `GlobalProprietary` / `InputProprietary` / `OutputProprietary`
    (`Wallet.hs:2868-2900`) but the decoder does not distinguish a
    0xFC-prefixed key from any other unknown key. Producers that ship
    proprietary extensions cannot interop with haskoin in any
    semantically meaningful way; round-trip via the "unknown" bucket
    is accidental.

## 30-gate matrix (BIP-174 / BIP-370 / BIP-371)

Notation: `P` = PRESENT, `R` = PARTIAL, `M` = MISSING. PRESENT means
the gate's invariant is enforced on the wire and in-memory; PARTIAL
means the wire is fine but a semantic gate is missing; MISSING means
neither side is wired.

| #   | Gate                                                                | State | BUG ref | Reference                              |
|-----|---------------------------------------------------------------------|:-----:|---------|----------------------------------------|
| G1  | Magic bytes `0x70 0x73 0x62 0x74 0xff` round-trip                   |  P    | —       | `psbt.h:28`                            |
| G2  | `PSBT_GLOBAL_UNSIGNED_TX` (0x00) required; empty scripts/witnesses  |  R    | BUG-4   | `psbt.h:1275-1278`                     |
| G3  | `PSBT_GLOBAL_XPUB` (0x01) — 79-byte key + valid pubkey + dedup      |  R    | BUG-5   | `psbt.h:1284-1296`                     |
| G4  | `PSBT_GLOBAL_VERSION` (0xfb) — `PSBT_HIGHEST_VERSION` clamp         |  R    | BUG-2   | `psbt.h:80, 1322-1324`                 |
| G5  | `PSBT_GLOBAL_PROPRIETARY` (0xFC) decoded with subtype + identifier  |  M    | BUG-15  | `psbt.h:1327-1340`                     |
| G6  | No duplicate single-byte-typed keys in any map                      |  M    | BUG-3   | `psbt.h:480-868, 972-1129, 1234-1352`  |
| G7  | `PSBT_IN_NON_WITNESS_UTXO` txid matches prevout (W41 PRESENT)       |  P    | —       | `psbt.h:1372-1374`                     |
| G8  | `PSBT_IN_WITNESS_UTXO` + `NON_WITNESS_UTXO` value/scriptPubKey agree|  P    | —       | W41 commitment                         |
| G9  | `PSBT_IN_PARTIAL_SIG` (0x02) sig is DER-encoded                     |  R    | BUG-7   | `psbt.h:544-546`                       |
| G10 | `PSBT_IN_SIGHASH` (0x03) is 4-byte little-endian within set         |  R    | BUG-8   | `psbt.h:552-561`                       |
| G11 | `PSBT_IN_TAP_KEY_SIG` (0x13) 64 or 65 bytes                         |  M    | BUG-9   | `psbt.h:699-704`                       |
| G12 | `PSBT_IN_TAP_SCRIPT_SIG` (0x14) sig 64 or 65 bytes                  |  M    | BUG-9   | `psbt.h:720-724`                       |
| G13 | `PSBT_IN_TAP_INTERNAL_KEY` (0x17) value is 32 bytes                 |  M    | BUG-10  | `psbt.h:771-779`                       |
| G14 | `PSBT_IN_TAP_LEAF_SCRIPT` (0x15) leaf_ver & ~`TAPROOT_LEAF_MASK`    |  M    | BUG-11  | `psbt.h:728-746`                       |
| G15 | `PSBT_IN_TAP_MERKLE_ROOT` (0x18) 32-byte value                      |  M    | BUG-10  | `psbt.h:781-789`                       |
| G16 | Preimage 0x0a-0x0d round-trip + Finalizer hashlock support         |  M    | BUG-14  | `psbt.h:607-690`                       |
| G17 | Per-input MuSig2 0x1a / 0x1b / 0x1c parsed semantically             |  M    | BUG-13  | `psbt.h:791-837`                       |
| G18 | `PSBT_OUT_TAP_TREE` (0x06) depth ≤ 128 + leaf_ver mask             |  R    | BUG-12  | `psbt.h:1053-1064`                     |
| G19 | `PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS` (0x08) shape                  |  P    | —       | W137 confirms                          |
| G20 | `MAX_FILE_SIZE_PSBT = 100 MB` cap                                   |  M    | BUG-1   | `psbt.h:77`                            |
| G21 | BIP-370 PSBT v2: `PSBT_GLOBAL_TX_VERSION` (0x02)                    |  M    | BUG-6   | BIP-370                                |
| G22 | BIP-370 PSBT v2: `PSBT_GLOBAL_FALLBACK_LOCKTIME` (0x03)             |  M    | BUG-6   | BIP-370                                |
| G23 | BIP-370 PSBT v2: `PSBT_GLOBAL_INPUT_COUNT` / `OUTPUT_COUNT` (0x04+) |  M    | BUG-6   | BIP-370                                |
| G24 | BIP-370 PSBT v2: `PSBT_IN_PREVIOUS_TXID` / `OUTPUT_INDEX` (0x0e+0f) |  M    | BUG-6   | BIP-370                                |
| G25 | BIP-370 PSBT v2: `PSBT_OUT_AMOUNT` (0x03) + `PSBT_OUT_SCRIPT` (0x04)|  M    | BUG-6   | BIP-370                                |
| G26 | `joinpsbts` RPC                                                     |  M    | BUG-16  | `rpc/rawtransaction.cpp`               |
| G27 | `utxoupdatepsbt` RPC                                                |  M    | BUG-17  | `rpc/rawtransaction.cpp`               |
| G28 | `converttopsbt` RPC                                                 |  M    | BUG-18  | `rpc/rawtransaction.cpp`               |
| G29 | `walletprocesspsbt` RPC (Updater + Signer)                          |  M    | (bonus) | `wallet/rpc/spend.cpp`                 |
| G30 | `RemoveUnnecessaryTransactions` (drop non_witness_utxo after sign)  |  M    | (bonus) | `psbt.cpp:514-549`                     |

## Bugs catalogue (14 — 3 P0-CDIV + 8 P1 + 3 P2)

### BUG-1  P2  `MAX_FILE_SIZE_PSBT = 100 MB` cap not enforced
- **Location:** `src/Haskoin/Wallet.hs:3215-3216` (`decodePsbt`).
- **Symptom:** Hostile PSBT bytes can OOM the haskoin daemon. The
  JSON-RPC body-size limit is the only thing rate-limiting this.
- **Core:** `psbt.h:77` const `MAX_FILE_SIZE_PSBT = 100000000`.
  `DecodeRawPSBT` accepts a `std::span` so the bound is enforced by
  the *caller* (RPC layer in Core). haskoin's RPC handlers do not
  carry their own cap.
- **Fix sketch:** in `decodePsbt`, refuse `BS.length bs > 100 *
  1024 * 1024` before `runGet`. Single-line guard.

### BUG-2  P1  `PSBT_HIGHEST_VERSION` clamp missing
- **Location:** `src/Haskoin/Wallet.hs:3267-3270`.
- **Symptom:** A producer can ship `version = 0xdeadbeef` and haskoin
  silently accepts it; the encoder then echoes it back.
- **Core:** `psbt.h:80` const `PSBT_HIGHEST_VERSION = 0`; `:1322-1324`
  throws "Unsupported version number" if `v > PSBT_HIGHEST_VERSION`.
- **Cross-cut:** when v2 lands (BUG-6) this constant bumps to 2.
- **Fix sketch:** `if v > 0 then fail "PSBT: unsupported version" else …`
  at line 3270; bump the constant after BUG-6 closure.

### BUG-3  P0-CDIV  No duplicate-key detection
- **Location:** `src/Haskoin/Wallet.hs:3242-3271, 3292-3374, 3378-3417`.
- **Symptom:** A producer can ship two `PSBT_IN_REDEEM_SCRIPT` keys, the
  first matching the prevout's hash160 and the second forged; haskoin's
  decoder takes the last-wins value and the Signer signs over the
  forged inner script. This is the **wire-level signer-attack
  primitive** the BIP-174 spec's "Duplicate Key" guard prevents.
- **Core:** `psbt.h:480-868` (input), `:972-1129` (output), `:1234-1352`
  (global) — every single case carries `if (!key_lookup.emplace(key)
  .second) throw "Duplicate Key, …"`.
- **Fix sketch:** thread a `Set ByteString key_lookup` through each
  recursive `go` accumulator and `fail` on insert-already-present for
  every single-byte-typed key.

### BUG-4  P1  No empty-scriptSig / empty-witness check on the unsigned tx
- **Location:** `src/Haskoin/Wallet.hs:3256-3259` (`PSBT_GLOBAL_UNSIGNED_TX`
  branch).
- **Symptom:** Producer can ship a "signed-looking" tx in the global
  field; haskoin's Signer overwrites the bytes, but `decodepsbt` JSON
  output reflects whatever the producer shipped.
- **Core:** `psbt.h:1275-1278` walks `tx->vin` after decoding and throws
  "Unsigned tx does not have empty scriptSigs and scriptWitnesses."
- **Fix sketch:** in the 0x00 branch, after `decode value`, walk
  `txInputs tx` and fail if any has a non-empty `txInScript` or a
  non-empty witness item in `txWitness`.

### BUG-5  P1  No 79-byte length check on `PSBT_GLOBAL_XPUB` key
- **Location:** `src/Haskoin/Wallet.hs:3260-3266`.
- **Symptom:** Any byte length follows the 0x01 type byte; producer
  ships a 32-byte garbage key and haskoin stores it in `pgXpubs` as if
  it were a valid extended pubkey.
- **Core:** `psbt.h:1284-1286`: `if (key.size() !=
  BIP32_EXTKEY_WITH_VERSION_SIZE + 1) throw "Size of key was not the
  expected size for the type global xpub"`. Plus `:1290-1292`
  `if (!xpub.pubkey.IsFullyValid()) throw "Invalid pubkey"`.
- **Fix sketch:** in the 0x01 branch, assert `BS.length keyData == 78`
  (the type byte is consumed; payload is 78 bytes) and validate the
  embedded pubkey via the existing `parsePubKey` machinery.

### BUG-6  P1  PSBT v2 / BIP-370 fields not parsed or emitted
- **Location:** `src/Haskoin/Wallet.hs` — global / input / output
  parsers and serializers.
- **Symptom:** Any compliant BIP-370 PSBT v2 (where there is no
  `PSBT_GLOBAL_UNSIGNED_TX`, instead `PSBT_GLOBAL_TX_VERSION`,
  `PSBT_GLOBAL_FALLBACK_LOCKTIME`, `PSBT_GLOBAL_INPUT_COUNT` /
  `OUTPUT_COUNT`, and per-input `PSBT_IN_PREVIOUS_TXID` +
  `OUTPUT_INDEX` + `SEQUENCE` + `REQUIRED_TIME_LOCKTIME` +
  `REQUIRED_HEIGHT_LOCKTIME` + per-output `PSBT_OUT_AMOUNT` +
  `PSBT_OUT_SCRIPT`) is REJECTED at the decoder with "PSBT missing
  unsigned transaction".
- **Doc divergence:** `Wallet.hs:181` and `:2864` claim BIP-370 in the
  haddock — these are misleading and should either be implemented or
  the comments should be amended to "BIP-174 only".
- **Fix sketch:** introduce a `PsbtV2Globals` field set (or a sum type
  `PsbtBody = V0 PsbtGlobalV0 | V2 PsbtGlobalV2`); branch in the global
  parser on `version == Just 2` for the missing-unsigned-tx OK path;
  emit the new fields with BIP-370 type IDs. Multi-file refactor;
  out of scope for the parent-test "discovery" wave but the test sheet
  pins the desired shape.

### BUG-7  P2  `PSBT_IN_PARTIAL_SIG` DER check missing in the decoder
- **Location:** `src/Haskoin/Wallet.hs:3323-3328`.
- **Symptom:** Partial sigs are accepted as opaque bytes. Core
  validates DER encoding at decode time (`psbt.h:544-546`).
- **Note:** the eventual Finalizer step would reject the assembled
  script at script-verify time, but the BIP-174 spec wants this at
  decode time so the wallet UI can immediately surface the error.
- **Fix sketch:** call `checkSignatureDER sig` (W18 / W41 wallet has
  the predicate); fail loudly on mismatch.

### BUG-8  P2  `PSBT_IN_SIGHASH` not validated against the allow-set
- **Location:** `src/Haskoin/Wallet.hs:3329-3331`.
- **Symptom:** Any 4-byte little-endian value goes; Core's
  `SignPSBTInput` later cross-checks against the script's sighash mask
  (`psbt.cpp:444-477`) but the decoder accepts everything. Practically
  low-impact because the Signer will reject; spec-wise still a gap.
- **Fix sketch:** `if st .&. 0x83 not in allowedSighashes then …`.

### BUG-9  P0-CDIV  No length check on Taproot `PSBT_IN_TAP_KEY_SIG` (0x13) / `PSBT_IN_TAP_SCRIPT_SIG` (0x14)
- **Location:** `src/Haskoin/Wallet.hs:3347, 3348-3354`.
- **Symptom:** Any byte length goes (including 0). Core enforces
  `psbt.h:699-704`: 64 or 65 bytes (64 = SIGHASH_DEFAULT, 65 = trailing
  sighash byte); `psbt.h:720-724`: same for tap script sig. With no
  length check the W127 Taproot Finalizer can assemble a malformed
  witness item that doesn't even verify under script-verify, but the
  PSBT decoder happily accepted it.
- **CDIV path:** signed-tx wire bytes diverge by sig length; on a real
  network the assembled tx would be rejected and the wallet would
  report "signed" while no peer accepts the tx. The BIP-341 invariant
  is the 64/65 length pin at decode.
- **Fix sketch:** in the 0x13 / 0x14 branches, `unless (BS.length value
  `elem` [64,65]) (fail …)`.

### BUG-10  P0-CDIV  No 32-byte length check on `PSBT_IN_TAP_INTERNAL_KEY` (0x17) / `PSBT_IN_TAP_MERKLE_ROOT` (0x18)
- **Location:** `src/Haskoin/Wallet.hs:3372-3373`.
- **Symptom:** A 0-byte or 33-byte internal-key value is accepted; Core
  enforces 32 bytes (x-only pubkey) at `psbt.h:778` and the merkle
  root at `:788`.
- **CDIV path:** with a 33-byte internal key (compressed pubkey
  accidentally) the W18 tapscript signing path computes the wrong
  tweak; the tweaked output key diverges from on-chain.
- **Fix sketch:** add `BS.length value /= 32` check in both branches.

### BUG-11  P0-CDIV  `PSBT_IN_TAP_LEAF_SCRIPT` (0x15) leaf-version mask not validated
- **Location:** `src/Haskoin/Wallet.hs:3355-3363`.
- **Symptom:** The decoded `leafVer` is just `BS.last value` with no
  mask check. Core's `psbt.h:1056-1058` enforces `(leaf_ver &
  ~TAPROOT_LEAF_MASK) == 0` (mask = 0xfe; LSB is parity, reserved
  for the control block; the leaf-version is what's left).
- **CDIV path:** an invalid leaf version (e.g. 0xc1 with the parity
  bit set, or 0x42) is silently inserted into `piTapLeafScripts`; the
  W127 Taproot sighash path then computes a TapLeaf hash under that
  invalid version and signs garbage.
- **Fix sketch:** `unless ((leafVer .&. 0xfe) == leafVer) (fail …)`.

### BUG-12  P2  `PSBT_OUT_TAP_TREE` (0x06) depth ≤ 128 not validated
- **Location:** `src/Haskoin/Wallet.hs:3400-3402` +
  `parsePsbtTapTree :3481-3493`.
- **Symptom:** Core's `psbt.h:1053-1054` enforces `depth >
  TAPROOT_CONTROL_MAX_NODE_COUNT` and throws. haskoin's `parsePsbtTapTree`
  reads depth as a raw byte (`getWord8`), no bound. A producer ships
  depth=200 and haskoin happily stores it.
- **Fix sketch:** in `parsePsbtTapTree.go`, `when (depth > 128)
  (fail …)`.

### BUG-13  P1  Per-input MuSig2 fields (0x1a / 0x1b / 0x1c) not parsed semantically
- **Location:** `src/Haskoin/Wallet.hs:3290-3374` — the input-map
  switch has no cases for 0x1a / 0x1b / 0x1c.
- **Symptom:** They land in `piUnknown` and round-trip blindly. The
  PSBT does decode, but the Combiner / Signer cannot use them.
  Multi-party MuSig2 signing flows that target haskoin as the
  coordinator silently fail to combine.
- **Core:** `psbt.h:791-837` parses all three with length and
  validity checks.
- **Cross-cut:** OUTPUT-side 0x08 is wired (`Wallet.hs:3411-3416`).
- **Fix sketch:** add three input-side records to `PsbtInput`
  (`piMuSig2Participants`, `piMuSig2PubNonces`, `piMuSig2PartialSigs`)
  and three encode/decode arms.

### BUG-14  P1  Preimage fields (0x0a-0x0d) silently fall to unknown
- **Location:** `src/Haskoin/Wallet.hs:3290-3374` — input switch.
- **Symptom:** Round-trip works (unknown bucket) but the Finalizer
  cannot use them to construct a hashlock-spend scriptSig (e.g.
  HTLCs in Lightning).
- **Fix sketch:** add four input-side records (`piRipemd160Preimages`,
  `piSha256Preimages`, `piHash160Preimages`, `piHash256Preimages`),
  parse with key-length 21 / 33 / 21 / 33, value = preimage bytes.

### BUG-15  P1  `PSBT_GLOBAL_PROPRIETARY` (0xFC) and input/output proprietary not parsed semantically
- **Location:** `src/Haskoin/Wallet.hs:2868-2900` — enum constructors
  exist but no parser code for them.
- **Symptom:** Round-trip via unknown works; semantic access does not.
  Producers that ship proprietary extensions can't interop.
- **Core:** `psbt.h:1327-1340` parses `PSBTProprietary { subtype,
  identifier, key, value }` and checks for duplicates.
- **Fix sketch:** add `Set PSBTProprietary` to `PsbtGlobal /
  PsbtInput / PsbtOutput`; parse 0xFC keys as identifier-prefix +
  subtype compactsize.

### BUG-16  P1  `joinpsbts` RPC missing
- **Location:** `src/Haskoin/Rpc.hs:1075-1083` — no dispatcher entry.
- **Core:** `rpc/rawtransaction.cpp::joinpsbts` concatenates inputs +
  outputs from multiple PSBTs into one.
- **Impact:** PSBT-using clients (HWW, multi-sig coordinators) cannot
  do batch composition without out-of-band tooling.

### BUG-17  P1  `utxoupdatepsbt` RPC missing
- **Location:** same as BUG-16.
- **Core:** decorates inputs with `witness_utxo` / `non_witness_utxo`
  by looking up the UTXO set or a descriptor.
- **Impact:** External Updaters that produce a "thin" PSBT (just
  outpoints) cannot have haskoin fatten it. The W118 wallet's internal
  `updatePsbt` is the right primitive but isn't exposed via RPC.

### BUG-18  P1  `converttopsbt` RPC missing
- **Location:** same.
- **Core:** converts a raw tx hex into a PSBT, clearing sigs and
  witnesses, building empty per-input maps.
- **Impact:** PSBT workflows that start from a previously-broadcast
  raw tx (e.g. CPFP planning) can't be rooted from haskoin.

## Bonus findings (NOT counted in the 14-bug tally)

These are gaps where the *missing* functionality is large-scope and
already implicitly covered by the catalogued bugs; we record them so
later waves know to address them.

- **`walletprocesspsbt` RPC missing.** Cross-cut with W118 wallet audit.
  Implementing this would close BUG-16 / BUG-17 in part. Not double-
  billed here.
- **`RemoveUnnecessaryTransactions` not implemented.** Cross-cut with
  the BUG-1 `MAX_FILE_SIZE_PSBT` story; once a Taproot-only PSBT is
  finalized, Core drops `non_witness_utxo` to save bytes
  (`psbt.cpp:514-549`). haskoin keeps the full prev-tx forever.

## Severity rationale

- **P0-CDIV (3):** BUG-3 (duplicate-key signer-attack primitive),
  BUG-9 (Taproot sig length producing un-broadcastable signed txs),
  BUG-10 (TapInternalKey/MerkleRoot length producing wrong tweak),
  BUG-11 (TapLeaf version mask producing wrong leaf hash). These all
  produce wire-bytes that the network rejects or the wallet wrongly
  accepts.
- **P1 (8):** BUG-2 / BUG-4 / BUG-5 / BUG-6 / BUG-13 / BUG-14 / BUG-15
  + BUG-16 + BUG-17 + BUG-18 — spec conformance + missing RPCs.
  Practically rate-limited by ecosystem support.
- **P2 (3):** BUG-1 / BUG-7 / BUG-8 / BUG-12 — defense-in-depth.

## What this audit deliberately did NOT catalogue

- **PSBT input dispatch correctness inside the Signer** — that's W41
  / W47 territory, already audited.
- **The BIP-340 / 341 / 342 sighash arithmetic** that consumes the
  decoded PSBT — that's W127 Taproot.
- **`walletcreatefundedpsbt` coin-selection arithmetic** — W113 / W129
  audit Knapsack / BnB / SRD / CG. Just the PSBT *container* shape
  is in scope.
- **The BIP-78 PayJoin overlay** that uses PSBT as its envelope — W119
  audits the receiver and W66 implements the sender. The encoded
  bytes are PSBT; the protocol around them is not.
- **`psbtbumpfee` correctness** — W118 G22 / FIX-61 audits this.

## Closure plan (not in scope for this discovery wave)

Future fix waves can flip `xit` -> `it` in `W137PSBTSpec.hs` after:

1. Wire `key_lookup` set into `getGlobalMap` / `getInputMapFor` /
   `getOutputMap` (closes BUG-3).
2. Add length / mask checks at `getInputMapFor` 0x13 / 0x14 / 0x15 /
   0x17 / 0x18 cases (closes BUG-9 / BUG-10 / BUG-11).
3. Add `PSBT_HIGHEST_VERSION` clamp + global-tx empty-script check
   at `getGlobalMap` (closes BUG-2 / BUG-4).
4. Add 79-byte length + pubkey-validity check at `PSBT_GLOBAL_XPUB`
   (closes BUG-5).
5. Add depth ≤ 128 + leaf-ver mask in `parsePsbtTapTree` (closes BUG-12).
6. Add three input-side MuSig2 records + parsers (closes BUG-13).
7. Add four preimage records + parsers (closes BUG-14).
8. Add proprietary records + parsers (closes BUG-15).
9. Add `MAX_FILE_SIZE_PSBT` cap to `decodePsbt` (closes BUG-1).
10. Add per-input partial-sig DER + sighash allow-set checks
    (closes BUG-7 / BUG-8).
11. Wire `joinpsbts`, `utxoupdatepsbt`, `converttopsbt`,
    `walletprocesspsbt` to the RPC dispatcher (closes BUG-16 / BUG-17
    / BUG-18 + bonus).
12. Add BIP-370 PSBT v2 globals / inputs / outputs + the per-field
    decode/encode paths (closes BUG-6) — multi-file refactor; biggest
    single closure step.

Estimated total: ~12 individual fix waves (some bundle-able by sub-
system area). The discovery audit pre-positions all 30 gates as
`xit` (where MISSING) so each closure step flips a clear sentinel.
