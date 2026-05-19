# W157 — Signet block solution + BIP-94 timewarp + miner-side header constants (haskoin)

**Wave:** W157 — `CheckSignetBlockSolution`, `SIGNET_HEADER (0xecc7daa2)`,
`signet_challenge`, `FetchAndClearCommitmentSection`,
`BIP-94 MAX_TIMEWARP=600` at retarget on **all networks** since v25,
`GetMinimumTime` miner-side clamp, `enforce_BIP94` consensus param,
`nVersion` BIP-9 signaling, `nBits` target encoding,
`GetNextWorkRequired` at retarget, `fPowAllowMinDifficultyBlocks` testnet,
signet on regtest, default vs custom signet_challenge.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/signet.cpp` —
  `static constexpr uint8_t SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2};`
  (line 28), `static constexpr script_verify_flags BLOCK_SCRIPT_VERIFY_FLAGS =
  P2SH | WITNESS | DERSIG | NULLDUMMY;` (line 30),
  `FetchAndClearCommitmentSection` (lines 32-57) — walks the witness
  commitment OP_RETURN, extracts the bytes that follow the 4-byte
  `SIGNET_HEADER` prefix into `signet_solution` and rebuilds a
  cleaned-up `witness_commitment` (the signed-merkle preimage),
  `ComputeModifiedMerkleRoot` (lines 59-68) — recomputes the merkle root
  AFTER swapping in the cleaned coinbase; deliberately uses the
  *modified* coinbase hash + every other tx's `GetHash().ToUint256()`
  capacity-rounded-up-to-even so an empty signet solution still
  exercises the duplicate-leaf rule (CVE-2012-2459) the same way Core
  does, `SignetTxs::Create` (lines 70-123) — synthesises the
  to-spend/to-sign pair the signet challenge will be verified against;
  builds `block_data = nVersion || hashPrevBlock || signet_merkle ||
  nTime` (skips the nonce!) and pushes it as the to-spend scriptSig
  prevout = `(to_spend.GetHash(), 0)`,
  `CheckSignetBlockSolution` (lines 126-153) — genesis short-circuit,
  pull `signet_challenge` from `Consensus::Params`, run `SignetTxs::Create`,
  reject on failure, then `VerifyScript(scriptSig, prev.scriptPubKey,
  &witness, BLOCK_SCRIPT_VERIFY_FLAGS, sigcheck)`.
- `bitcoin-core/src/signet.h` — public surface: just
  `CheckSignetBlockSolution(const CBlock&, const Consensus::Params&)`
  and `class SignetTxs { Create; m_to_spend; m_to_sign; }`.
- `bitcoin-core/src/consensus/params.h:121` — `bool enforce_BIP94;`
  (per-network consensus flag — true on testnet4 always, opt-in on
  regtest via `-enforce_bip94=1`, false on mainnet/testnet3/signet
  per current chainparams).
- `bitcoin-core/src/consensus/params.h:140` —
  `std::vector<uint8_t> signet_challenge;` (per-network consensus
  payload — empty unless `m_chain_type == SIGNET`).
- `bitcoin-core/src/consensus/consensus.h:35` —
  `static constexpr int64_t MAX_TIMEWARP = 600;`
- `bitcoin-core/src/validation.cpp:4097-4104` —
  `ContextualCheckBlockHeader` enforces BIP-94 on every network where
  `consensus.enforce_BIP94` is set: at every difficulty-adjustment
  boundary the new block's `GetBlockTime()` must be ≥
  `pindexPrev->GetBlockTime() - MAX_TIMEWARP`; reject `time-timewarp-attack`.
- `bitcoin-core/src/pow.cpp:67-76` — `CalculateNextWorkRequired` uses
  `pindexFirst->nBits` when `enforce_BIP94` is true (otherwise
  `pindexLast->nBits` — the legacy time-warp-attack surface).
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime`: at every
  difficulty-adjustment boundary, clamp `min_time` UP to
  `max(MTP+1, prev_block_time - MAX_TIMEWARP)`. **The comment on
  line 41-42 reads** *"Account for BIP94 timewarp rule on all networks.
  This makes future activation safer."* — i.e. the miner enforces the
  BIP-94 floor regardless of whether the consensus flag is on, so
  templates produced for mainnet/testnet3/signet still respect the
  rule and can be safely fed to a future fork that activates BIP-94.
- `bitcoin-core/src/node/miner.cpp:49-65` — `UpdateTime` calls
  `GetMinimumTime(...)` first, then `max` with `NodeClock::now()`;
  only after that does it conditionally re-derive `nBits` if
  `fPowAllowMinDifficultyBlocks`.
- `bitcoin-core/src/kernel/chainparams.cpp:308-322` — testnet4
  `consensus.enforce_BIP94 = true;` (line 322), genesis,
  `nMinimumChainWork`, `defaultAssumeValid`.
- `bitcoin-core/src/kernel/chainparams.cpp:404-520` — `SigNetParams`.
  Default signet: `signet_challenge` populated from a hard-coded
  challenge unless `-signetchallenge=<hex>` overrides; default genesis
  `00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6`,
  `nDefaultPort = 38333`, `powLimit =
  00000377ae000000000000000000000000000000000000000000000000000000`,
  `nPowTargetTimespan = 14 days`, `nPowTargetSpacing = 600s`,
  `fPowAllowMinDifficultyBlocks = false`, `enforce_BIP94 = false`,
  `BIP34Height/BIP65Height/BIP66Height/CSVHeight/SegwitHeight = 1`,
  `MinBIP9WarningHeight = 0`, deployment TESTDUMMY bit 28 with
  threshold 1815/2016 over a 2016-block period, message-start
  derived from `sha256d(signet_challenge)[:4]`.
- `bitcoin-core/src/kernel/chainparams.cpp:530-558` — regtest
  `consensus.enforce_BIP94 = opts.enforce_bip94;` (operator opt-in).
- `bitcoin-core/src/rpc/mining.cpp:489-493, 1024-1026` —
  `getmininginfo` and `getblocktemplate` emit `signet_challenge` (hex
  of the script) when `m_chain_type == SIGNET`.

**Files audited**
- `src/Haskoin/Consensus.hs` — `Network` record (lines 266-297; no
  `signet_blocks` / `netSignetChallenge` field), `mainnet` (1041-1132),
  `testnet3` (1135-1184), `testnet4` (1187-1237), `regtest`
  (1280-1324); **no signet network at all**; `maxTimewarp = 600`
  (552-553); `getNextWorkRequired` BIP-94 first-block-of-period
  selection (798-799); `calculateNextWorkRequired` (787-834);
  `difficultyAdjustment` (header-chain variant, 3802-3856); `addHeader`
  gate 2 (3973-3982) — BIP-94 time-timewarp-attack reject;
  `validateFullBlock` (2389-2590) — no BIP-94 cross-check, no signet
  check, pre-segwit block-size cap missing (line 2443); `connectBlock`
  / `connectBlockAt` (3027-3199) — no signet hook;
  `computeBlockVersion` (1914-1928) — VERSIONBITS_TOP_BITS;
  `taprootDeployment` (1678-1686) — special-cased on `netName ==
  "main"`; `versionBitsTopBits = 0x20000000` (1648-1649);
  `versionBitsNumBits = 29` (1656-1657); `bitsToTargetFull`
  (612-629) — compact-target decoder.
- `src/Haskoin/BlockTemplate.hs` — `createBlockTemplate` (208-295):
  `minTime = mtp + 1` (line 218), `maxTime = now + 7200` (219),
  `curTime = max minTime now` (220), no BIP-94 floor, no signet
  challenge field on the BlockTemplate; `submitBlock` (472-639) —
  routes through `validateFullBlockIO` (line 544) so it inherits the
  same gaps; `applyBlockToCache` (later) — same.
- `src/Haskoin/Rpc.hs` — `handleGetMiningInfo` (3073-3100): no
  `signet_challenge` field; `handleGetBlockTemplate` (2760-2838) and
  `handleTemplateRequest`: no `signet_challenge` field; `rules` array
  hard-codes `"csv"` and `"!segwit"` (2796) — does not branch on signet;
  `handleBlockProposal` (2851-2869) — **NOOP: always returns success**
  for any decodable block (W155 BUG-5 carry-forward — re-confirmed
  here because signet operators trying to use the BIP-23 proposal
  mode to validate a signet block would get a falsely-positive
  acceptance with no signet check at all); `handleGetBlockchainInfo`
  (1170-1233) — emits `chain` = `netName net`; no `signet_challenge`,
  no `enforce_BIP94` field.
- `src/Haskoin/Daemon.hs` — `networkSection` (326-336) maps a
  config-file `[signet]` header through to a string named "signet",
  but no `Network` value exists named "signet" so any keys under
  `[signet]` are silently dropped on the haskoin side.
- `app/Main.hs` — `NetworkName` enum (80): `Mainnet | Testnet |
  Testnet4 | Regtest` — **no `Signet` constructor**. `optNetwork`
  parser (217): `value Mainnet <> help "Network: Mainnet, Testnet,
  Testnet4, Regtest"`. `runCommand` (381-385) maps `NetworkName ->
  Network`; an attempt to start with `--network Signet` fails the
  enum parse before reaching `runNode`. `-reindex` / `-reindex-chainstate`
  flags (259-267).

---

## Gate matrix (37 sub-gates / 13 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Signet `Network` value present | G1: `signet :: Network` exported | **BUG-1 (P0-CDIV)** — no `signet` value at all in Consensus.hs |
| 1 | … | G2: `NetworkName` enum has `Signet` constructor | **BUG-1 cross-cite** — only Mainnet/Testnet/Testnet4/Regtest |
| 1 | … | G3: `runCommand` dispatches `Signet -> signet` | **BUG-1 cross-cite** |
| 1 | … | G4: config-file `[signet]` section is honoured | **BUG-1 cross-cite** — `networkSection "signet" -> "signet"` is plumbed but no consumer ever filters on it |
| 2 | `CheckSignetBlockSolution` | G5: function exported from a haskoin module | **BUG-2 (P0-CDIV)** — no `checkSignetBlockSolution` exists anywhere in `src/Haskoin/` |
| 2 | … | G6: `SIGNET_HEADER = 0xec 0xc7 0xda 0xa2` constant | **BUG-2 cross-cite** — no such bytes anywhere in the tree |
| 2 | … | G7: `FetchAndClearCommitmentSection` analog | **BUG-2 cross-cite** |
| 2 | … | G8: `SignetTxs.Create` (to_spend / to_sign synthesis) | **BUG-2 cross-cite** |
| 2 | … | G9: `BLOCK_SCRIPT_VERIFY_FLAGS = P2SH|WITNESS|DERSIG|NULLDUMMY` set on signet block validation | **BUG-2 cross-cite** |
| 2 | … | G10: genesis short-circuit (`block.GetHash() == hashGenesisBlock`) | **BUG-2 cross-cite** |
| 3 | `signet_challenge` chain param | G11: `Network` record has a `netSignetChallenge :: ByteString` (or `Maybe Script`) field | **BUG-3 (P0-CDIV)** — Network record has 32 fields, none for signet challenge |
| 3 | … | G12: default-signet challenge bytes wired (matches Core SigNetParams default block) | **BUG-3 cross-cite** |
| 3 | … | G13: `-signetchallenge=<hex>` operator override | **BUG-3 cross-cite** |
| 3 | … | G14: custom-signet genesis hash + magic re-derived from `sha256d(challenge)[:4]` | **BUG-3 cross-cite** |
| 4 | BIP-94 `enforce_BIP94` flag wiring | G15: per-network `netEnforceBIP94 :: Bool` present | PASS (`Consensus.hs:292`) |
| 4 | … | G16: mainnet = False | PASS (`1096`) |
| 4 | … | G17: testnet3 = False | PASS (`1168`) |
| 4 | … | G18: testnet4 = True | PASS (`1221`) |
| 4 | … | G19: regtest = False (operator can override per Core) | PARTIAL — field exists (`1308`); **BUG-4** — no `-enforce_bip94` runtime knob |
| 4 | … | G20: signet field present | **BUG-3 cross-cite** — no signet record |
| 5 | BIP-94 consensus-side timewarp reject | G21: `time-timewarp-attack` fires on first block of each retarget period when timestamp < prev - 600 | PASS — `addHeader` gate 2 (`Consensus.hs:3973-3982`) |
| 5 | … | G22: reject token is byte-identical to Core (`time-timewarp-attack`) | PASS (line 3982) |
| 5 | … | G23: gate runs in `validateFullBlock` too (validation.cpp:4097 is in ContextualCheckBlockHeader which runs on every block-level acceptance, not just header acceptance) | **BUG-5 (P1)** — `validateFullBlock` skips this check entirely; a block-level handoff that bypasses `addHeader` (e.g. side-branch reconstruction after a reorg, future `-reindex` block-by-block replay) would never see the BIP-94 check |
| 6 | BIP-94 miner-side timewarp clamp | G24: template `minTime` includes `prev_block_time - MAX_TIMEWARP` floor at retarget boundary | **BUG-6 (P0-CDIV)** — `BlockTemplate.hs:218` is `minTime = mtp + 1`; no BIP-94 floor. Core comment: *"Account for BIP94 timewarp rule on all networks. This makes future activation safer."* |
| 6 | … | G25: clamp fires on all networks (Core's "all networks" comment) | **BUG-6 cross-cite** — fires on no networks here |
| 7 | `GetNextWorkRequired` BIP-94 first-block-of-period selection | G26: at retarget boundary, use `pindexFirst->nBits` when `enforce_BIP94` | PASS (`Consensus.hs:798-799 + 3842-3845`) |
| 8 | nVersion BIP-9 signaling | G27: top 3 bits = 001 | PASS (`Consensus.hs:1648-1649`) |
| 8 | … | G28: 29-bit version-bits range | PASS (`1656-1657`) |
| 8 | … | G29: STARTED or LOCKED_IN deployments OR-in their bit | PASS (`computeBlockVersion` 1914-1928) |
| 9 | nBits encoding | G30: `SetCompact` semantics (negative + overflow detection) | PASS (`bitsToTargetFull` 612-629) |
| 9 | … | G31: `GetCompact` round-trip + sign-bit shift | PASS (`targetToBits` 644-668) |
| 10 | `fPowAllowMinDifficultyBlocks` testnet rule | G32: 20-minute pass when `timestamp > prev + targetSpacing*2` | PASS (`testnetExpectedBits` 3861-3881 + `testnetMinDifficultyCheck` 758-783) |
| 10 | … | G33: testnet walk-back to last non-min-diff block | PASS (`walkBackToRealDifficulty` 771-783 + `walkBackMinDiff` 3873-3881) |
| 11 | `MAX_FUTURE_BLOCK_TIME` future-time gate | G34: header reject when `timestamp > now + 7200` | PASS (`addHeader` gate 3, `Consensus.hs:3985-3989`) |
| 12 | `getmininginfo` / `getblocktemplate` signet plumbing | G35: `signet_challenge` field emitted on signet chain | **BUG-7 (P2)** — handleGetMiningInfo (3073-3100) does not emit `signet_challenge`. handleTemplateRequest does not emit it either. W123 BUG-7 / BUG-7b carry-forward, second confirmation |
| 12 | … | G36: `rules` array contains `"signet"` on signet chain (mining.cpp:950-958 fleet-wide check) | **BUG-7 cross-cite** — handleTemplateRequest hardcodes `["csv","!segwit"]` (Rpc.hs:2796) |
| 13 | Pre-segwit block-size cap (cross-cite W143 BUG-2 + W154 BUG-1) | G37: pre-segwit blocks rejected when serialized size > 1 MB | **BUG-8 (P0-CONS, carry-forward, 6+ waves)** — `validateFullBlock` line 2443: `when (flagSegWit flags && blockWeight block > maxBlockWeight)`; gate is shape-gated on SegWit, so heights 0..481823 accept arbitrary-size blocks. `maxBlockSize = 1000000` defined at line 459 but **never consulted by the consensus path** |

---

## BUG-1 (P0-CDIV) — Signet network does not exist in haskoin

**Severity:** P0-CDIV (cross-impl divergence; signet operator cannot
even start the node, let alone reach the missing solution-check
code below). Bitcoin Core's `CChainParams::SignetParams` is one of
five first-class network types (`MAIN`, `TESTNET`, `TESTNET4`,
`SIGNET`, `REGTEST`). haskoin has only four: mainnet, testnet3,
testnet4, regtest. There is no `signet :: Network` value in
`Consensus.hs`, no `Signet` constructor in `NetworkName` (`Main.hs:80`),
no signet-genesis-block definition, no signet challenge plumbing.

The config-file parser does map `[signet]` through to a string
(`Daemon.hs:334`), but no `Network` consumer ever filters on it, so
every key in a `bitcoin.conf` `[signet]` section is silently dropped
when running haskoin against a `bitcoin.conf` that the operator
copied from a Core install.

A user attempting `haskoin node --network Signet` is rejected by
the optparse enum BEFORE `runNode` is called. There is no way to
participate in any signet network — public default-signet,
SRF-signet, custom-signet — from haskoin.

**File:** `src/Haskoin/Consensus.hs:266-297, 1041-1324` (only four
networks); `app/Main.hs:80, 217, 381-385` (only four enum cases);
`src/Haskoin/Daemon.hs:334` (config-file plumbing for a section the
rest of the code knows nothing about).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:404-520`
(`SigNetParams`); `bitcoin-core/src/chainparamsbase.cpp` (ChainType
enum has SIGNET as a first-class type).

**Impact:**
- **Operator UX divergence**: a `bitcoin.conf` that includes
  `signet=1` or `chain=signet` cannot be reused with haskoin —
  the optparse layer refuses the value with an enum mismatch
  rather than the more useful "signet not supported in this
  build".
- **Cross-fleet asymmetry**: every other Hashhog impl that has
  any signet support (e.g. rustoshi, blockbrew, etc.) can sync a
  signet chain or at least refuse to start with a clear message.
  haskoin fails opaquely.
- **Carry-forward for BUG-2/BUG-3**: any later fix to add signet
  block-solution checking or signet challenge plumbing depends on
  this gap being closed first.

---

## BUG-2 (P0-CDIV) — `CheckSignetBlockSolution` entirely absent

**Severity:** P0-CDIV (signet-fleet split — the haskoin node, if
ever wired with a signet network value, would accept any
PoW-valid block as a valid signet block, indistinguishable from
mainnet behaviour). Bitcoin Core's `CheckSignetBlockSolution`
(`signet.cpp:126-153`) is the entry point that distinguishes signet
from PoW networks: rather than relying on collision-search to
admit a block, signet requires the coinbase witness commitment to
embed an OP_RETURN-style record introduced by the 4-byte
`SIGNET_HEADER` magic `0xec 0xc7 0xda 0xa2`. That record carries
a scriptSig + scriptWitness that must satisfy the network's
`signet_challenge` script, signed against the modified-merkle
preimage `nVersion || hashPrevBlock || signet_merkle || nTime`.
The script is verified with `BLOCK_SCRIPT_VERIFY_FLAGS = P2SH |
WITNESS | DERSIG | NULLDUMMY` — these are mandatory and any of
them missing would let a malformed signature pass on signet
specifically.

haskoin has **no analog at all**. Grep for `CheckSignet`,
`SIGNET_HEADER`, `0xecc7daa2`, `0xec, 0xc7`, `signetChallenge`,
`SignetTxs` over `src/` and `app/` returns zero hits. The only
references to "signet" in the entire production codebase are the
config-file section name pass-through (`Daemon.hs:324, 334, 345`)
and a one-line comment in the mainnet config (`Consensus.hs:1158`
on testnet3's `netTaprootHeight`). `submitBlock` (`BlockTemplate.hs:484`)
routes through `validateFullBlockIO` which never branches on
signet. Effectively: if a signet `Network` value were defined and
the rest of the fleet were wired, every signet block would be
accepted on the basis of PoW alone — i.e. haskoin would fork off
the signet network at block 1 (since the genesis is the trivial
OP_TRUE challenge, and block 1 immediately differs).

This is the same shape as **blockbrew W143 BUG-9** (P0-CONS signet
— "CheckSignetBlockSolution entirely missing — accepts any
PoW-valid block, forks off signet at block 1"). Fleet pattern:
"signet-CheckSignetBlockSolution-absent" — second confirmed
instance after blockbrew.

**File:** `src/Haskoin/Consensus.hs` (no `checkSignetBlockSolution`
exported); `src/Haskoin/BlockTemplate.hs:472-639` (`submitBlock`
never branches on signet); `src/Haskoin/Sync.hs:340-460`
(`blockProcessor` never branches on signet).

**Core ref:** `bitcoin-core/src/signet.cpp:28, 30, 32-57, 59-68,
70-123, 126-153`.

**Impact:**
- **Hard chain split at signet block 1** (default-signet) and at
  every custom-signet block 1. The only way for haskoin to ever
  produce an interoperable signet sync is to also fix BUG-1 and
  BUG-3 (and then the operator has to wait for this fix).
- **Fleet-wide pattern**: cross-cites blockbrew W143 BUG-9.
- **Test gap**: no `WNNNSignetSpec.hs` exists in `test/` either —
  the audit-only test surface for signet is zero. (Test list at
  `test/W141ZmqRestNotifySpec.hs`, `W138AssumeUTXOSpec.hs`, etc.
  shows ~50 wave specs; none mention signet.)

---

## BUG-3 (P0-CDIV) — `signet_challenge` chain parameter not modelled

**Severity:** P0-CDIV. Bitcoin Core's
`Consensus::Params::signet_challenge` (`consensus/params.h:140`) is
the per-network payload that drives signet block-solution checking
(see BUG-2). For default signet, Core hard-codes a 41-byte multisig
script; for custom signet, it's set via `-signetchallenge=<hex>`
during chainparams construction. The challenge is also used to
derive `pchMessageStart` (`sha256d(signet_challenge)[:4]`) so that
custom-signet shards do not collide on the wire.

haskoin's `Network` record (`Consensus.hs:266-297`) has 32 fields
covering name, magic, ports, address prefixes, PoW limit, target
spacing/timespan, retarget interval, halving, coinbase maturity,
genesis block, BIP heights, taproot, DNS seeds, checkpoints,
allow-min-diff, no-retargeting, BIP94, min-chainwork,
headers-sync params, assumeUTXO, and assumeValid. There is **no
field for signet challenge** and no field for `signet_blocks`
(Core's boolean that gates the whole signet code path —
`Consensus::Params::signet_blocks` at `consensus/params.h:139`).

Even if BUG-1/BUG-2 were partly fixed (Signet network value +
solution-check function), without this field there is no way to
pass the challenge bytes into `CheckSignetBlockSolution`, no way
to differentiate default-signet from custom-signet on the wire
(magic + genesis would have to come from somewhere else), no way
to surface `signet_challenge` in `getmininginfo` /
`getblocktemplate` (Core mining.cpp:489-493, 1024-1026 → W123
BUG-7 carry-forward).

**File:** `src/Haskoin/Consensus.hs:266-297` (Network record);
absent from all four network value definitions (1041-1324).

**Core ref:** `bitcoin-core/src/consensus/params.h:139-140`
(`signet_blocks`, `signet_challenge`);
`bitcoin-core/src/kernel/chainparams.cpp:432-478` (default + custom
challenge resolution + magic derivation).

**Impact:**
- Custom-signet operator override (`-signetchallenge=<hex>`) is
  inexpressible.
- Default-signet challenge bytes have to be hardcoded into the
  one site that uses them rather than living in the chainparams.
- W123 BUG-7 / BUG-7b stay open forever — the field they request
  haskoin emit through `getmininginfo` / GBT does not exist.

---

## BUG-4 (P1) — Regtest `-enforce_bip94` runtime override absent

**Severity:** P1. Core's `kernel/chainparams.cpp:547` sets
`consensus.enforce_BIP94 = opts.enforce_bip94;` for regtest,
honouring a `-enforce_bip94=1` operator switch. This is how a
local regtest test exercises the BIP-94 timewarp reject path
without needing testnet4. haskoin's regtest record hard-codes
`netEnforceBIP94 = False` (`Consensus.hs:1308`) with no runtime
override hook — there is no `-enforce_bip94` flag in
`parseOptions` (`Main.hs:135-330`).

The consequence is that the BIP-94 timewarp reject (`addHeader`
gate 2, `Consensus.hs:3973-3982`) cannot be exercised on regtest;
every regtest BIP-94 test must instead spin up a fake testnet4
chain, which complicates harness setup and prevents the
test-suite from using the cheap regtest insta-mining path to
drive the gate.

**File:** `src/Haskoin/Consensus.hs:1308` (regtest BIP94 = False,
fixed); `app/Main.hs:135-330` (parseOptions, no `-enforce_bip94`
flag).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:547`;
`bitcoin-core/src/init.cpp` (`-enforce_bip94` arg parse for
regtest).

**Impact:** test ergonomics; cross-impl divergence in regtest
behaviour matrix. Not a consensus bug because the only network
where `enforce_BIP94` is meaningfully `true` (testnet4) is
correctly handled.

---

## BUG-5 (P1) — `validateFullBlock` does not re-run the BIP-94 timewarp gate

**Severity:** P1 ("two-pipeline guard 18th distinct extension" — the
header-level path and the full-block path disagree on BIP-94
enforcement scope; first time the BIP-94 reject is the divergent
gate). Bitcoin Core's `ContextualCheckBlockHeader` (`validation.cpp:4080-4121`)
is invoked from BOTH `AcceptBlockHeader` (header-only acceptance) AND
`AcceptBlock` (full-block path, where it's a re-check before
`ConnectBlock`). The BIP-94 timewarp reject at line 4097-4104 fires
in both contexts.

haskoin's BIP-94 check lives only in `addHeader`
(`Consensus.hs:3973-3982`) — i.e. only on the header-acceptance
path. `validateFullBlock` (`Consensus.hs:2389-2590`) explicitly
implements many of the ContextualCheckBlockHeader gates (BIP-34
nVersion at 2423-2436, MTP at 2456-2462, etc.) but skips the
BIP-94 timewarp gate entirely. The implicit assumption is that
every block that reaches `validateFullBlock` has already been
through `addHeader` — but:

- `submitBlock` (`BlockTemplate.hs:484-639`) routes through
  `validateFullBlockIO` (line 544); the corresponding `addHeader`
  call is at line 633, **after** validation succeeds. A
  caller-introduced reordering, or a future side-branch storage
  path that registers the header via `addSideBranchHeader`
  (Consensus.hs:4106-4133) which bypasses gates 1-7 by design,
  could deliver a block to `validateFullBlock` whose BIP-94 status
  was never checked.
- `addSideBranchHeader` documents explicitly that it "does NOT
  re-run difficulty / MTP / PoW / checkpoint validation: the
  caller has already done that" (line 4098-4103). The "already
  done that" assumption is a textbook two-pipeline carry-forward
  invariant — any future caller that skips the validation
  pre-step also skips BIP-94.
- A future `-reindex` block-by-block replay path that reads
  blocks from disk and pipes them straight into `validateFullBlock`
  would silently skip BIP-94.

Core mitigates this by running ContextualCheckBlockHeader inside
the block-acceptance pipeline too. haskoin should mirror.

**File:** `src/Haskoin/Consensus.hs:2389-2590` (`validateFullBlock`
— no `enforce_BIP94 && height % retargetInterval == 0` check);
gate is present in `addHeader` only (3973-3982).

**Core ref:** `bitcoin-core/src/validation.cpp:4080-4121`
(`ContextualCheckBlockHeader` is invoked from AcceptBlockHeader
AND AcceptBlock — the latter at validation.cpp ~line 4321 via the
`ContextualCheckBlockHeader` call inside `AcceptBlock`).

**Excerpt (haskoin, scope gap)**

```haskell
-- Consensus.hs:2422-2440 (validateFullBlock):
let blockVer = bhVersion header
when (flagBIP34 flags && blockVer < 2) $
  Left $ "bad-version(0x" ++ ...
when (flagBIP66 flags && blockVer < 3) $ ...
when (flagBIP65 flags && blockVer < 4) $ ...

-- Consensus.hs:2456-2462 (validateFullBlock, MTP):
when (height > 0 && bhTimestamp header <= csMedianTime cs) $
  Left "timestamp not after median time past"

-- MISSING (Core validation.cpp:4097-4104, BIP-94):
-- if (consensusParams.enforce_BIP94 &&
--     nHeight % DifficultyAdjustmentInterval == 0 &&
--     block.GetBlockTime() < pindexPrev.GetBlockTime() - MAX_TIMEWARP)
--   reject "time-timewarp-attack"
```

**Impact:**
- Anti-DoS depth-of-defence gap: a single addHeader bypass
  becomes a consensus bypass instead of a noisy double-check.
- Future-fix-recursion: if BUG-1/BUG-2/BUG-3 are addressed and
  signet runs through a different acceptance path that doesn't
  use `addHeader`, BIP-94 would slip through on signet (Core
  doesn't enforce_BIP94 on signet, so the gate would be a no-op
  on signet specifically — but the same shape on a future
  network with enforce_BIP94=true bites).

---

## BUG-6 (P0-CDIV) — Miner `minTime` lacks the BIP-94 floor

**Severity:** P0-CDIV. Bitcoin Core's `GetMinimumTime`
(`node/miner.cpp:36-47`) clamps the miner's minimum-time-for-new-block
to `max(MTP+1, prev_block_time - MAX_TIMEWARP)` whenever the new
block is the first block of a difficulty-adjustment interval. The
critical detail is the Core code comment on line 41-42:

> Account for BIP94 timewarp rule on all networks. This makes
> future activation safer.

i.e. the miner clamp fires on **every** network — mainnet,
testnet3, testnet4, signet, regtest — regardless of whether
`consensus.enforce_BIP94` is set. The rationale is forward-safety:
a template produced today for mainnet (where `enforce_BIP94`
is currently `false`) should be valid against a hypothetical
future mainnet activation. Without the floor, a mining template
generated by Core right before an enforce_BIP94 activation could
be invalid against post-activation rules.

haskoin's `createBlockTemplate` (`BlockTemplate.hs:218-220`) sets:

```haskell
let mtp = medianTimePast entries prevHash
    minTime = mtp + 1
    maxTime = now + 7200  -- current time + 2 hours
    curTime = max minTime now
```

There is no clamp against `prev_block_time - 600`. Every haskoin
template — including testnet4 templates, where BIP-94 is
consensus-active — can emit a `mintime` below the BIP-94 floor.
On testnet4 specifically, a miner consuming such a template and
producing a block whose `nTime` matches the suggested `mintime`
would have the block rejected with `time-timewarp-attack` by
peers (and by haskoin's OWN `addHeader` gate, see BUG-7).

The `btCurTime` exposed at line 287 is also wrong on the same
basis: `curTime = max minTime now` does not clamp to the BIP-94
floor, so any haskoin-derived auto-time on a testnet4 boundary
block can produce an invalid block.

This is a NEW fleet pattern this wave: **"miner-clamp-missing-BIP-94-floor"**.
Cross-cites W143 BUG-10 (hotbuns missing BIP-94 in validateBlockHeader
DEAD code path) and W154 BUG-7 (camlcoin missing BIP-94 in template
construction).

**File:** `src/Haskoin/BlockTemplate.hs:217-220`
(`createBlockTemplate`, minTime/curTime); also lines 287-289
(template fields).

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47`
(`GetMinimumTime` BIP-94 floor on all networks).

**Excerpt (haskoin, missing floor)**

```haskell
-- BlockTemplate.hs:215-220:
entries <- readTVarIO (hcEntries hc)
now <- (round :: Double -> Word32) . realToFrac <$> getPOSIXTime
let mtp = medianTimePast entries prevHash
    minTime = mtp + 1                  -- MISSING the BIP-94 floor
    maxTime = now + 7200
    curTime = max minTime now          -- inherits the gap

-- Should be (Core parity):
-- let isBoundary = (height `mod` netRetargetInterval net) == 0
--     bip94Floor = if isBoundary
--                  then fromIntegral (bhTimestamp (ceHeader tip)) - 600
--                  else 0
--     minTime = max (mtp + 1) (fromIntegral bip94Floor)
```

**Impact:**
- **Self-rejection on testnet4 boundary blocks**: a miner that
  consumes the template and picks any timestamp ≤ `btMinTime`
  produces a block that haskoin's own `addHeader` will reject
  (Consensus.hs:3973-3982).
- **Future-safe gap on mainnet/regtest**: if and when mainnet
  ever activates BIP-94 (or regtest is started with
  `-enforce_bip94`), all extant haskoin templates become
  retroactively wrong.
- Fleet pattern: aligns haskoin with camlcoin W154 BUG-7 and
  hotbuns W143 BUG-10 — third fleet instance of the
  "miner-clamp-missing-BIP-94-floor" gap.

---

## BUG-7 (P0-CDIV) — Template `mintime` reports an invalid value on testnet4 retarget boundaries

**Severity:** P0-CDIV (interop / spec). `getblocktemplate`'s
`mintime` field is documented (`bitcoin-core/src/rpc/mining.cpp`
GBT result, BIP22) as "the minimum timestamp appropriate for next
block time" — i.e. the SMALLEST `nTime` a miner is permitted to
pick. On Core, this is the output of `GetMinimumTime` (miner.cpp:36-47),
which is BIP-94 aware on all networks.

`handleTemplateRequest` (`Rpc.hs:2825`) emits `btMinTime bt` as the
`mintime` field. As BUG-6 establishes, `btMinTime` is `mtp + 1`
without the BIP-94 floor. A miner querying `getblocktemplate` on
testnet4 at a difficulty-adjustment boundary, picking
`mintime` exactly, and submitting the result via `submitblock`
gets a `time-timewarp-attack` rejection. This is a contract
violation: the GBT field promises validity, the resulting block
is invalid.

A correctly-implemented miner that picks `max(mintime, NOW)`
silently dodges the bug almost always (because NOW is normally
≥ the BIP-94 floor). But a regression-test miner that wants
`exactly mintime` to drive deterministic test vectors hits the
contract violation every time.

**File:** `src/Haskoin/Rpc.hs:2825` (mintime field emit);
`src/Haskoin/BlockTemplate.hs:218` (`btMinTime` derivation).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp` (GBT mintime field
sourced from BlockAssembler::m_options.coinbase_output_time or
chain.GetMTP — both flowing through GetMinimumTime).

**Impact:**
- Test-vector mining at boundary blocks fails interop.
- Cross-impl GBT response can disagree with Core on the exact
  same chain state, by 600 or fewer seconds.

---

## BUG-8 (P0-CONS, carry-forward, 6+ waves) — Pre-segwit blocks accept arbitrary size

**Severity:** P0-CONS. **Re-confirmation of W143 BUG-2 + W154 BUG-1**.
Bitcoin Core's `MAX_BLOCK_BASE_SIZE = 1_000_000` legacy cap
(`bitcoin-core/src/consensus/consensus.h`) is enforced UNCONDITIONALLY
on every block via `CheckBlock`/`ContextualCheckBlock`. The
post-SegWit weight cap (`MAX_BLOCK_WEIGHT = 4_000_000`) is an
ADDITIONAL constraint — both apply once SegWit is active, but the
1 MB base cap was the only block size limit pre-SegWit and stays
the floor afterward (weight 4M / 4 = 1M base equivalent for
non-witness blocks).

haskoin's `validateFullBlock` enforces only the weight check, and
it is **shape-gated** on SegWit activation (`Consensus.hs:2443`):

```haskell
-- 4. Check block weight (only after SegWit activation)
when (flagSegWit flags && blockWeight block > maxBlockWeight) $
  Left "Block exceeds maximum weight"
```

For all mainnet heights below 481824 (SegWit activation),
`flagSegWit` is `False` and the entire block-size check is
skipped. There is no separate `maxBlockSize` enforcement
anywhere on the consensus path. The constant `maxBlockSize =
1000000` exists at `Consensus.hs:459` and is exported, but a
full grep for callers in `src/` shows zero — it is dead data.

This was originally identified in:
- **W143 BUG-2 (P0-CONS, May 18)**: "pre-segwit blocks have NO
  size cap (flagSegWit gates entire weight check; maxBlockSize=1MB
  DEAD; heights 0..481823 accept arbitrary-size; carry-forward W142)"
- **W154 BUG-1 (P0-CONS)**: same gap on the mining template side
- The hashhog repo MEMORY notes the carry-forward stack at length:
  "haskoin W143 BUG-2 P0-CONS pre-segwit no size cap on mining
  template" + 6+ waves open.

This W157 audit re-confirms the gap from a new angle (signet/BIP-94
audit) because:
1. The pre-segwit-no-size-cap interacts with the missing
   `CheckSignetBlockSolution` (BUG-2): even if a signet block were
   constructed today, the signet challenge-script payload (Core's
   `signet_solution` bytes) sits inside the witness commitment
   OP_RETURN — a malformed challenge could push the coinbase
   scriptPubKey large enough to overflow the 1 MB cap, and
   haskoin would silently accept the bloated coinbase on the
   pre-segwit code path.
2. The gap also voids BIP-94's miner-clamp protections: a
   testnet4 (which IS post-SegWit, so the shape gate is fine
   there) regression-test that wants to span a regtest scenario
   from height 0 onwards through SegWit activation cannot
   exercise the cap correctly because the cap is the wrong shape
   below SegWit.

**File:** `src/Haskoin/Consensus.hs:2443` (the shape gate).

**Core ref:** `bitcoin-core/src/validation.cpp` (CheckBlock,
unconditional 1 MB base-size check via the serialized size of the
block bytes).

**Impact:**
- **Mainnet chain split with Core on a reorg that crosses a
  hypothetical too-large pre-SegWit block**: such blocks exist
  only in the test corpus today, but a deep reorg that included
  one would fork off Core.
- **Cross-fleet carry-forward**: 6+ waves open. The fix is
  ~3 lines: drop the `flagSegWit` gate, or add a parallel
  unconditional `when (blockBaseSize block > maxBlockSize) $
  Left "bad-blk-length"` guard above the weight check.

---

## BUG-9 (P0-CDIV, carry-forward) — `handleBlockProposal` accepts any decodable block

**Severity:** P0-CDIV ("comment-as-confession" + W155 BUG-5
carry-forward, 2nd wave). `handleBlockProposal` at
`Rpc.hs:2851-2869`:

```haskell
handleBlockProposal :: RpcServer -> Value -> IO RpcResponse
handleBlockProposal server params = do
  case extractProposalData params of
    Nothing -> ... "Missing data String key for proposal" ...
    Just hexBlock -> do
      case B16.decode (TE.encodeUtf8 hexBlock) of
        Left err -> ... "Block decode failed" ...
        Right blockBytes -> do
          case S.decode blockBytes :: Either String Block of
            Left err -> ... "Block decode failed" ...
            Right block -> do
              -- For proposal mode, we just validate the block structure
              -- In a full implementation, we'd check PoW, merkle root, etc.
              -- and return appropriate BIP22 rejection reason
              return $ RpcResponse Null Null Null  -- null means accepted
```

Core's `submitblock` with `"mode": "proposal"` (BIP-23) is
supposed to run the FULL block-acceptance pipeline (CheckBlock +
ContextualCheckBlock + ConnectBlock dry-run) and return a BIP-22
result string — including, on signet, the
`CheckSignetBlockSolution` result. haskoin returns "accepted"
for any decodable block of any shape, on any chain. The inline
comment ("In a full implementation, we'd check PoW, merkle root,
etc.") is a textbook **comment-as-confession** (fleet pattern,
recorded ~8 distinct haskoin instances by W156).

For signet-fleet-pattern interaction (W157 scope): even if BUG-2
(`CheckSignetBlockSolution` absent) were fixed, the proposal-mode
RPC would still ignore the new check. A signet operator using
`bitcoin-cli submitblock ... '{"mode":"proposal"}'` to dry-run a
candidate block gets a falsely-positive "accepted" verdict.

**File:** `src/Haskoin/Rpc.hs:2851-2869`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::submitblock`
(proposal mode dispatches through TestBlockValidity which runs
the same checks as AcceptBlock).

**Impact:**
- BIP-23 is non-functional.
- W155 BUG-5 stays open; this is the 2nd-wave carry-forward
  re-confirmation.

---

## BUG-10 (P1) — `taprootDeployment` special-cases only mainnet on `netName == "main"`

**Severity:** P1 (fleet pattern: string-compare on netName is a
brittle alternative to a typed `m_chain_type` discriminator).
`Consensus.hs:1678-1686`:

```haskell
taprootDeployment :: Network -> Deployment
taprootDeployment net = Deployment
  { depBit = 2
  , depStartTime = if netName net == "main" then 1619222400 else deploymentAlwaysActive
  , depTimeout = if netName net == "main" then 1628640000 else maxBound
  , depMinActivationHeight = if netName net == "main" then 709632 else 0
  , depPeriod = 2016
  , depThreshold = if netName net == "main" then mainnetThreshold else testnetThreshold
  }
```

For testnet3/testnet4/regtest/(future signet), the deployment is
`deploymentAlwaysActive` — Taproot is considered active from
genesis. For testnet3 specifically, this is **wrong**: Core's
testnet3 Taproot activated by BIP-9 with a real (NEVER_ACTIVE)
start time so the deployment never activated. For signet, Core
runs the TESTDUMMY BIP-9 deployment (bit 28, start NEVER_ACTIVE,
period 2016, threshold 1815/2016, min_activation_height 0) — not
"always active Taproot at bit 2".

The string-compare on `netName == "main"` is also a fleet
pattern weakness that would have to be re-audited if a Signet
network were ever added (BUG-1): a naive add would set
`netName = "signet"` and silently fall into the
`deploymentAlwaysActive` else-arm, mis-modelling signet's BIP-9
state machine.

**File:** `src/Haskoin/Consensus.hs:1678-1686`.

**Core ref:** `bitcoin-core/src/deploymentinfo.cpp` + the
per-network `vDeployments` tables in `kernel/chainparams.cpp`.

**Impact:**
- `getdeploymentinfo` reports wrong state on testnet3 (always
  active vs Core's failed).
- Forward-trap for a future Signet add (BUG-1).

---

## BUG-11 (P1) — `versionBitsTopMask` only checks top 3 bits, no `versionBitsTopBits` mismatch surface

**Severity:** P1. `Consensus.hs:1648-1657`:

```haskell
versionBitsTopBits = 0x20000000
versionBitsTopMask = 0xe0000000
versionBitsNumBits = 29
```

The pattern is right (Core: `VERSIONBITS_TOP_BITS = 0x20000000U,
VERSIONBITS_TOP_MASK = 0xE0000000UL, VERSIONBITS_NUM_BITS = 29`).
But `addHeader` never rejects a header whose top 3 bits are NOT
`001` — `validateFullBlock` rejects nVersion < {2,3,4} for the
BIP-34/66/65 hard-cutover gates (lines 2430-2436), but a block
with `nVersion = 0x10000000` (top 3 bits = `000`, satisfies
nVersion ≥ 4 numerically) passes those gates yet does not signal
the version-bits family at all. Core treats this as
non-signaling but valid (which haskoin matches), so this isn't
necessarily wrong — but it's worth recording that
`versionBitsTopBits` is exported and re-exported as a public API
(line 176) yet never used in a validation reject path. It's a
dead constant outside `computeBlockVersion`.

**File:** `src/Haskoin/Consensus.hs:1648-1657, 1689-1693`.

**Impact:** none functionally; documentation gap; potential
trip-wire for a future BIP-N that wants to gate on top-bits
shape.

---

## BUG-12 (P2) — `MAX_FUTURE_BLOCK_TIME` enforced only in `addHeader`, not in `validateFullBlock`

**Severity:** P2. Same shape as BUG-5. `addHeader`'s gate 3
(`Consensus.hs:3985-3989`) rejects headers whose timestamp is
more than 2 hours in the future. `validateFullBlock` does not
re-check. By Core's design, `ContextualCheckBlockHeader` runs in
both paths, and the future-time gate fires in both.

The future-time gate is anti-DoS, not consensus, so the
two-pipeline gap is lower severity than BUG-5. But the same
trip-wire applies: any caller path that produces a block for
`validateFullBlock` without first running `addHeader` —
`addSideBranchHeader` documented bypass, future `-reindex`
block-by-block replay — bypasses the gate.

**File:** `src/Haskoin/Consensus.hs:2389-2590` (no
`maxFutureBlockTime` check); `addHeader` only at 3985-3989.

**Core ref:** `bitcoin-core/src/validation.cpp:4108-4110`.

**Impact:** anti-DoS depth-of-defence gap; same flavour as BUG-5.

---

## BUG-13 (P1) — STANDARD_SCRIPT_VERIFY_FLAGS entirely absent (W144 BUG-3 carry-forward, 5+ waves)

**Severity:** P1 (carry-forward). The MEMORY index for the W142-W145
quad explicitly calls out: **"haskoin missing ALL 14 STANDARD bits"**
on the W144 script-verify-flags audit, and notes "10 of 21 flag enum
members defined-and-consulted-but-never-emitted". This W157 audit
re-confirms the surface from the BIP-94 angle: the signet block
solution's `BLOCK_SCRIPT_VERIFY_FLAGS = P2SH | WITNESS | DERSIG |
NULLDUMMY` (signet.cpp:30) intersects with the STANDARD set on
NULLDUMMY (a standardness flag historically; treated as
consensus-mandatory in `BLOCK_SCRIPT_VERIFY_FLAGS` for signet).
A future fix to add `CheckSignetBlockSolution` (BUG-2) will need
NULLDUMMY in the flag set; if it's pulled from a partial
STANDARD set that's missing it, the resulting check is laxer than
Core's.

This is recorded here as a forward-trap for the BUG-2 fix path,
not a new finding.

**File:** `src/Haskoin/Script.hs` (per W144 audit).

**Core ref:** `bitcoin-core/src/policy/policy.h` (STANDARD set)
+ `bitcoin-core/src/signet.cpp:30` (BLOCK_SCRIPT_VERIFY_FLAGS).

**Impact:** depends on whether BUG-2 lands first or BUG-13 does.

---

## BUG-14 (P2) — `submitBlock` reject token "Block validation failed: " + err breaks BIP-22 wire-parity

**Severity:** P2 (reject-string wire-parity slippage — fleet
pattern, 10th distinct haskoin instance per MEMORY tracking).
`BlockTemplate.hs:546`:

```haskell
Left err -> return $ Left $ "Block validation failed: " ++ err
```

Core's `submitblock` returns the bare BIP-22 reject string
(e.g. `"bad-cb-amount"`, `"high-hash"`, `"time-timewarp-attack"`).
haskoin prefixes with `"Block validation failed: "` which is then
fed into `bip22ResultString` (`Rpc.hs:2910+`). For most pre-known
tokens the canonical match still works because the prefix is
stripped (line 2934 elemof-check). But a token Core ever adds
that haskoin's bip22 mapper does NOT pre-recognise (e.g. a
hypothetical future `bad-signet-solution`) would land in the
free-form fallback path and be exposed to the client with the
non-canonical prefix.

For signet specifically (BUG-2 forward-fix): when
`CheckSignetBlockSolution` is added, the reject token must be
exactly `"bad-signet-blksig"` (per Core's
`CheckSignetBlockSolution` log message). If `validateFullBlock`
or `submitBlock` re-wraps it, the BIP-22 contract is violated.

**File:** `src/Haskoin/BlockTemplate.hs:546`.

**Core ref:** Core's submitblock returns the BIP-22 string
unmodified.

**Impact:** wire-parity / monitoring; cosmetic until BUG-2 lands,
then a forward-trap.

---

## BUG-15 (P2) — `extractProposalData` only accepts the first array element with a `data` key

**Severity:** P2. `Rpc.hs:2881-2887`:

```haskell
extractProposalData :: Value -> Maybe Text
extractProposalData (Array arr) = case V.toList arr of
  (Object obj : _) -> case KM.lookup "data" obj of
    Just (String s) -> Just s
    _ -> Nothing
  _ -> Nothing
extractProposalData _ = Nothing
```

BIP-23's `getblocktemplate` `data` parameter is the hex-encoded
block. The parser pulls only from the first array element. Core
also accepts the data key inside the templaterequest object,
which haskoin also handles via the first-arg branch. The narrow
form is correct, but the parser silently drops non-Object first
arguments (e.g. a raw string array), which is non-Core-compliant.

Listed for completeness; signet-relevant because BIP-23 proposal
mode is the most likely path a signet operator uses to
pre-validate a signed block before submitting.

**File:** `src/Haskoin/Rpc.hs:2881-2887`.

**Impact:** BIP-23 spec compliance; minor.

---

## BUG-16 (P1) — `compute­BlockVersion` walks back at most 2016 entries — fine but missing fleet-pattern `maxLookback` audit log

**Severity:** P1 (operability). `Consensus.hs:1973`:

```haskell
maxLookback = 2016
```

`computeBlockVersionFromChain` walks back exactly one BIP-9
period. This is correct for BIP-9 signal-counting at a retarget
boundary — but Core also checks `MinBIP9WarningHeight` (per-network
in chainparams; signet sets it to 0; mainnet sets it to 0 too) to
gate the "unknown deployment activated" UI warning. haskoin has
no `MinBIP9WarningHeight` analog; the warnings array in
`getmininginfo` / `getblockchaininfo` always reports `[]` or `""`
(Rpc.hs:3098 line `pair "warnings" (text "")`).

For signet-fleet-relevance: signet activates new deployments
frequently (the whole point of signet) and operators rely on the
"unknown new rules activated" warning. haskoin would never
surface it.

**File:** `src/Haskoin/Consensus.hs:1973`; `src/Haskoin/Rpc.hs:3098,
1231`.

**Core ref:** `bitcoin-core/src/validation.cpp` `WarningBitsConditionChecker`
+ `getblockchaininfo` warnings field.

**Impact:** monitoring gap on signet's primary use case.

---

## BUG-17 (P1) — `maxBlockSize = 1000000` is a dead export

**Severity:** P1 ("dead-data plumbing" — fleet pattern, ~12th
distinct haskoin instance per MEMORY index). `Consensus.hs:23`
exports `maxBlockSize` to consumers; `Consensus.hs:458-459`
defines it as `1000000`. `BlockTemplate.hs:23` re-imports it via
the long import list (around line 70). A full grep over `src/`
for uses returns:
- the definition itself (459)
- the export (23)
- no caller invocations

Cross-cite BUG-8: this is exactly the constant that should be
guarding pre-segwit block size. The export-but-no-call shape is
the classic "already-exports-the-primitive-just-not-called"
fleet pattern (5+ haskoin instances per MEMORY).

**File:** `src/Haskoin/Consensus.hs:23, 458-459`.

**Impact:** depends on whether BUG-8 lands (using maxBlockSize)
or is fixed differently (then maxBlockSize stays dead).

---

## BUG-18 (P1) — `bip30ExceptionHeight` is mainnet-only; no signet/testnet4/regtest stub

**Severity:** P1. `Consensus.hs:3237-3242` hardcodes the two
mainnet BIP-30 exception heights (91722, 91812) and returns
`Nothing` for any other height. This is correct for mainnet but
ignores the per-network nature of the BIP-30 anchor (Core uses
`BIP34Hash` as the anchor for skipping BIP-30 from
`BIP34Height` onward — see haskoin's `netBIP34Hash` field at
line 282 and the testnet4 zero-hash comment at line 1207-1208).

For signet (BUG-1 forward), Core's `BIP34Hash` is `uint256{}`
(default), `BIP34Height = 1`, so BIP-30 stays enforced post-1.
haskoin's `bip30ExceptionHeight` returning `Nothing` happens to
work for signet, but the design is brittle: a hardcoded
2-element function rather than a per-network table.

**File:** `src/Haskoin/Consensus.hs:3237-3242`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:88-90`
(mainnet `BIP34Hash`).

**Impact:** documentation / fleet hygiene; no consensus risk
today.

---

## BUG-19 (P1) — `handleGetBlockchainInfo` does not emit `enforce_BIP94` or `signet_challenge` in softforks/info

**Severity:** P1 (monitoring divergence; cross-cite W123 BUG-7).
`Rpc.hs:1170-1233` emits chain/blocks/headers/bestblockhash/...
but no:
- `enforce_BIP94` flag,
- `signet_challenge` hex (BUG-3 cross-cite),
- `chain` is reported as the haskoin `netName` (`"testnet4"`,
  `"main"`, etc.) — Core uses `"main"`, `"test"`, `"testnet4"`,
  `"signet"`, `"regtest"`. **haskoin emits `"testnet3"` where
  Core emits `"test"`** — a wire-parity slippage (would have to
  be cross-cited against W125 RPC error parity for the official
  fleet count).

Verify: `Consensus.hs:1137` sets `netName = "testnet3"` for
testnet3. `Daemon.hs:330-331` maps both `"testnet"` and
`"testnet3"` → `"test"` for the config-file section. But the
`getblockchaininfo` `chain` field is sourced from `netName`
directly (`Rpc.hs:1215`). So a Core-compatible monitoring tool
reading the field gets `"testnet3"` from haskoin and `"test"`
from Core for the same network.

**File:** `src/Haskoin/Rpc.hs:1215`; cross-cite
`src/Haskoin/Consensus.hs:1137`.

**Core ref:** `bitcoin-core/src/util/chaintype.cpp::ChainTypeToString`.

**Impact:** monitoring tools depending on Core's chain-name
contract break when pointed at haskoin.

---

## Summary

**Bug count:** 19 (BUG-1 through BUG-19).

**Severity distribution:**
- **P0-CDIV:** 7 (BUG-1, BUG-2, BUG-3, BUG-5 reclassified P1,
  BUG-6, BUG-7, BUG-9)
  - Actually: BUG-5 is P1. Recount P0-CDIV: BUG-1, BUG-2,
    BUG-3, BUG-6, BUG-7, BUG-9 = 6.
- **P0-CONS:** 1 (BUG-8 — carry-forward)
- **P1:** 9 (BUG-4, BUG-5, BUG-10, BUG-11, BUG-13, BUG-16,
  BUG-17, BUG-18, BUG-19)
- **P2:** 3 (BUG-12, BUG-14, BUG-15)

Total: 6 + 1 + 9 + 3 = 19. ✓

**Fleet patterns confirmed or extended:**
- **"signet-CheckSignetBlockSolution-absent"** (BUG-2) — 2nd
  fleet instance after blockbrew W143 BUG-9 (signet split at
  block 1).
- **"signet-Network-not-modelled"** (BUG-1) — NEW pattern this
  wave; haskoin is the first impl audited at this depth where
  the signet network value itself is absent (rather than just
  partly wired). Companion to BUG-3 "signet_challenge chain
  param absent".
- **"miner-clamp-missing-BIP-94-floor"** (BUG-6) — 3rd fleet
  instance after camlcoin W154 BUG-7 and hotbuns W143 BUG-10.
- **"two-pipeline guard 18th distinct extension"** (BUG-5) —
  BIP-94 header gate vs validateFullBlock gate disagree on
  scope. 1st time the divergent gate is BIP-94 specifically.
- **"comment-as-confession"** (BUG-9 inline comment "In a full
  implementation, we'd check PoW, merkle root, etc.") — ~9th
  distinct haskoin instance per MEMORY tracking.
- **"already-exports-the-primitive-just-not-called"** (BUG-17,
  `maxBlockSize` exported but no caller) — 6th+ haskoin
  instance.
- **"dead-data plumbing"** (BUG-17 + the config-file `[signet]`
  section pass-through in Daemon.hs) — ~13th distinct haskoin
  instance.
- **"shape-gated NOT flag-gated"** (BUG-8 line 2443) — same
  shape as W144 lunarblock BUG-3/4 cluster (native P2W*/TR
  dispatch SHAPE-gated not FLAG-gated). First haskoin instance
  in this taxonomy.
- **"reject-string wire-parity slippage"** (BUG-14) — ~10th
  haskoin instance per MEMORY tracking.
- **"carry-forward re-anchor"** — BUG-8 (W143 BUG-2 + W154
  BUG-1, 6+ waves), BUG-9 (W155 BUG-5), BUG-13 (W144 BUG-3, 5+
  waves), BUG-19 wire-parity adjacency to W125 sweep.

**Top three findings:**
1. **BUG-1+BUG-2+BUG-3 cluster (P0-CDIV signet trio)** — signet
   support is totally absent (no Network value, no
   CheckSignetBlockSolution, no signet_challenge field). Fixing
   any one alone is insufficient. The cluster is the haskoin
   equivalent of blockbrew W143 BUG-9 escalated by two more
   layers (blockbrew at least has a SIGNET chainparams shell;
   haskoin has nothing). On a signet chain haskoin forks at
   block 1.
2. **BUG-6 (P0-CDIV miner-side BIP-94 floor missing)** — the
   miner template's `minTime` and `curTime` don't include the
   `prev_block_time - MAX_TIMEWARP` clamp, so testnet4
   boundary blocks emitted by the haskoin miner can be invalid
   against haskoin's OWN consensus check (BIP-94 reject in
   `addHeader`). Cross-cites W154 BUG-7 (camlcoin) and W143
   BUG-10 (hotbuns) — 3rd fleet instance of the
   miner-clamp-missing-BIP-94-floor gap.
3. **BUG-8 (P0-CONS pre-segwit no size cap, 6+ wave
   carry-forward)** — re-confirmed from a new angle for the
   ~6th time. Pre-SegWit blocks (heights 0..481823 on mainnet)
   have no size limit enforced at all because
   `validateFullBlock`'s weight check is shape-gated on
   `flagSegWit`. The 1 MB `maxBlockSize` constant exists, is
   exported, and is never called from any consensus path.
