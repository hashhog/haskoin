# W155 — getblocktemplate + submitblock + BIP-22 / BIP-23 (haskoin)

**Wave:** W155 — `getblocktemplate` (BIP-22 / BIP-23 / BIP-9 / BIP-145),
`submitblock` (BIP-22 result strings), `getmininginfo`,
`prioritisetransaction`, `getprioritisedtransactions`, `submitheader`,
the proposal-mode validation path (`TestBlockValidity`), per-tx fields
(`data` / `txid` / `hash` / `depends` / `fee` / `sigops` / `weight`),
top-level fields (`coinbasevalue` / `longpollid` / `mintime` /
`curtime` / `mutable` / `noncerange` / `sizelimit` / `weightlimit` /
`sigoplimit` / `target` / `bits` / `vbavailable` / `vbrequired` /
`rules` / `coinbaseaux` / `default_witness_commitment` /
`signet_challenge`), longpoll wait loop, IBD + peer-count + signet/segwit
rule-set guards.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/rpc/mining.cpp:615-1036` — `getblocktemplate` RPC:
  - lines 716-761: parse `mode` / `capabilities` / `rules` /
    `longpollid` / `data`; dispatch proposal mode
  - lines 740-751: proposal mode dispatch including
    `chainman.UpdateUncommittedBlockStructures` + duplicate detection
    (`duplicate` / `duplicate-invalid` / `duplicate-inconclusive`),
    then `BIP22ValidationResult(TestBlockValidity(..., check_pow=false,
    check_merkle_root=true))`
  - lines 766-775: IBD guard (`RPC_CLIENT_IN_INITIAL_DOWNLOAD`) +
    peer-count guard (`RPC_CLIENT_NOT_CONNECTED`); both skipped on
    `miner.isTestChain()`
  - lines 783-845: long-poll wait loop (`miner.waitTipChanged` +
    `mempool.GetTransactionsUpdated` check, releases `cs_main_lock`
    during wait)
  - lines 850-857: client rule-set enforcement (signet → `signet`
    required; always → `segwit` required); throws
    `RPC_INVALID_PARAMETER` if absent
  - lines 859-884: cached template + `nTransactionsUpdatedLast` (5-sec
    cache); `include_dummy_extranonce=true` passed to
    `createNewBlock` (BIP22 path), `cooldown=false`
  - lines 897-936: per-tx records (`data`, `txid`, `hash` =
    wtxid hex, `depends` 1-based, `fee`, `sigops` halved for
    pre-segwit, `weight`)
  - lines 950-991: rules array: `csv` always; `!segwit` + `taproot`
    when post-segwit; `!signet` on signet; then per-deployment via
    `gbtstatus.signalling` / `.locked_in` / `.active`; for non-optional
    rules NOT in `setClientRules`, throws strict `RPCError` or strips
    bit from version
  - lines 993-1031: top-level fields. `coinbasevalue` is the actual
    `block.vtx[0]->vout[0].nValue` (NUMBER, satoshis); `longpollid` =
    `tip.GetHex() + ToString(nTransactionsUpdatedLast)`; `mintime` via
    `GetMinimumTime(pindexPrev, DifficultyAdjustmentInterval())`
    (BIP-94 timewarp clamp on EVERY network); `sizelimit` =
    `MAX_BLOCK_SERIALIZED_SIZE / WITNESS_SCALE_FACTOR` for pre-segwit;
    `weightlimit` only emitted post-segwit; `signet_challenge`
    emitted only on signet; `default_witness_commitment` = hex of the
    real `coinbase.required_outputs[0].scriptPubKey`
- `bitcoin-core/src/rpc/mining.cpp:587-603` —
  `BIP22ValidationResult(state)`: NULL on valid; `RPC_VERIFY_ERROR`
  exception on `IsError`; else returns reject reason string (or
  `"rejected"` if empty) AS THE `result` FIELD (not as RPC error)
- `bitcoin-core/src/rpc/mining.cpp:502-583` —
  `prioritisetransaction` (3-arg form with deprecated dummy=0) and
  `getprioritisedtransactions`
- `bitcoin-core/src/rpc/mining.cpp:416-498` — `getmininginfo`:
  emits `currentblockweight` + `currentblocktx` (from
  `BlockAssembler::m_last_block_*`), `signet_challenge` on signet,
  `next` sub-object (height / bits / difficulty / target),
  `warnings` as ARRAY by default (string only under
  `-deprecatedrpc=warnings`)
- `bitcoin-core/src/rpc/mining.cpp:1056-1106` — `submitblock`:
  `UpdateUncommittedBlockStructures` before processing (writes
  witness-commitment magic / nonce if absent); on already-known +
  accepted returns `"duplicate"`; on validation-interface
  `!sc->found` returns `"inconclusive"`; else
  `BIP22ValidationResult(sc->state)`
- `bitcoin-core/src/rpc/mining.cpp:1108-1146` — `submitheader`
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime`: at
  every retarget boundary (`height % difficulty_adjustment_interval
  == 0`), apply BIP-94 timewarp clamp `min_time = max(min_time,
  prev->GetBlockTime() - MAX_TIMEWARP)`
- `bitcoin-core/src/node/miner.cpp:182-200` — coinbase scriptSig
  prefix `CScript() << nHeight`, then `OP_0` dummy extranonce when
  `include_dummy_extranonce=true` (which `getblocktemplate` passes
  explicitly so heights ≤16 don't bad-cb-length)
- BIP-22 (https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki):
  - request: `mode` ∈ {template, proposal, submit}, `capabilities[]`,
    `longpollid`, `data` (proposal mode)
  - response: `coinbasevalue` (NUMBER, satoshis), `coinbasetxn`
    (OBJECT, only if no `coinbasevalue` mutation), `coinbaseaux`
    (OBJECT of hex key/values), `target`, `mintime`, `mutable[]`,
    `noncerange` (hex), `sigoplimit`, `sizelimit`, `curtime`, `bits`,
    `height`
  - submit return strings: `null` (accept), `"duplicate"`,
    `"duplicate-invalid"`, `"duplicate-inconclusive"`, reject
    reason, `"inconclusive"`
- BIP-23 (https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki):
  proposal mode result strings (uses same canonical reject-reason set
  as BIP-22 submit)
- BIP-9 / GBT changes
  (https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki):
  `rules[]` and `vbavailable{}` semantics, `!` prefix for mandatory
- BIP-145
  (https://github.com/bitcoin/bips/blob/master/bip-0145.mediawiki):
  segwit GBT additions — `default_witness_commitment` is REQUIRED
  output post-segwit-activation

**Files audited**
- `src/Haskoin/BlockTemplate.hs` — `BlockTemplate` record (line 162-179
  with `btCoinbaseValue`, `btSigopLimit`, `btWeightLimit`,
  `btMinTime`, `btMaxTime`, `btCurTime`, `btWitnessCommitment`,
  `btDefaultWitnessNonce`, `btCoinbaseTxn`), `createBlockTemplate`
  (line 201-295), `TemplateTransaction` (line 182-190),
  `buildTemplateTx` (line 330-360), `assembleBlock` (line 447-464),
  `submitBlock` (line 472-639), `submitBlockSideBranch` (line 670-726),
  `buildCoinbase` (line 387-428), `encodeHeight` /
  `encodeBip34Height` redirect (line 438), `applyBlockToCache` (line
  1224-1393).
- `src/Haskoin/Rpc.hs` — RPC dispatch (line 1010-1160; mining handlers
  at 1037-1041), `handleGetBlockTemplate` (line 2760-2766),
  `handleTemplateRequest` (line 2769-2848), `handleBlockProposal`
  (line 2851-2869), `extractTemplateMode` / `extractProposalData`
  (line 2872-2887), `buildWitnessCommitmentScript` (line 2893-2900),
  `bip22ResultString` (line 2910-3027), `handleSubmitBlock` (line
  3030-3068), `handleGetMiningInfo` (line 3073-3100),
  `handleGenerateToAddress` / `handleGenerateBlock` / `handleGenerate`
  (line 3109-3185), `generateSingleBlock` (line 3252-3317),
  `buildRegtestCoinbase` (line 3319-3342), `encodeRegtestHeight` (line
  3347-3359), `findRegtestNonce` (line 3363-3375),
  `computeGbtDeploymentStatus` (line 2730-2753), help table mining
  section (line 7135-7138).
- `src/Haskoin/Mempool.hs` — `Mempool` record `mpFeeDeltas` (line
  574-576), `selectTransactions` (line 2076-2100; sorts by
  `meAncestorFees`/`meAncestorSize` — IGNORES `mpFeeDeltas`),
  `MempoolEntry` shape (line 280-297), `mpHeight` (line 565-566),
  `buildMempoolEntry` (line 978).
- `src/Haskoin/Consensus.hs` — `taprootDeployment` (line 1678-1686),
  `computeBlockVersionFromChain` (line 1965-1969),
  `computeBlockVersion` (line 1914-1928), `addHeader` "already known"
  short-circuit (line 3955-3957), `connectBlock` (line 3027-3058).

---

## Gate matrix (45 sub-gates / 23 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | RPC dispatch presence | G1: `getblocktemplate` dispatched | PASS (`Rpc.hs:1038`) |
| 1 | … | G2: `submitblock` dispatched | PASS (`Rpc.hs:1039`) |
| 1 | … | G3: `getmininginfo` dispatched | PASS (`Rpc.hs:1040`) |
| 1 | … | G4: `prioritisetransaction` dispatched | **BUG-1 (P0-CDIV)** — absent from dispatch table (`Rpc.hs:1037-1041` only registers 3 mining RPCs); `mpFeeDeltas` consumer exists in admit gate (`Mempool.hs:859-870`) but no writer. Carry-forward W154 BUG-20 (W108 BUG-15). |
| 1 | … | G5: `getprioritisedtransactions` dispatched | **BUG-1 cross-cite** |
| 1 | … | G6: `submitheader` dispatched | **BUG-2 (P1)** — absent; operators cannot pre-stage headers (used by mining-pool failover and reorg-testing tooling). `addHeader` primitive exists (`Consensus.hs:3944`) but no RPC surface. |
| 2 | BIP-22 GBT request parse | G7: `mode` extracted | PASS (`Rpc.hs:2872-2878`) |
| 2 | … | G8: `capabilities` extracted | **BUG-3 (P1)** — `extractTemplateMode` reads only `mode`; `capabilities` field is never consulted. The client signal that they support `proposal` / `coinbasevalue` / `coinbasetxn` is silently discarded. |
| 2 | … | G9: `rules` array client-side enforcement (BIP-9: throw if non-optional rule absent) | **BUG-4 (P0-CDIV)** — `rules` array is NOT parsed from the request at all. Core (mining.cpp:754-760) builds `setClientRules` and at line 854-857 throws `RPC_INVALID_PARAMETER` `"getblocktemplate must be called with the segwit rule set"` when `segwit` is absent. haskoin always emits a template regardless — old miners that don't understand segwit get a post-segwit template and produce invalid blocks. |
| 2 | … | G10: signet rule-set required on signet | **BUG-4 cross-cite** — Core line 850-852 throws when `signet_blocks && !contains("signet")`. haskoin emits the same template on every network. |
| 3 | proposal mode (BIP-23) | G11: dispatch to proposal arm | PASS (`Rpc.hs:2765`) |
| 3 | … | G12: invoke `TestBlockValidity` and return BIP-22 reject string | **BUG-5 (P0-CDIV)** — `handleBlockProposal` (`Rpc.hs:2851-2869`) parses the block bytes and returns `Null` (= accepted) UNCONDITIONALLY. Inline comment confesses: `"For proposal mode, we just validate the block structure / In a full implementation, we'd check PoW, merkle root, etc."`. BIP-23 proposal mode IS A NOOP — accepts arbitrary garbage. **comment-as-confession 9th distinct fleet instance**. |
| 3 | … | G13: duplicate detection (`duplicate` / `duplicate-invalid` / `duplicate-inconclusive`) | **BUG-6 (P1)** — Core line 742-749 `LookupBlockIndex(hash)` returns one of three duplicate strings depending on the index status. haskoin's proposal arm has no duplicate detection at all. |
| 4 | IBD guard | G14: throw `RPC_CLIENT_IN_INITIAL_DOWNLOAD` mid-IBD on non-test chains | **BUG-7 (P0-CDIV)** — Core line 766-775 throws when `!miner.isTestChain() && miner.isInitialBlockDownload()`. haskoin's `handleGetBlockTemplate` (`Rpc.hs:2760-2766`) has NO IBD guard. A miner that calls GBT mid-IBD gets a template on top of a stale tip, then `submitblock` later succeeds against an outdated work-state. The `estimateIsInitialBlockDownload` helper (line 9142) is wired into `getblockchaininfo` but NOT into mining. |
| 5 | peer-count guard | G15: throw `RPC_CLIENT_NOT_CONNECTED` when 0 connections + non-test chain | **BUG-8 (P1)** — Core line 768-770 throws when peer count = 0 on non-test chain. haskoin has no equivalent check. A miner that calls GBT while the daemon is fully disconnected from peers is happy to mine a block that the network will never see. |
| 6 | long-poll wait loop | G16: parse `longpollid` and block until tip or transactions update | **BUG-9 (P1)** — Core line 783-845 implements the full long-poll: parse hashWatchedChain + nTransactionsUpdatedLastLP, release `cs_main` lock, wait via `miner.waitTipChanged` for up to 60s+10s with REVERSE_LOCK. haskoin emits the `longpollid` field (`Rpc.hs:2780`) but performs NO wait — the field is purely decorative. |
| 6 | … | G17: `longpollid` format `<tip>` + `<nTxsUpdatedLast>` | **BUG-10 (P1)** — Core line 1002: `tip.GetHex() + ToString(nTransactionsUpdatedLast)`. haskoin (`Rpc.hs:2780`): `showHash (btPreviousBlock bt) <> T.pack (show (btHeight bt))` — uses HEIGHT instead of nTransactionsUpdatedLast. A spec-compliant client that parses our longpollid back (e.g. for a follow-up GBT call) gets nonsense in the second half. Decoupled from BUG-9 because even with the wait wired, parse-side compatibility is broken. |
| 7 | template caching + `nTransactionsUpdatedLast` (5s freshness) | G18: cache template across requests within 5s if tip unchanged | **BUG-11 (P1)** — Core line 859-884 caches `pindexPrev` + `block_template` static state and rebuilds only when tip changes OR (mempool changed AND >5s elapsed). haskoin's `handleTemplateRequest` (`Rpc.hs:2769-2776`) rebuilds the template from scratch on EVERY call by calling `createBlockTemplate`. On a mainnet pool node hammering GBT at 5+ rps, every call walks the mempool, computes wtxids, and runs the witness-merkle root — wasted O(mempool_size) per call. |
| 8 | per-tx records | G19: `data` = hex(tx) | PASS (`Rpc.hs:2841`) |
| 8 | … | G20: `txid` = byte-reversed hex | PASS (`Rpc.hs:2842`) — `showHash (BlockHash (getTxIdHash ...))` reverses |
| 8 | … | G21: `hash` = wtxid byte-reversed hex | PARTIAL — `Rpc.hs:2843` calls `computeWtxId (ttTx tt)` which IGNORES `meWtxid` cached field on the mempool entry (`Mempool.hs:283`). Wasted SHA256d per tx per GBT call. Carry-forward W154 BUG-15. |
| 8 | … | G22: `depends` is array of 1-based indices into transactions[] | **BUG-12 (P0-CDIV)** — `buildTemplateTx` (`BlockTemplate.hs:339`) computes `[ i | (i, e) <- zip [0..] allEntries, ...]` — **0-based**. Core line 921: `deps.push_back(setTxIndex[in.prevout.hash])` where `setTxIndex[txHash] = i++` starting from `i = 0` for the coinbase, so non-coinbase txs are 1-based. **Off-by-one**: a miner that uses depends-driven CPFP-aware repacking sees parents pointing one slot too far back; in the worst case the cited index is out of range or points at an unrelated tx. |
| 8 | … | G23: `fee` field | PASS (`Rpc.hs:2844`) |
| 8 | … | G24: `sigops` halved when pre-segwit | **BUG-13 (P1)** — Core line 928-931: if pre-segwit, divide nTxSigOps by WITNESS_SCALE_FACTOR. haskoin emits the raw `ttSigops` (`Rpc.hs:2845`) unconditionally. On a from-genesis regtest replay, pre-segwit blocks see 4× inflated sigops counts. **Same shape as W143 BUG-2 / W154 BUG-1 segwit-gated divergence.** |
| 8 | … | G25: `weight` field | PASS (`Rpc.hs:2846`) |
| 9 | top-level fields: `coinbasevalue` | G26: emitted as JSON NUMBER, value in satoshis | PASS (`Rpc.hs:2822`) — `btCoinbaseValue :: Word64` emits as JSON Number via aeson's `.=`. Note: Word64 max value 18,446,744,073,709,551,615 EXCEEDS JS's 2^53-1 safe integer; for templates with extreme dust+subsidy this could exceed the safe range. In practice Bitcoin's MAX_MONEY = 2,100,000,000,000,000 satoshis = ~2.1 × 10^15 which is BELOW 2^53 ≈ 9 × 10^15, so safe in practice. |
| 9 | … | G27: `longpollid` present | PASS (`Rpc.hs:2823`); content broken (BUG-10) |
| 9 | … | G28: `mintime` BIP-94 timewarp clamp | **BUG-14 (P0-CDIV cross-cite W154 BUG-16)** — Core mining.cpp:1004 calls `GetMinimumTime(pindexPrev, DifficultyAdjustmentInterval())` which applies `max(mtp+1, prev->GetBlockTime() - MAX_TIMEWARP)` at EVERY retarget boundary on EVERY network (Core comment: "Account for BIP94 timewarp rule on all networks. This makes future activation safer."). haskoin `BlockTemplate.hs:218`: `minTime = mtp + 1` unconditionally. On testnet4 every 2016-block boundary's template has a too-early `mintime`. On mainnet pre-BIP-94 the values currently coincide by luck, but once BIP-94 ships to mainnet, every retarget-boundary template will leak a too-early timestamp into miners. Carry-forward W154 BUG-16. |
| 9 | … | G29: `curtime` set to `max(mintime, wallclock)` | PASS (`BlockTemplate.hs:220` `curTime = max minTime now`). But because `minTime` is wrong (G28), `curTime` may be off too. |
| 9 | … | G30: `mutable` array includes `time`, `transactions`, `prevblock` | PASS (`Rpc.hs:2799`) |
| 9 | … | G31: `noncerange` hex string | PASS (`Rpc.hs:2827` `"00000000ffffffff"`) |
| 9 | … | G32: `sizelimit` MAX_BLOCK_SERIALIZED_SIZE=4000000 post-segwit; halved pre-segwit | **BUG-15 (P0-CDIV)** — `Rpc.hs:2829`: `"sizelimit" .= (4000000 :: Int)` UNCONDITIONALLY. Core line 1007-1014 halves both sigoplimit AND sizelimit when pre-segwit (`nSizeLimit /= WITNESS_SCALE_FACTOR` → 1,000,000). Same shape as BUG-13. **Pre-segwit miners pointed at haskoin see a sizelimit 4× too large**, then submit oversize blocks rejected by Core's network. Fleet two-pipeline-at-consensus-boundary divergence (same shape as W154 BUG-19 / `selectTransactions` reserves 4000 not 8000). |
| 9 | … | G33: `weightlimit` emitted only post-segwit | **BUG-15 cross-cite** — `Rpc.hs:2830`: emitted unconditionally. Core line 1017-1019 emits only when post-segwit. Pre-segwit miners receive a `weightlimit` they don't know how to enforce. |
| 9 | … | G34: `sigoplimit` halved pre-segwit | **BUG-15 cross-cite** — `Rpc.hs:2828`: `btSigopLimit bt` emitted raw (=`maxBlockSigops`=80000 cost units). Core halves to 20000 for pre-segwit. |
| 9 | … | G35: `default_witness_commitment` emitted post-segwit-activation | **BUG-16 (P0-CDIV)** — `Rpc.hs:2811`: `defaultWitnessCommitment = buildWitnessCommitmentScript bt`. `buildWitnessCommitmentScript` (`Rpc.hs:2893-2900`) **always returns `BS.empty`** — the inline comment confesses: `"For now, return empty and let miner compute it"`. Field never emitted. The `BlockTemplate` record DOES carry the real 32-byte hash (`btWitnessCommitment`, line 175) but it is never read by the RPC. **Half-wired / already-exports-the-primitive-just-not-called fleet pattern (5th distinct haskoin instance)**. Mining software that depends on BIP-145 cannot construct correct coinbases. **comment-as-confession 10th distinct fleet instance**. |
| 9 | … | G36: `signet_challenge` emitted on signet | **BUG-17 (P1)** — Core line 1024-1026 emits `signet_challenge` hex on signet. haskoin emits nothing (no signet support in `Network` record per `Consensus.hs` grep — no `netSignetChallenge` field). Signet miners pointed at haskoin can't construct the signet block signature. |
| 9 | … | G37: `coinbasetxn` mode (BIP-22 alternative to coinbasevalue) | **BUG-18 (P1)** — BIP-22 specifies `coinbasetxn` as an OBJECT containing the full coinbase template (`data`, `hash`, `depends`, `fee`, `sigops`, `required` etc.) to be used when the miner CANNOT manipulate the coinbase value. haskoin always emits `coinbasevalue` (the alternative). Core emits `coinbasevalue` by default too, but `coinbasetxn` is a documented BIP-22 alternative miners may request via `capabilities`. The `btCoinbaseTxn` field exists (`BlockTemplate.hs:174`) but is never emitted — third dead field in this audit (cf. G35 `btWitnessCommitment`). |
| 9 | … | G38: `vbavailable` set of pending versionbit deployments | PASS — `Rpc.hs:2803-2804` builds `{name: bit}` for STARTED/LOCKED_IN deployments. Core line 968-983 does the same. |
| 9 | … | G39: `vbrequired` bitmask | PASS (`Rpc.hs:2818` hardcoded `0`; Core line 996 also `0`) |
| 9 | … | G40: `rules` array includes `csv`, `!segwit`, `taproot` (post-segwit, post-taproot active), `!signet` on signet | PARTIAL — `Rpc.hs:2796` hardcodes `["csv", "!segwit"] ++ activeNames`. Missing: `!signet` on signet (BUG-19 below); also the `!segwit` is emitted unconditionally even on a pre-segwit-activation chain (e.g. fresh regtest), where Core emits NEITHER `!segwit` nor `taproot` until post-segwit. |
| 9 | … | G41: `!signet` emitted on signet | **BUG-19 (P0-CDIV)** — Core mining.cpp:959-963 emits `aRules.push_back("!signet")` when `consensusParams.signet_blocks`. haskoin has no signet awareness in `handleTemplateRequest`. Signet miners that strictly check the `rules` array see signet is NOT listed and may refuse to mine. |
| 10 | submitblock | G42: BIP-22 result string in `result` field, not as JSON-RPC error | PASS (`Rpc.hs:3066-3067` returns the string as `result`) |
| 10 | … | G43: `"duplicate"` short-circuit for already-known block | **BUG-20 (P1)** — Core line 1086-1099 looks up `block.hashPrevBlock` in the block index, calls `UpdateUncommittedBlockStructures`, then submits via `ProcessNewBlock`. On `!new_block && accepted` returns `"duplicate"`. haskoin's `submitBlock` (`BlockTemplate.hs:484-639`) does NOT pre-check the block index for the block's own hash — duplicate submitblock calls walk the entire validation pipeline again, then `connectBlock` fails because the parent isn't the active tip (since this block already extended it). The error path returns `bip22ResultString err` which falls through to `"rejected"` instead of `"duplicate"`. Duplicate detection IS in `addHeader` (`Consensus.hs:3955-3957`) but it's reached only AFTER `validateFullBlockIO` + `applyBlockToCache` + `connectBlock`, all of which fail first. |
| 10 | … | G44: `UpdateUncommittedBlockStructures` (write witness-magic + nonce if absent) before submission | **BUG-21 (P1)** — Core line 1087-1089 calls `chainman.UpdateUncommittedBlockStructures(block, pindex)` BEFORE `ProcessNewBlock`. This patches up a block whose miner forgot to add the BIP-141 witness-commitment OP_RETURN, or where the witness nonce is missing. haskoin has no equivalent; a miner that submits a block with the right merkle root but missing commitment is rejected even though Core would patch + accept. (Edge case in practice — most modern mining software handles this, but BIP-22 specifies the server SHOULD do so.) |
| 11 | submitblock 2-arg form (BIP-22 dummy) | G45: accept and ignore `dummy` param | PARTIAL — `Rpc.hs:3044-3045` only reads `params 0`; if a client passes a 2-arg form `[hexdata, dummy]`, the second arg is silently ignored. This matches BIP-22 spec and Core's behaviour, but the help string at `Rpc.hs:7138` declares the 2-arg form so this is consistent. PASS. |
| 12 | bip22ResultString reject-string mapping | G46: maps every Core-canonical reject reason | PARTIAL — `Rpc.hs:2921-2934` includes 25+ canonical strings. Missing carry-forwards include `"high-hash"` mapping for some PoW errors phrased differently, `"bad-blk-length"` mapping (BUG-22 below). Tested elsewhere but adequate. |
| 12 | … | G47: maps `bad-blk-length` (block size > MAX_BLOCK_SERIALIZED_SIZE) | **BUG-22 (P1)** — `Rpc.hs:2966`: only maps `"exceeds maximum weight"` to `"bad-blk-length"`. Core also emits `bad-blk-length` for raw serialized-size cap violations. Cross-cite W154 BUG-1 (pre-segwit blocks have no size cap in haskoin's CheckBlock anyway — the divergence stacks). |
| 13 | getmininginfo | G48: `currentblockweight` / `currentblocktx` emitted (last assembled block) | **BUG-23 (P1)** — Core line 467-468 emits these from `BlockAssembler::m_last_block_weight` / `m_last_block_num_txs`. haskoin (`Rpc.hs:3088-3098`) emits neither. Mining-pool monitoring tools that scrape these to track assembler health get nothing. |
| 13 | … | G49: `networkhashps` integrated (RPC chain) | **BUG-24 (P1)** — `Rpc.hs:3094`: `pair "networkhashps" (AE.int 0)`. **Hardcoded to 0**. There IS a `handleGetNetworkHashPS` RPC handler (`Rpc.hs:1140`) but `handleGetMiningInfo` ignores it. Mining pools depending on networkhashps for hashrate-on-the-fly difficulty tracking see permanent 0. **already-exports-the-primitive-just-not-called fleet pattern 6th distinct haskoin instance**. |
| 13 | … | G50: `signet_challenge` emitted on signet | **BUG-17 cross-cite** — same as G36; not emitted on signet here either. |
| 13 | … | G51: `warnings` as array by default (not string under deprecation flag) | **BUG-25 (P2)** — Core line 444-450: emits `warnings` as ARRAY by default; only emits string under `-deprecatedrpc=warnings`. haskoin (`Rpc.hs:3098`): `pair "warnings" (text "")` — always string, never array. Monitoring tools that parse `warnings` strictly as array see a type error. |
| 13 | … | G52: `blockmintxfee` configurable (not hardcoded) | **BUG-26 (P1)** — `Rpc.hs:3093`: `pair "blockmintxfee" (btcAmountEnc 1000)`. Hardcoded to 1000 sat/vB (presumably MIN_RELAY_TX_FEE × 1000 = 1 sat/vB in BTC/kB). Core line 474-476: `assembler_options.blockMinFeeRate.GetFeePerK()` — configurable via `-blockmintxfee` CLI. haskoin has no operator knob. |
| 14 | mempool selection vs prioritisetransaction | G53: `selectTransactions` reads `mpFeeDeltas` and sorts by modifiedFee | **BUG-27 (P0-CDIV)** — `Mempool.hs:2076-2098` sorts by `(meAncestorFees * 1000) / meAncestorSize`, IGNORING `mpFeeDeltas`. The admit-side gate at line 859-870 DOES apply the delta (so a low-fee tx with positive delta gets ADMITTED), but the selection-for-block side does NOT (so the same tx gets SELECTED based on its base fee). Net effect: `prioritisetransaction` cannot change template ordering even when wired. Half-wired: admit-side consumes the field, mining-side ignores it. **Two-pipeline guard 19th distinct extension — same field consumed inconsistently across mempool subsystems within one impl.** |
| 15 | mpHeight=0 startup gap affects mining via mempool admit | G54: `createBlockTemplate` reads chain tip directly | PASS (`BlockTemplate.hs:210-211` `tip <- readTVarIO (hcTip hc); height = ceHeight tip + 1`). Same carry-forward note as W154 BUG-19: mempool admit may have over-permitted txs during startup, and the template inherits them. Carry-forward W150→W151→W152→W153→W154→W155 (6-wave). |
| 16 | template self-test | G55: `TestBlockValidity` on the constructed template | **BUG-28 (P1)** — Carry-forward W154 BUG-17. Core mining.cpp:223-228 calls `TestBlockValidity` after coinbase construction inside `createNewBlock` to catch self-inflicted bugs. haskoin's `createBlockTemplate` (`BlockTemplate.hs:201-295`) returns immediately after building; no self-test. Combined with W154 BUG-10 (1-byte scriptSig for heights 1..16) the GBT path silently hands miners templates that hash to invalid blocks. |
| 17 | regtest miner two-pipeline divergence | G56: `generate` / `generatetoaddress` / `generateblock` route through canonical `createBlockTemplate` | **BUG-29 (P1 cross-cite W154 BUG-19)** — `generateSingleBlock` (`Rpc.hs:3252-3317`) is a complete re-implementation that disagrees with `createBlockTemplate` on coinbase encoding (W108 BUG-11..14), `selectTransactions` reservation (4000 vs 8000), bits derivation (hardcoded 0x207fffff vs `difficultyAdjustment`), fee handling (coinbase = subsidy only, ignoring fees — W154 BUG-18), and witness-commitment generation (absent). **Two-pipeline-at-consensus-boundary-that-self-rejects** carry-forward. |

---

## BUG-1 (P0-CDIV) — `prioritisetransaction` / `getprioritisedtransactions` RPCs absent

**Severity:** P0-CDIV.  Bitcoin Core's `prioritisetransaction` is the
canonical operator-knob that lets a node operator (or wallet) raise the
"effective fee" of a specific txid in the local mempool so the
transaction-selection pipeline (BlockAssembler + relay-side
min-relay-fee + RBF policy) treats it as if it paid more (or less).
The field is plumbed through `CTxMemPool::PrioritiseTransaction` →
`mapDeltas` and consumed by every CPFP-aware path
(`ws.m_modified_fees` in `MemPoolAccept`, `entry.GetModifiedFee()` in
the chunk selector).  Without it there is no way to push a stuck tx
into the next block from outside the daemon.

haskoin's RPC dispatch (`src/Haskoin/Rpc.hs:1037-1041`) registers
exactly three mining RPCs: `getblocktemplate`, `submitblock`,
`getmininginfo`.  Neither `prioritisetransaction` nor
`getprioritisedtransactions` appears.  The data store IS partially
present — `Mempool.mpFeeDeltas :: TVar (Map TxId Int64)`
(`Mempool.hs:574-576`) — and the admit-side gate at
`Mempool.hs:859-870` reads it.  **Producer is missing, consumer is
half-wired (G53/BUG-27 catches the second half).**

**File:** `src/Haskoin/Rpc.hs:1037-1041` (no dispatch); cross-file gap
to `src/Haskoin/Mempool.hs:574-576` (storage exists, no RPC writer).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:502-583`
(`prioritisetransaction` + `getprioritisedtransactions`).

**Impact:**
- Operators cannot push a stuck transaction into the next block.
- Mining pools cannot prioritise their own coinbase-spending
  transactions for downstream fee structures.
- Cross-impl divergence: every other hashhog impl that exposes
  `prioritisetransaction` would have its tests pass on Core but fail
  on haskoin with `Method not found`.
- Fleet pattern: **"already-exports-the-primitive-just-not-called"**
  — `mpFeeDeltas` storage + admit-side consumer ship, the
  RPC writer does not.  This is the 5th distinct haskoin instance of
  the W140 (TimingResistantEqual) / W141 (notify-fan-out) shape;
  cumulative 6 across waves.
- Carry-forward W154 BUG-20 (which carry-forwarded W108 BUG-15);
  three-wave open since W108.

---

## BUG-2 (P1) — `submitheader` RPC absent

**Severity:** P1.  Core's `submitheader` accepts a single hex-encoded
header, runs `ProcessNewBlockHeaders`, and surfaces validation errors
via `RPC_VERIFY_ERROR`.  Mining pools use it to:
- Pre-stage headers for failover scenarios (the pool's "leader"
  node receives a header before the body arrives, so when the body
  lands it's already in the index).
- Test reorg behaviour against a private chain without serializing
  full block bodies.

`addHeader` (`Consensus.hs:3944`) implements the primitive — runs the
full 7-gate validation (PoW, MTP, timewarp, future-time, difficulty,
checkpoint, too-little-chainwork).  No RPC exposes it.

**File:** `src/Haskoin/Rpc.hs:1037-1041` (no dispatch);
`Consensus.hs:3944-...` (primitive exists, no RPC wrapper).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1108-1146`.

**Impact:** mining-pool tooling and reorg-test scripts that depend on
`submitheader` get `Method not found`.  **already-exports-the-primitive-
just-not-called** fleet pattern, 6th distinct haskoin instance.

---

## BUG-3 (P1) — `capabilities` array silently discarded; `extractTemplateMode` reads only `mode`

**Severity:** P1.  BIP-22 specifies that clients advertise the
capabilities they understand (`coinbasevalue`, `coinbasetxn`,
`longpoll`, `proposal`, `serverlist`, `workid`) in the
`template_request.capabilities` array.  The server uses this to decide
whether to emit `coinbasevalue` (NUMBER) or `coinbasetxn` (full
coinbase OBJECT), whether to long-poll, etc.

haskoin's `extractTemplateMode` (`Rpc.hs:2872-2878`) only reads
`mode`.  There is no equivalent helper that reads `capabilities`.  The
`handleTemplateRequest` arm unconditionally emits `coinbasevalue` and
never emits `coinbasetxn`.

**File:** `src/Haskoin/Rpc.hs:2769-2776`, `2872-2887`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:632`.

**Impact:** clients that strictly require `coinbasetxn` (legacy mining
software, BIP-22-compliant proxies that cannot manipulate
coinbasevalue directly) cannot use haskoin's GBT.  Cross-impl
divergence with Core.

---

## BUG-4 (P0-CDIV) — `rules` array client-side enforcement absent; segwit / signet rule gating not performed

**Severity:** P0-CDIV.  Bitcoin Core enforces (mining.cpp:850-857)
that GBT clients explicitly acknowledge support for `segwit` (always)
and `signet` (on signet) in their `template_request.rules` array.  If
the rule is absent, Core throws `RPC_INVALID_PARAMETER`:

```cpp
if (!setClientRules.contains("segwit")) {
    throw JSONRPCError(RPC_INVALID_PARAMETER,
        "getblocktemplate must be called with the segwit rule set "
        "(call with {\"rules\": [\"segwit\"]})");
}
```

The purpose is defensive: pre-segwit mining software given a
post-segwit template would NOT know to honour the witness-commitment
OP_RETURN and would emit invalid blocks.  Same for signet's signed
block-solution requirement.

haskoin's `handleTemplateRequest` (`Rpc.hs:2769-2776`) NEVER parses
the `rules` field from the request.  Templates are emitted to
everyone, including pre-segwit miners.

**File:** `src/Haskoin/Rpc.hs:2760-2766`, `2769-2776`,
`2872-2887` (extractor reads only `mode`).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:754-760, 850-857`.

**Impact:**
- A pre-segwit miner that calls `getblocktemplate` gets a
  post-segwit template (with witness-commitment in the coinbase),
  fails to honour the BIP-141 commitment, and submits a block the
  network rejects.
- On signet, the same shape: a miner that doesn't know to add the
  signet-challenge signature in the coinbase witness produces
  invalid signet blocks.
- Defense-in-depth gap: Core's gate is a fail-fast contract; haskoin
  silently hands miners templates they can't honour.

---

## BUG-5 (P0-CDIV) — Proposal-mode handler does NOT run `TestBlockValidity`; accepts any block

**Severity:** P0-CDIV.  BIP-23 proposal mode is the canonical way for
a miner to ask the node "would you accept this block, if I submitted
it now?" without actually committing to it.  Core runs the full
`TestBlockValidity(state, ..., check_pow=false, check_merkle_root=true)`
and returns one of the BIP-22 reject strings (`high-hash`,
`bad-txnmrklroot`, `bad-cb-amount`, etc.) or `null` for acceptance.
This is what mining-pool stratum proxies use to validate locally-mined
blocks before relaying to the upstream pool.

haskoin's `handleBlockProposal` (`Rpc.hs:2851-2869`):

```haskell
Right block -> do
  -- For proposal mode, we just validate the block structure
  -- In a full implementation, we'd check PoW, merkle root, etc.
  -- and return appropriate BIP22 rejection reason
  return $ RpcResponse Null Null Null  -- null means accepted
```

The block is decoded (success means well-formed bytes) and the
function returns `Null` (= accepted) WITHOUT calling ANY validation.
A pool that uses haskoin as a sanity-check upstream sees every
proposed block "accepted" — including blocks with wrong PoW, wrong
merkle root, bad coinbase amount, double-spends, etc.

**File:** `src/Haskoin/Rpc.hs:2851-2869`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:740-751`.

**Excerpt (Core, calls TestBlockValidity)**
```cpp
uint256 hash = block.GetHash();
LOCK(cs_main);
const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
if (pindex) {
    if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
        return "duplicate";
    if (pindex->nStatus & BLOCK_FAILED_VALID)
        return "duplicate-invalid";
    return "duplicate-inconclusive";
}
return BIP22ValidationResult(
    TestBlockValidity(chainman.ActiveChainstate(), block,
                      /*check_pow=*/false,
                      /*check_merkle_root=*/true));
```

**Excerpt (haskoin, decodes-and-accepts)**
```haskell
Right block -> do
  -- For proposal mode, we just validate the block structure
  -- In a full implementation, we'd check PoW, merkle root, etc.
  -- and return appropriate BIP22 rejection reason
  return $ RpcResponse Null Null Null  -- null means accepted
```

The inline comment `"For proposal mode, we just validate the block
structure"` + `"In a full implementation, we'd check PoW, merkle root,
etc."` is a **comment-as-confession** (fleet pattern, 9th distinct
haskoin instance) — admits the divergence in code.

**Impact:**
- Mining-pool stratum proxies that use proposal mode for pre-submit
  validation see all proposed blocks falsely accepted.
- Downstream relay: any pool that proposed→submitted on haskoin would
  have submitted invalid blocks to Core nodes, getting banned.
- Cross-impl divergence: every other hashhog impl that wires
  TestBlockValidity sees Core-parity reject strings on the proposal
  path; haskoin returns `null` for all.
- Wave-level pattern: BIP-23 entry point completely non-functional;
  this is the 30-of-30-gates-buggy class for the proposal path
  (every consensus check is skipped).

---

## BUG-6 (P1) — Duplicate-block detection absent in proposal mode

**Severity:** P1.  BIP-23 specifies three distinct duplicate
results: `duplicate` (block fully valid, on chain or in index),
`duplicate-invalid` (block previously rejected), `duplicate-inconclusive`
(block in index but not fully validated).  These let a pool know
"someone else already mined this — don't waste another round".

haskoin's proposal arm (`Rpc.hs:2851-2869`) has no lookup against the
block index.  Combined with BUG-5, even an already-mined-and-confirmed
block returns `null` (= acceptance).

**File:** `src/Haskoin/Rpc.hs:2851-2869`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:742-749`.

**Impact:** cross-impl tooling drift; pools cannot distinguish a
genuinely-new candidate from a duplicate.

---

## BUG-7 (P0-CDIV) — No IBD guard on `getblocktemplate`

**Severity:** P0-CDIV.  Core mining.cpp:766-775 guards GBT on
non-test chains:

```cpp
if (!miner.isTestChain()) {
    const CConnman& connman = EnsureConnman(node);
    if (connman.GetNodeCount(ConnectionDirection::Both) == 0) {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED,
            CLIENT_NAME " is not connected!");
    }
    if (miner.isInitialBlockDownload()) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD,
            CLIENT_NAME " is in initial sync and waiting for blocks...");
    }
}
```

A miner that called GBT during IBD would receive a template on top of
a stale tip (often days behind the network).  Mining onto a stale tip
is wasted hashpower and produces blocks that lose every race against
the synced tip — the canonical "fee snipe + orphan" anti-pattern.

haskoin's `handleGetBlockTemplate` (`Rpc.hs:2760-2766`) has no IBD
check.  The `estimateIsInitialBlockDownload` helper exists at line
9142 and IS called by `getblockchaininfo` (line 1179), `handleSyncState`
(line 1381), and `dumptxoutset` paths.  The mining RPC was overlooked.

**File:** `src/Haskoin/Rpc.hs:2760-2766` (no guard).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:766-775`.

**Impact:** mainnet/testnet operators that scripts a miner-restart
loop see the daemon hand templates the moment the RPC is reachable —
even before headers-sync settles.  Wasted hashpower until IBD finishes.

---

## BUG-8 (P1) — No peer-count guard on `getblocktemplate`

**Severity:** P1.  Same shape as BUG-7 but for the peer-count half of
the Core gate.  A daemon with zero peers cannot publish a mined block;
mining on it is wasted hashpower.  haskoin has no equivalent check.

**File:** `src/Haskoin/Rpc.hs:2760-2766`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:768-770`.

**Impact:** mining onto a network-isolated node; orphan-rate ≈ 100%
until peers connect.

---

## BUG-9 (P1) — Long-poll wait loop entirely absent

**Severity:** P1.  Core implements the BIP-22 long-poll
(`bitcoin-core/src/rpc/mining.cpp:783-845`):

```cpp
if (!lpval.isNull()) {
    // ... parse hashWatchedChain + nTransactionsUpdatedLastLP ...
    REVERSE_LOCK(cs_main_lock, cs_main);
    MillisecondsDouble checktxtime{std::chrono::minutes(1)};
    while (IsRPCRunning()) {
        std::optional<BlockRef> maybe_tip{
            miner.waitTipChanged(hashWatchedChain, checktxtime)};
        if (!maybe_tip) break;
        tip = maybe_tip->hash;
        if (tip != hashWatchedChain) break;
        if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP) {
            break;
        }
        checktxtime = std::chrono::seconds(10);
    }
}
```

Mining pools use long-poll to avoid hammering GBT every second; the
RPC blocks until either (a) the tip changes or (b) the mempool sees
"enough" new transactions, then returns the new template.

haskoin emits the `longpollid` field (`Rpc.hs:2780`) but performs no
wait — the field is purely decorative.  A long-polling client gets an
immediate response regardless of whether anything changed.

**File:** `src/Haskoin/Rpc.hs:2769-2848`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:783-845`.

**Impact:** mining-pool GBT call rate compounds because the
long-poll-saves-RPC-traffic optimisation is absent.  At pool scale
(thousands of workers polling) this is meaningful CPU + bandwidth.
Decorative field also misleads operators into thinking long-poll is
wired.

---

## BUG-10 (P1) — `longpollid` format diverges: uses height instead of `nTransactionsUpdatedLast`

**Severity:** P1.  Core's longpollid format is:

```cpp
result.pushKV("longpollid",
  tip.GetHex() + ToString(nTransactionsUpdatedLast));
```

So the longpollid encodes `<tip_hash><tx_update_counter>`.  A
spec-compliant client passes it back unchanged on the next call; the
server parses the first 64 hex chars as the tip hash and the rest as
the prior counter.

haskoin (`Rpc.hs:2778-2780`):

```haskell
-- Generate longpollid: <previousblockhash><transactionsUpdated>
-- For simplicity, we use the block hash and height
let longpollid = showHash (btPreviousBlock bt) <> T.pack (show (btHeight bt))
```

Uses HEIGHT instead of nTransactionsUpdated.  The inline comment
admits the divergence (`"For simplicity, we use the block hash and
height"`) — **comment-as-confession 10th distinct fleet instance**.

Even with BUG-9 fixed (longpoll loop wired), a spec-compliant client
that parses the second half as an integer counter sees the wrong
value, and the long-poll either fires immediately or never (depending
on how the parser handles the height value).

**File:** `src/Haskoin/Rpc.hs:2778-2780`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1002`.

**Impact:** decoupled from BUG-9; even if the wait is wired, parse-side
breaks.  Carry-forward: this is one of two two-pipeline-guard
extensions where the WIRE format diverges (the other is W138 / W141
ZMQ hash byte-order).

---

## BUG-11 (P1) — No template caching; every GBT call rebuilds from scratch

**Severity:** P1.  Core caches the BlockTemplate across calls
(mining.cpp:859-884) and only rebuilds when:
1. Tip changed, OR
2. `mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast`
   AND `GetTime() - time_start > 5` (5-second freshness window).

The result is that a mining-pool scraper polling at 1Hz amortises the
template-building cost across requests.  Inside the 5-second window,
all GBT calls share a single template build.

haskoin's `handleTemplateRequest` (`Rpc.hs:2769-2776`) calls
`createBlockTemplate` on every invocation.  At a typical mainnet
mempool of ~30k entries, each call:
- walks the mempool (`selectTransactions` is O(n log n) for the sort),
- computes wtxids on every selected tx (BUG-15 carry-forward —
  ignores cached `meWtxid`),
- runs the witness-merkle hash.

At pool-scale GBT rates (~10 rps from a typical stratum proxy fleet)
this is wasted CPU.

**File:** `src/Haskoin/Rpc.hs:2769-2776`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:859-884`.

**Impact:** mining-pool host CPU pressure; bigger blocks compound the
issue.  Not a correctness bug; perf-and-scale.

---

## BUG-12 (P0-CDIV) — `depends` uses 0-based indices; BIP-22 spec is 1-based

**Severity:** P0-CDIV.  BIP-22 (and Core's GBT output) specifies the
`depends` array as **1-based** indices into the `transactions[]`
array, where index 1 refers to `transactions[0]` (the first
non-coinbase tx).  This is because the implicit coinbase is treated
as a notional index 0.

Core's implementation (mining.cpp:898-922):

```cpp
std::map<Txid, int64_t> setTxIndex;
int i = 0;
for (const auto& it : block.vtx) {
    const CTransaction& tx = *it;
    Txid txHash = tx.GetHash();
    setTxIndex[txHash] = i++;
    if (tx.IsCoinBase()) continue;  // index 0 reserved
    // ... 
    UniValue deps(UniValue::VARR);
    for (const CTxIn& in : tx.vin) {
        if (setTxIndex.contains(in.prevout.hash))
            deps.push_back(setTxIndex[in.prevout.hash]);
    }
    entry.pushKV("depends", std::move(deps));
}
```

So `setTxIndex[coinbase] = 0`, `setTxIndex[first_non_coinbase] = 1`,
etc.  The first non-coinbase has `depends=[]`, the second
non-coinbase that spends the first cites `depends=[1]` (NOT `[0]`).

haskoin's `buildTemplateTx` (`BlockTemplate.hs:330-360`):

```haskell
buildTemplateTx txIdSet allEntries idx entry =
  let tx = meTransaction entry
      parentTxIds = map (outPointHash . txInPrevOutput) (txInputs tx)
      depends = [ i | (i, e) <- zip [0..] allEntries
                , meTxId e `elem` parentTxIds
                , Set.member (meTxId e) txIdSet
                , i < idx
                ]
      ...
```

`zip [0..] allEntries` is 0-based, and `allEntries` is the
NON-COINBASE list (coinbase isn't built via `buildTemplateTx`).  So
the first non-coinbase gets `idx=0`, the second non-coinbase that
spends the first cites `depends=[0]` — Core would cite `[1]`.

**Off-by-one across the entire `depends` array.**  A mining-pool
package-aware scheduler that uses `depends` to validate CPFP
topology before submitting a sub-block sees parents pointing to the
wrong slot.

**File:** `src/Haskoin/BlockTemplate.hs:339`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:898-922`.

**Excerpt (haskoin, 0-based)**
```haskell
depends = [ i | (i, e) <- zip [0..] allEntries
          , meTxId e `elem` parentTxIds
          , Set.member (meTxId e) txIdSet
          , i < idx
          ]
```

**Impact:**
- Mining pool / package-aware schedulers see depends indices that
  are 1 less than Core's.
- Worst case: index 0 valid by accident if the scheduler treats it
  as "depends on the coinbase".
- Cross-impl divergence: GBT output diff would surface this
  immediately.

---

## BUG-13 (P1) — Per-tx `sigops` field not halved for pre-segwit blocks

**Severity:** P1.  Core mining.cpp:925-932:

```cpp
int index_in_template = i - 2;
entry.pushKV("fee", tx_fees.at(index_in_template));
int64_t nTxSigOps{tx_sigops.at(index_in_template)};
if (fPreSegWit) {
    CHECK_NONFATAL(nTxSigOps % WITNESS_SCALE_FACTOR == 0);
    nTxSigOps /= WITNESS_SCALE_FACTOR;
}
entry.pushKV("sigops", nTxSigOps);
```

Pre-segwit (height < SEGWIT_HEIGHT on the active network) the sigops
field is in raw legacy units (count, not cost), so Core divides by
WITNESS_SCALE_FACTOR=4 before emitting.  Post-segwit, the field is
sigops COST (legacy × 4 + witness sigops, as defined by
MAX_BLOCK_SIGOPS_COST).

haskoin always emits `ttSigops` raw (`Rpc.hs:2845`); the
`templateLegacySigOpCost` helper at `BlockTemplate.hs:309-310` already
multiplies by `witnessScaleFactor` so the stored `ttSigops` is
ALREADY in COST units.  For pre-segwit blocks this is 4× too high.

**File:** `src/Haskoin/Rpc.hs:2845`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:925-932`.

**Impact:** on regtest from-genesis replay (pre-segwit blocks), GBT
emits sigop counts 4× higher than Core.  Mining software that
budgets against the cited per-tx sigops sees the template look
"fuller" than it is and may skip txs that would otherwise fit.
Cross-cite W154 BUG-1 (same segwit-gated divergence in CheckBlock).

---

## BUG-14 (P0-CDIV cross-cite W154 BUG-16) — `mintime` does NOT apply BIP-94 timewarp clamp

**Severity:** P0-CDIV.  Carry-forward W154 BUG-16.  Core's
`GetMinimumTime` (`bitcoin-core/src/node/miner.cpp:36-47`):

```cpp
int64_t GetMinimumTime(const CBlockIndex* pindexPrev,
                       const int64_t difficulty_adjustment_interval)
{
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    const int height{pindexPrev->nHeight + 1};
    // Account for BIP94 timewarp rule on all networks. This makes
    // future activation safer.
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time,
                       pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return min_time;
}
```

Core's comment is explicit: BIP-94 timewarp clamp is applied on EVERY
network at the retarget boundary, even before BIP-94 activates on
mainnet, "to make future activation safer".  The clamp bumps mintime
to `prevBlock.time - 600` if that's greater than `mtp+1`.

haskoin's `createBlockTemplate` (`BlockTemplate.hs:218`):

```haskell
let minTime = mtp + 1
```

Unconditional `mtp + 1`; no boundary check, no MAX_TIMEWARP clamp.

**File:** `src/Haskoin/BlockTemplate.hs:217-220`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47`,
`bitcoin-core/src/rpc/mining.cpp:1004`.

**Impact:**
- testnet4 already enforces BIP-94 at consensus level (haskoin's
  `addHeader` line 3978-3982 does check `time-timewarp-attack` on
  testnet4 retarget boundaries).  Mining templates that emit a
  `mintime` < clamp produce blocks the validator's own gate would
  reject if a miner doesn't update `curtime` past the clamp.
- mainnet pre-BIP-94: currently identical-by-luck.  When BIP-94 ships
  to mainnet, every retarget-boundary template emits a too-early
  `mintime`, miners that strictly honour mintime as "the earliest
  they can use" produce blocks that BIP-94 consensus rejects.
- Self-rejection: same shape as W154 BUG-19
  (two-pipeline-at-consensus-boundary-that-self-rejects) — the
  template emits a mintime the validator would reject at the same
  boundary.  Carry-forward W154 BUG-16; six-wave-open since W154.

---

## BUG-15 (P0-CDIV) — `sizelimit` / `sigoplimit` / `weightlimit` not adjusted for pre-segwit

**Severity:** P0-CDIV.  Core mining.cpp:1007-1019:

```cpp
int64_t nSigOpLimit = MAX_BLOCK_SIGOPS_COST;
int64_t nSizeLimit = MAX_BLOCK_SERIALIZED_SIZE;
if (fPreSegWit) {
    CHECK_NONFATAL(nSigOpLimit % WITNESS_SCALE_FACTOR == 0);
    nSigOpLimit /= WITNESS_SCALE_FACTOR;
    CHECK_NONFATAL(nSizeLimit % WITNESS_SCALE_FACTOR == 0);
    nSizeLimit /= WITNESS_SCALE_FACTOR;
}
result.pushKV("sigoplimit", nSigOpLimit);
result.pushKV("sizelimit", nSizeLimit);
if (!fPreSegWit) {
    result.pushKV("weightlimit", MAX_BLOCK_WEIGHT);
}
```

Pre-segwit:
- `sigoplimit` = 20000 (cost units / 4)
- `sizelimit` = 1000000 bytes (4MB / 4)
- `weightlimit` NOT emitted at all

Post-segwit:
- `sigoplimit` = 80000
- `sizelimit` = 4000000 (max serialized; raw block bytes)
- `weightlimit` = 4000000 (separate weight metric)

haskoin (`Rpc.hs:2828-2830`) emits all three unconditionally with
post-segwit values:

```haskell
, Just $ "sigoplimit"          .= btSigopLimit bt      -- 80000 always
, Just $ "sizelimit"           .= (4000000 :: Int)     -- 4MB always
, Just $ "weightlimit"         .= btWeightLimit bt     -- 4MB always
```

**File:** `src/Haskoin/Rpc.hs:2828-2830`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1007-1019`.

**Impact:**
- Pre-segwit miners see sizelimit 4× too high → produce 4MB
  blocks the legacy-validator would reject as `bad-blk-length`.
- Pre-segwit miners see sigoplimit 4× too high → produce blocks
  with 80000 legacy sigops, also rejected.
- Pre-segwit miners see weightlimit they don't know how to enforce
  → adopt it as the binding cap and overproduce blocks.
- Compounds W154 BUG-1 (pre-segwit blocks have NO size cap in
  haskoin's CheckBlock at all — so haskoin's OWN validator would
  ACCEPT these oversized blocks; cross-impl with Core would result
  in a fork).

This is a stacking-CVE-class divergence: BUG-15 + W154 BUG-1 →
pre-segwit haskoin nodes produce blocks Core rejects, fork the chain
on a from-genesis replay (heights 0..481823).

---

## BUG-16 (P0-CDIV) — `default_witness_commitment` is permanently empty; `buildWitnessCommitmentScript` is a stub

**Severity:** P0-CDIV.  BIP-145 specifies `default_witness_commitment`
as the BIP-141 witness-commitment OP_RETURN scriptPubKey that
mining software should include in the coinbase's vout when it does NOT
modify the witness merkle root.  This is the OP_RETURN with prefix
`6a24aa21a9ed` followed by 32 bytes of `SHA256d(witness_merkle_root ||
witness_nonce)`.

Core (mining.cpp:1028-1031):

```cpp
if (auto coinbase{block_template->getCoinbaseTx()}; coinbase.required_outputs.size() > 0) {
    CHECK_NONFATAL(coinbase.required_outputs.size() == 1);
    result.pushKV("default_witness_commitment",
                  HexStr(coinbase.required_outputs[0].scriptPubKey));
}
```

The required-output is constructed during `GenerateCoinbaseCommitment`
(mining.cpp:200) and ships in the template.

haskoin:
- `BlockTemplate` HAS the commitment hash field (`btWitnessCommitment
  :: ByteString`, `BlockTemplate.hs:175`).
- `buildCoinbase` constructs the OP_RETURN at
  `BlockTemplate.hs:411-414` and prepends the right magic prefix.
- The `BlockTemplate` IS populated with the right commitment value at
  `BlockTemplate.hs:266-267, 293`.

But the RPC handler routes through `buildWitnessCommitmentScript`
(`Rpc.hs:2811, 2893-2900`):

```haskell
buildWitnessCommitmentScript :: BlockTemplate -> ByteString
buildWitnessCommitmentScript bt
  | null (btTransactions bt) = BS.empty
  | otherwise =
      -- OP_RETURN <aa21a9ed><placeholder 32 bytes>
      -- In a real implementation, we'd compute the witness merkle root
      -- For now, return empty and let miner compute it
      BS.empty
```

**Always returns `BS.empty`.**  The `if not (BS.null defaultWitnessCommitment)` gate
(`Rpc.hs:2834-2836`) then NEVER fires, so `default_witness_commitment`
is NEVER emitted in the JSON response.

The actual commitment data (`btWitnessCommitment`) is DEAD FIELD in
the RPC — populated by `createBlockTemplate` but never consumed by
the JSON encoder.

**File:** `src/Haskoin/Rpc.hs:2811, 2834-2836, 2893-2900`;
unread field at `src/Haskoin/BlockTemplate.hs:175, 293`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1028-1031`,
BIP-145.

**Impact:**
- Mining software that depends on the server-provided
  `default_witness_commitment` (most BIP-145-compliant miners) cannot
  construct the required OP_RETURN.  They either skip the commitment
  (producing pre-segwit-style blocks that consensus rejects on
  post-segwit chains) or compute their own (defeating the purpose of
  the field).
- Cross-impl divergence: every other hashhog impl that emits the
  field produces compatible templates; haskoin does not.
- Fleet pattern: **"already-exports-the-primitive-just-not-called"**
  5th distinct haskoin instance — the data exists,
  the encoder ignores it.
- **comment-as-confession 10th distinct fleet instance** — the
  inline comment admits the stub.

---

## BUG-17 (P1) — `signet_challenge` absent from both `getblocktemplate` and `getmininginfo`

**Severity:** P1.  Core emits `signet_challenge` (hex of the
`signet_challenge` consensus param) on signet networks in both
GBT response (mining.cpp:1024-1026) and `getmininginfo`
(mining.cpp:489-492).  Signet miners use this to know which
key/script must sign each block.

haskoin's `Network` record (per `Consensus.hs` grep) has no
`netSignetChallenge` field.  Neither RPC emits the value.  Signet is
effectively unsupported for mining (operators would have to hardcode
the challenge in the miner's source).

**File:** `src/Haskoin/Rpc.hs:2813-2837` (GBT, no signet emit);
`src/Haskoin/Rpc.hs:3088-3098` (getmininginfo, no signet emit).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1024-1026, 489-492`.

**Impact:** signet mining is impractical on haskoin; the challenge
must come from out-of-band knowledge.

---

## BUG-18 (P1) — `coinbasetxn` mode never emitted; `btCoinbaseTxn` is a dead field

**Severity:** P1.  BIP-22 specifies `coinbasetxn` as an OBJECT that
fully describes the template's coinbase (`data`, `hash`, `depends`,
`fee`, `sigops`, `required` etc.) for clients that cannot manipulate
`coinbasevalue` directly.  The two are mutually exclusive: emit
`coinbasevalue` (number) OR `coinbasetxn` (object).

haskoin always emits `coinbasevalue` (the simpler path).  But
`BlockTemplate.btCoinbaseTxn :: Tx` (`BlockTemplate.hs:174`)
exists and is populated (line 292).  No JSON encoder reads it; the
field is a third dead-data candidate alongside G35 (`btWitnessCommitment`)
and G37 (this field).

**File:** `src/Haskoin/Rpc.hs:2813-2837` (no `coinbasetxn` emit);
`src/Haskoin/BlockTemplate.hs:174` (field exists, no RPC consumer).

**Core ref:** BIP-22.

**Impact:** legacy mining software that requires `coinbasetxn` mode
cannot use haskoin's GBT.  Niche but documented in BIP-22.

---

## BUG-19 (P0-CDIV) — `!signet` rule not added to `rules` array on signet

**Severity:** P0-CDIV.  Core mining.cpp:959-963:

```cpp
if (consensusParams.signet_blocks) {
    aRules.push_back("!signet");
}
```

The `!` prefix marks the rule as MANDATORY — clients that don't
understand it MUST refuse to mine.  Signet block-solution requires
adding a signed challenge to the coinbase witness; a miner that
doesn't know this produces invalid signet blocks.

haskoin (`Rpc.hs:2796`):

```haskell
rules = ["csv" :: Text, "!segwit"] ++ activeNames
```

Hardcoded to `csv` + `!segwit` + the active deployment names; no
signet branch.  On signet, the rules array silently omits `!signet`.

**File:** `src/Haskoin/Rpc.hs:2792-2796`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:959-963`.

**Impact:** signet miners using haskoin's GBT see no `!signet` rule
in the array, assume "no special signet handling required", and
produce invalid signet blocks.  Cross-cite BUG-4 (server-side signet
rule-set enforcement also missing) — the two stack: client doesn't
declare support, server doesn't enforce support, template lacks the
rule.  Triply broken on signet.

---

## BUG-20 (P1) — `submitblock` does not pre-check the block index; duplicate submits fall through to "rejected"

**Severity:** P1.  Core's `submitblock` (mining.cpp:1086-1099):

```cpp
{
    LOCK(cs_main);
    const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
    if (pindex) {
        chainman.UpdateUncommittedBlockStructures(block, pindex);
    }
}
bool new_block;
auto sc = std::make_shared<submitblock_StateCatcher>(block.GetHash());
chainman.m_options.signals->RegisterSharedValidationInterface(sc);
bool accepted = chainman.ProcessNewBlock(blockptr, /*force_processing=*/true,
                                          /*min_pow_checked=*/true, &new_block);
chainman.m_options.signals->UnregisterSharedValidationInterface(sc);
if (!new_block && accepted) {
    return "duplicate";
}
if (!sc->found) {
    return "inconclusive";
}
return BIP22ValidationResult(sc->state);
```

So duplicate detection happens via `ProcessNewBlock`'s `&new_block`
out-param: a known block returns `accepted=true, new_block=false` →
`"duplicate"`.

haskoin's `submitBlock` (`BlockTemplate.hs:484-639`) does NOT pre-check
whether the block is already known.  The flow is:
1. `Map.lookup prevHash entries` — for a duplicate-block submit, the
   parent IS known.
2. `validateFullBlockIO` — for a duplicate-block submit, this might
   fail or succeed depending on whether validation is idempotent.
3. `applyBlockToCache` — likely fails because the UTXOs would already
   be spent.
4. `connectBlock` — fails because the parent isn't the active tip
   (the duplicate's parent IS the tip's parent, not the tip itself).

The error string returned from connectBlock falls into `bip22ResultString`
(`Rpc.hs:3066`) which maps to `"rejected"` (the catch-all at line
3025) — NOT `"duplicate"`.

The `addHeader` short-circuit at `Consensus.hs:3955-3957` DOES detect
already-known headers (`Just existing -> return $ Right existing`) but
that check is unreachable because the duplicate-block hash IS in the
entries — but `submitBlock`'s flow looks up the PARENT's entry, not
the block's own entry.

**File:** `src/Haskoin/BlockTemplate.hs:484-516` (no own-hash pre-check).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1086-1099`.

**Impact:** mining-pool failover scenarios (block submitted twice by
two redundant pool processes) see `"rejected"` instead of
`"duplicate"`; the failover logic may interpret this as a real
rejection and trigger reorg-recovery code.  Cross-impl divergence
with Core.

---

## BUG-21 (P1) — `UpdateUncommittedBlockStructures` not called before submit; missing-witness-magic blocks rejected

**Severity:** P1.  Core's `submitblock` calls
`chainman.UpdateUncommittedBlockStructures(block, pindex)` BEFORE
processing (mining.cpp:1088).  This patches up a block that's missing
the BIP-141 witness commitment OP_RETURN (writing the commitment
output) and/or the witness reserved-value nonce in the coinbase.

haskoin's `handleSubmitBlock` (`Rpc.hs:3043-3068`) goes straight from
decode to `submitBlock` (`BlockTemplate.hs:484`).  No patch step.  A
block submitted with a correct merkle root but missing
witness-commitment OP_RETURN is rejected with `bad-witness-merkle-match`
even though Core would patch + accept.

**File:** `src/Haskoin/Rpc.hs:3043-3068`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1086-1090`.

**Impact:** edge-case interop break — most modern mining software
constructs the OP_RETURN correctly so this rarely fires, but legacy
or naive miners get unexpected rejections.

---

## BUG-22 (P1) — `bip22ResultString` doesn't map raw `bad-blk-length` (only weight-exceeded)

**Severity:** P1.  Core's BIP22ValidationResult returns the consensus
reject string verbatim.  `bad-blk-length` fires when the SERIALIZED
block size exceeds MAX_BLOCK_SERIALIZED_SIZE = 4MB (consensus/tx_check
+ block-receive); separately, weight exceedance fires
`bad-blk-weight`.

haskoin's `bip22ResultString` (`Rpc.hs:2966`) only maps `"exceeds
maximum weight"` → `"bad-blk-length"`.  It conflates the two distinct
Core strings:
- raw size > 4MB → `bad-blk-length` (Core)
- weight > 4000000 → `bad-blk-weight` (Core) — NOT mapped to
  `bad-blk-length`; that's wrong.

**File:** `src/Haskoin/Rpc.hs:2966`.

**Core ref:** consensus/tx_check.cpp + validation.cpp.

**Impact:** wire-string parity gap — submitting a block whose weight
exceeds the cap returns `bad-blk-length` instead of `bad-blk-weight`.
Cross-cite W154 BUG-1 + BUG-15 (pre-segwit blocks have NO cap at all
in haskoin's CheckBlock — so the path that would produce
`bad-blk-length` doesn't even fire).

---

## BUG-23 (P1) — `getmininginfo` missing `currentblockweight` + `currentblocktx`

**Severity:** P1.  Core emits these (mining.cpp:467-468) from
`BlockAssembler::m_last_block_weight` / `m_last_block_num_txs` — the
last template's weight and tx count.  Mining-pool monitoring tools
scrape these to track per-block assembler health and chunk-selection
fullness.

haskoin's `handleGetMiningInfo` (`Rpc.hs:3088-3098`) emits neither
field.  No equivalent state is maintained on the haskoin side.

**File:** `src/Haskoin/Rpc.hs:3073-3100`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:467-468`.

**Impact:** monitoring observability gap; no assembler-health metric.

---

## BUG-24 (P1) — `networkhashps` permanently hardcoded to 0

**Severity:** P1.  Core (mining.cpp:472) routes networkhashps through
the dedicated RPC handler: `obj.pushKV("networkhashps",
getnetworkhashps().HandleRequest(request))`.

haskoin's `handleGetMiningInfo` (`Rpc.hs:3094`):

```haskell
pair "networkhashps" (AE.int 0)
```

Hardcoded to 0.  There IS a `handleGetNetworkHashPS` handler
(`Rpc.hs:1140`) — but it's never called from getmininginfo.

**File:** `src/Haskoin/Rpc.hs:3094`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:472`.

**Impact:** monitoring tools that scrape networkhashps from
getmininginfo see permanent 0.  Fleet pattern:
**already-exports-the-primitive-just-not-called** — 6th distinct
haskoin instance.  Trivial 1-line fix.

---

## BUG-25 (P2) — `warnings` field is string not array (Core's default since deprecation)

**Severity:** P2.  Core's getmininginfo (`mining.cpp:443-450`) emits
`warnings` as an ARRAY by default; only emits a string under
`-deprecatedrpc=warnings`.  haskoin (`Rpc.hs:3098`):

```haskell
pair "warnings" (text "")
```

Always emits a string.  Monitoring tools that strictly parse warnings
as array see a type error.

**File:** `src/Haskoin/Rpc.hs:3098`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:443-450`.

**Impact:** schema-strict monitoring breaks.  Trivial to fix.

---

## BUG-26 (P1) — `blockmintxfee` hardcoded; no `-blockmintxfee` operator knob

**Severity:** P1.  Core (mining.cpp:474-476) routes through
`BlockAssembler::Options.blockMinFeeRate` which is settable via
`-blockmintxfee=N` (BTC/kvB).  haskoin (`Rpc.hs:3093`):

```haskell
pair "blockmintxfee" (btcAmountEnc 1000)
```

Hardcoded to 1000 sat/vB (= MIN_RELAY_TX_FEE × 1000? unclear — the
unit semantics aren't documented in the line).  No operator knob.

**File:** `src/Haskoin/Rpc.hs:3093`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:474-476`.

**Impact:** no-operator-knob fleet pattern; operators can't tune the
template's chunk-selection floor.  Companion to W149 BUG-5
(`-assumevalid` absent), W148 (etc.) — pattern of CLI flag missing
even when the underlying value is consumed.

---

## BUG-27 (P0-CDIV) — `selectTransactions` ignores `mpFeeDeltas`; `prioritisetransaction` would be inert even if wired

**Severity:** P0-CDIV.  Bitcoin Core's BlockAssembler chunk-selection
sorts by **modifiedFee** (= `entry.GetFee() + entry.GetModifiedFee()`),
where `GetModifiedFee()` reads `mapDeltas` (the prioritisetransaction
deltas).  This is what makes prioritisetransaction actually move a tx
up the selection order.

haskoin's `selectTransactions` (`Mempool.hs:2076-2098`):

```haskell
let ancestorFeeRate entry =
      let totalFees = meAncestorFees entry
          totalSize = meAncestorSize entry
      in if totalSize == 0 then 0
         else (totalFees * 1000) `div` fromIntegral totalSize
let sorted = sortBy (comparing (Down . ancestorFeeRate)) (Map.elems entries)
```

Sorts by raw `meAncestorFees` — NEVER reads `mpFeeDeltas`.  Compare
with the admit-side gate (`Mempool.hs:859-870`) which DOES read
mpFeeDeltas and computes modifiedFee for the min-relay-fee check.
Same field, **inconsistent consumers**.

So even if BUG-1 were fixed (RPC writer added), prioritised txs would
still be sorted by their base fee in the template — defeating the
purpose.

**File:** `src/Haskoin/Mempool.hs:2076-2098` (no mpFeeDeltas lookup);
cross-cite admit-side `Mempool.hs:859-870` (DOES read).

**Core ref:** `bitcoin-core/src/node/miner.cpp` BlockAssembler chunk
selector, `bitcoin-core/src/txmempool.h::CTxMemPoolEntry::GetModifiedFee`.

**Excerpt (haskoin, ignores deltas)**
```haskell
let totalFees = meAncestorFees entry        -- raw, NOT modifiedFee
    totalSize = meAncestorSize entry
in if totalSize == 0 then 0
   else (totalFees * 1000) `div` fromIntegral totalSize
```

**Impact:**
- BUG-1 + BUG-27 combine to make prioritisetransaction completely
  non-functional even after the RPC is wired: the field would persist,
  the admit gate would honour it, but the mining template would never
  select-up the prioritised tx.
- **Two-pipeline guard 19th distinct extension** — first instance
  where the SAME field is consumed inconsistently across mempool
  subsystems within a single impl (admit-side vs select-side).
- Cross-impl divergence: every Core-parity wallet that uses
  prioritisetransaction sees a no-op on haskoin.

---

## BUG-28 (P1) — Carry-forward W154 BUG-17: no `TestBlockValidity` self-test after template construction

**Severity:** P1.  Carry-forward (W154 → W155, two-wave).  Core
mining.cpp:223-228 runs `TestBlockValidity` inside `createNewBlock`
AFTER coinbase construction, with `check_pow=false,
check_merkle_root=false`.  This catches self-inflicted bugs early
(e.g. bad-cb-length on low-height regtest blocks).

haskoin's `createBlockTemplate` (`BlockTemplate.hs:201-295`) returns
immediately after building the template; no self-test.  Combined with
W154 BUG-10 (1-byte scriptSig for heights 1..16) and W154 BUG-1 (no
size cap pre-segwit), the GBT path silently hands miners templates
that would be rejected at submit time.

**File:** `src/Haskoin/BlockTemplate.hs:201-295`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:223-228`.

**Impact:** ergonomic; defects in the template construction propagate
to submit time instead of being caught locally.  Two-wave carry-forward.

---

## BUG-29 (P1 cross-cite W154 BUG-19) — Regtest `generateSingleBlock` divergent from canonical `createBlockTemplate` path

**Severity:** P1.  Carry-forward (W154 → W155, two-wave).
`generateSingleBlock` (`Rpc.hs:3252-3317`) is a complete
re-implementation that disagrees with `createBlockTemplate` /
`assembleBlock` / `submitBlock` on at least 6 distinct points (cited
in W154 BUG-19): coinbase encoding (W108), `selectTransactions`
reservation (4000 vs 8000), bits derivation (hardcoded 0x207fffff vs
`difficultyAdjustment`), fee handling (subsidy only — W154 BUG-18),
witness-commitment generation (absent — see BUG-16 above), and
nSequence/nLockTime divergence.

The W155 angle: the GBT-path templates already differ from
`generateSingleBlock` outputs.  An operator who uses GBT-then-submit on
regtest sees one block layout; an operator who uses `generate` /
`generatetoaddress` sees another.  They are not interchangeable;
testing against one does not validate the other.

**File:** `src/Haskoin/Rpc.hs:3252-3317`.

**Core ref:** unified Core path via single `createNewBlock`.

**Impact:** **two-pipeline-at-consensus-boundary-that-self-rejects**
fleet pattern, 4th distinct haskoin instance (carry-forward W154
BUG-19; companion to BUG-27 above which extends two-pipeline-guard to
the mempool field-consumer drift).

---

## Summary

**Bug count:** 29 (BUG-1 through BUG-29).

**Severity distribution:**
- **P0-CDIV:** 10 (BUG-1, BUG-4, BUG-5, BUG-7, BUG-12, BUG-14, BUG-15, BUG-16, BUG-19, BUG-27)
- **P1:** 18 (BUG-2, BUG-3, BUG-6, BUG-8, BUG-9, BUG-10, BUG-11, BUG-13, BUG-17, BUG-18, BUG-20, BUG-21, BUG-22, BUG-23, BUG-24, BUG-26, BUG-28, BUG-29)
- **P2:** 1 (BUG-25)

**Fleet patterns confirmed:**
- **"already-exports-the-primitive-just-not-called"** (5 distinct
  fields this wave: `mpFeeDeltas` BUG-1, `addHeader` BUG-2,
  `meWtxid` cached field, `btWitnessCommitment` BUG-16,
  `btCoinbaseTxn` BUG-18; **also** `handleGetNetworkHashPS` BUG-24
  not wired into `handleGetMiningInfo`) — confirms 6 distinct fields
  per wave; cumulative 6 across waves
- **"comment-as-confession"** (BUG-5 proposal stub admits noop;
  BUG-10 longpollid divergence admits "for simplicity"; BUG-16
  witness-commitment stub admits "for now") — 8th, 9th, 10th
  distinct haskoin instances
- **"two-pipeline guard, 19th distinct extension"** (BUG-27 — same
  `mpFeeDeltas` field consumed inconsistently across mempool
  subsystems within one impl: admit-side reads, select-side ignores)
- **"two-pipeline-at-consensus-boundary-that-self-rejects"** (BUG-14
  mintime / BIP-94, BUG-15 pre-segwit sizelimit/weightlimit; BUG-29
  regtest miner — pattern: the GBT template emits values the
  haskoin validator's own gate would reject)
- **"dead field"** (3 instances: `btCoinbaseTxn`, `btWitnessCommitment`,
  `btDefaultWitnessNonce` — all populated, none consumed by RPC)
- **"hardcoded constant should be operator-knob"** (BUG-24 networkhashps;
  BUG-26 blockmintxfee; BUG-25 warnings array shape)
- **"no operator knob"** (BUG-26 -blockmintxfee absent; symmetric to
  W149 BUG-5 `-assumevalid`, W148 etc.)
- **"30-of-30-gates-buggy" / subsystem-rewrite candidate** —
  `handleBlockProposal` (BUG-5 + BUG-6: every consensus check
  skipped); `handleGetMiningInfo` (BUG-17/23/24/25/26 = 5 distinct
  fields wrong or absent); 3rd instance of the pattern this wave
- **"carry-forward"** — W154 BUG-15 (`meWtxid` ignored, see G21),
  W154 BUG-16 (mintime BIP-94, see BUG-14), W154 BUG-17
  (`TestBlockValidity` self-test, see BUG-28), W154 BUG-19
  (regtest miner two-pipeline, see BUG-29); W108 BUG-15 →
  W154 BUG-20 → W155 BUG-1 (3-wave open prioritisetransaction)
- **"wire-string parity slippage"** (BUG-10 longpollid format; BUG-19
  `!signet` rule omission; BUG-22 bad-blk-length conflation)

**Top three findings:**
1. **BUG-5 (P0-CDIV proposal-mode noop)** — `handleBlockProposal`
   skips `TestBlockValidity` entirely and returns `null` for ALL
   proposed blocks.  BIP-23 proposal mode is non-functional;
   stratum proxies that use it as a sanity check fail to detect
   any invalid block.  Inline comment confesses the stub.  Most
   severe finding because the entry point is fully reachable from
   the public RPC surface and silently accepts garbage.
2. **BUG-16 (P0-CDIV default_witness_commitment empty)** —
   `buildWitnessCommitmentScript` always returns `BS.empty`, so the
   `default_witness_commitment` field is NEVER emitted by GBT.  The
   `BlockTemplate.btWitnessCommitment` field IS correctly populated
   but the RPC encoder ignores it.  Mining software dependent on
   BIP-145 (the entire modern mining stack) cannot construct correct
   coinbases.  Cross-impl divergence with Core.  Fleet pattern:
   already-exports-the-primitive-just-not-called.
3. **BUG-1 + BUG-27 prioritisetransaction cluster** — the RPC writer
   is absent (BUG-1), and even if added, the mempool select-side
   ignores the deltas (BUG-27).  Two-pipeline-guard 19th distinct
   extension where the same field is consumed inconsistently across
   mempool subsystems within one impl.  Carry-forward 3-wave open
   (W108 → W154 → W155).

**Specifically-asked-for checks:**
- (a) coinbasevalue JSON NUMBER not String: **PASS** (Word64 via
  aeson `.=`)
- (b) sizelimit MAX_BLOCK_SERIALIZED_SIZE=4000000 post-segwit:
  PARTIAL — emitted, but no pre-segwit halving (BUG-15)
- (c) longpollid present: PASS (decorative, BUG-9 + BUG-10)
- (d) mutable[] array: PASS
- (e) rules:["segwit"] acknowledged: **FAIL** (BUG-4 client-side
  rule-set enforcement absent)
- (f) vbavailable BIP-9: PASS
- (g) default_witness_commitment post-segwit: **FAIL** (BUG-16
  permanently empty)
- (h) per-tx depends: **FAIL** (BUG-12 0-based instead of 1-based)
- (i) per-tx fee+sigops: PARTIAL — emitted, but no pre-segwit halving
  for sigops (BUG-13)
- (j) submitblock BIP22ValidationResult string: PASS
- (k) prioritisetransaction RPC: **FAIL** (BUG-1 absent)
- (l) coinbasetxn mode: **FAIL** (BUG-18 dead field, never emitted)
- (m) noncerange: PASS
- (n) mintime + BIP-94: **FAIL** (BUG-14, carry-forward W154
  BUG-16 / W143 BUG-10 dead validateBlockHeader path)
- (o) curtime clock skew: PASS

29 bugs across 23 behaviour categories.  10 P0-CDIV, 18 P1, 1 P2.
Top BIP-22/23 spec-compliance gaps: proposal-mode noop, no rule-set
enforcement, default_witness_commitment empty, depends off-by-one,
no IBD guard.
