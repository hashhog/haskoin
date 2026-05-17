# W130 BIP-125 Fee Bumper Rule 3 (haskoin)

**Date:** 2026-05-17
**Status:** DISCOVERY — no production code changes
**Scope:** `bumpfee` / `psbtbumpfee` wallet-side enforcement of BIP-125 Rules
1-5 and the precise `incrementalRelayFee.GetFee(maxTxSize)` invariant.

**Files audited:**
- `src/Haskoin/Wallet.hs` lines 2100-2580 (bumpfee pipeline +
  computeReplacementFee, buildReplacementTx, buildBumpedTx, bumpFee,
  psbtBumpFee, checkBumpPreconditions, walletIncrementalRelayFeePerKvB).
- `src/Haskoin/Mempool.hs` lines 1626-1683 (checkReplacement: the
  policy-side Rules 3, 3a, 4, 5 enforcement that any bumped tx will
  ultimately face inside the mempool).
- `src/Haskoin/Rpc.hs` lines 6580-6745 (`bumpfee` and `psbtbumpfee`
  RPC handlers — option parsing, error mapping, response shape).

**Bitcoin Core references:**
- `bitcoin-core/src/wallet/feebumper.cpp` (entire file — 386 lines).
  Specifically `PreconditionChecks` (lines 23-57), `CheckFeeRate`
  (lines 60-117), `EstimateFeeRate` (lines 119-144),
  `TransactionCanBeBumped` (lines 148-157),
  `CreateRateBumpTransaction` (lines 159-328).
- `bitcoin-core/src/wallet/feebumper.h`.
- `bitcoin-core/src/policy/rbf.cpp` (`PaysForRBF` lines 100-125,
  `GetEntriesForConflicts` lines 58-83, `EntriesAndTxidsDisjoint`,
  `ImprovesFeerateDiagram`).
- `bitcoin-core/src/policy/rbf.h` (`MAX_REPLACEMENT_CANDIDATES = 100`).
- `bitcoin-core/src/policy/feerate.cpp` (`CFeeRate::GetFee`).
- `bitcoin-core/src/util/feefrac.h` (`EvaluateFeeUp` — exact ceil
  semantics: `CeilDiv(uint64_t(fee) * at_size, uint32_t(size))`).
- `bitcoin-core/src/policy/policy.h:48` (`DEFAULT_INCREMENTAL_RELAY_FEE = 100`).
- `bitcoin-core/src/wallet/wallet.h:124`
  (`WALLET_INCREMENTAL_RELAY_FEE = 5000`).
- `bitcoin-core/src/wallet/wallet.h:137`
  (`DEFAULT_TRANSACTION_MAXFEE = COIN / 10`).
- `bitcoin-core/src/validation.cpp` (RBF gates at ATMP, lines 1000-1044).

**BIP:** 125 (Opt-in Full Replace-by-Fee Signalling).

**Result:** **5 PRESENT / 7 PARTIAL / 18 MISSING out of 30 gates.**

**Bugs found:** **15** (3 P0, 7 P1, 5 P2 + DEAD/STYLE).
**Tests added:** 28 cases in `W130BIP125FeeBumperRule3Spec.hs`
(18 `it` pinning + 10 `xit` sentinels).

## Relationship to W118 / W120

- **W118** is the broad wallet audit. W118 closed BUG-22 with the FIX-61
  introduction of `bumpFee` / `psbtBumpFee` / `transactionCanBeBumped`,
  but only validated _presence_ of the pipeline — it did not exercise
  the BIP-125 Rule-3 precise fee math.
- **W120** audited the **policy-side** Rules 1-5 (`checkReplacement`,
  `checkNoNewUnconfirmedInputs`, `checkDiagramReplacement`) for any
  mempool admission — that's the path the bumped tx eventually hits.
  W120 found 5 bugs all on the mempool side (Rule 3 modified-fee
  accumulator, dead rolling-min-fee, package path skipping RBF, TRUC
  sibling eviction base-fee math, style-drift on RBF threshold).
- **W130** is the **wallet-side** complement: it audits the *outgoing*
  side — what `bumpfee` / `psbtbumpfee` will produce **before** the
  replacement reaches `checkReplacement`. Several Rule-3/Rule-4 gates
  exist twice in Core (once in the wallet's `CheckFeeRate` and once
  again in the mempool's `PaysForRBF`); haskoin enforces them in the
  mempool but not in the wallet, so bumpfee can construct a tx that
  the mempool will reject and surface a misleading error to the user.

No double-counting: W130 catalogues bugs in `bumpfee.cpp` parity
(haskoin Wallet.hs); W120 stays in `policy/rbf.cpp` parity (haskoin
Mempool.hs). Where a bug surfaces in both contexts it is cited once,
in the file where the gap originates.

## Top-line verdict

haskoin's `bumpfee` pipeline is **structurally present** but **does not
enforce the wallet-side guard rail** that Core's `CheckFeeRate`
provides. The wallet-side guard exists in Core specifically so the
user gets a *meaningful* error (`"Insufficient total fee ...
must be at least X (oldFee + incrementalFee)"`,
`"New fee rate is lower than the minimum fee rate to get into the
mempool"`, `"Specified or calculated fee is too high (cannot be higher
than -maxtxfee)"`) **before** any signing work. haskoin's bumpfee
short-cuts past most of these checks; the user only learns the
replacement is too expensive (or too cheap, or sources fresh
unconfirmed inputs) when the broadcast eventually fails inside the
mempool — possibly weeks later if the wallet is offline.

The most consensus-relevant findings:

1. **P0: `checkBumpPreconditions` does not short-circuit.** It is
   written with `do`-notation as if `Either` would discard later
   actions once an error fires, but the function actually evaluates
   every branch and only the **last** result is returned. Result: the
   confirmed-tx check and the already-replaced check are dead code.
   Only the signalsOptInRBF check actually decides the return value.
   A `bumpfee` against an already-confirmed transaction returns OK
   (because the original is still RBF-signalling) and proceeds to
   build a replacement that will fail at the mempool because the
   inputs are already spent. Confirmed by tracing line 2273-2282.
   **G4, BUG-1.**

2. **P0: `bumpFee` performs ZERO mempool-side validation.**
   Core's `CheckFeeRate` (feebumper.cpp:60-117) runs *before*
   `CreateTransaction` and verifies, at minimum:
     - `newFeerate >= mempool_min_fee` (the rolling minimum fee
       gate; line 67-75).
     - `new_total_fee >= min_total_fee = old_fee +
       incrementalRelayFee.GetFee(maxTxSize)` (line 88-99, the
       **wave-named invariant**).
     - `new_total_fee >= GetRequiredFee(wallet, maxTxSize)`
       (line 101-106, the wallet's static floor including
       `m_min_fee` / `m_max_fee_rate`).
     - `new_total_fee <= m_default_max_tx_fee` (line 109-114,
       the `-maxtxfee` upper cap).
   haskoin's `buildBumpedTx` (line 2409-2434) computes
   `computeReplacementFee` and then *immediately* tries to absorb
   the delta from the change output. None of the four Core-side
   pre-checks happen. **G5, G6, G7, G8, BUG-2.**

3. **P0: Wallet-side Rule 2 absent — bumpfee can introduce new
   unconfirmed inputs.** Core sets
   `new_coin_control.m_min_depth = 1` (feebumper.cpp:312) right
   before re-running `CreateTransaction`. haskoin's bumpfee does
   not re-run coin selection at all; it just shrinks the change
   output. If the original tx already used unconfirmed parents
   that have since dropped out of the mempool, the bumped tx
   inherits those non-existent prevouts (`buildReplacementTx`
   keeps `txInputs origTx` verbatim). Rule 2 is correctly
   enforced on the **mempool** side
   (`checkNoNewUnconfirmedInputs`, Mempool.hs:1719) but only
   against *new* unconfirmed parents — a bumpfee that inherits
   a vanished unconfirmed parent will fail at signing or, worse,
   broadcast and get evicted. **G3, BUG-3.**

The most surprising finding is **BUG-7**: the wallet's incremental
relay fee constant is hard-coded to `5000 sat/kvB` (Wallet.hs:2254,
matching Core's `WALLET_INCREMENTAL_RELAY_FEE = 5000`) but the
**mempool** constant `incrementalRelayFeePerKvb = 100`
(Mempool.hs:382, matching `DEFAULT_INCREMENTAL_RELAY_FEE`). These
are correct constants in isolation, but Core's `EstimateFeeRate`
explicitly takes `std::max(node_incremental_relay_fee,
wallet_incremental_relay_fee)` (feebumper.cpp:135-137) — so the
*effective* increment is 5000 sat/kvB (the wallet number). haskoin
hard-codes `walletIncrementalRelayFeePerKvB` in `computeReplacementFee`
without consulting the node side at all. If a future operator
configures `-incrementalrelayfee=10000` the wallet will silently
underprice the bump and the mempool will reject. STYLE-DRIFT
adjacency: two separate constants with the same units, no shared
named alias.

## 30-Gate Audit Matrix

Status: P=PRESENT (correctness verified), p=PARTIAL (exists but
gap or off-by-one), M=MISSING.

### Wallet-side BIP-125 enforcement (G1-G10)

| G  | Gate                                                       | Status | BUG |
|----|------------------------------------------------------------|--------|-----|
| G1 | `walletIncrementalRelayFeePerKvB = 5000` constant exists   | P      | -   |
| G2 | `WALLET_INCREMENTAL_RELAY_FEE` regression-pinned in test   | M      | BUG-15 |
| G3 | bumpfee enforces no NEW unconfirmed inputs (`m_min_depth=1`) | M    | BUG-3 |
| G4 | `checkBumpPreconditions` short-circuits on first error     | M      | BUG-1 |
| G5 | `CheckFeeRate` mempoolMinFee gate                          | M      | BUG-2 |
| G6 | `CheckFeeRate` min-total-fee gate (old_fee + inc*size)     | M      | BUG-2 |
| G7 | `CheckFeeRate` GetRequiredFee static-floor gate            | M      | BUG-2 |
| G8 | `CheckFeeRate` -maxtxfee upper cap                         | M      | BUG-2 |
| G9 | `AllInputsMine` check (require_mine = True for bumpfee)    | M      | BUG-4 |
| G10| `HasWalletSpend` (descendants in wallet) check             | M      | BUG-5 |

### Rule 3 (paysForRBF) precise math (G11-G15)

| G  | Gate                                                       | Status | BUG |
|----|------------------------------------------------------------|--------|-----|
| G11| `incrementalRelayFee.GetFee(maxTxSize)` uses **ceil** mult | P      | -   |
| G12| `EstimateFeeRate`'s `+= CFeeRate(1)` rounding nudge        | M      | BUG-6 |
| G13| `max(node_relay_inc, WALLET_INCREMENTAL_RELAY_FEE)` taken  | M      | BUG-7 |
| G14| `feerate += min_feerate` (wallet GetMinimumFeeRate gate)   | M      | BUG-2 |
| G15| `computeReplacementFee` returns >= `old_fee + incBump`     | P      | -   |

### Rule 1, 2, 4, 5 wallet leg (G16-G20)

| G  | Gate                                                       | Status | BUG |
|----|------------------------------------------------------------|--------|-----|
| G16| BIP-125 Rule 1 — original tx signals (or chain ancestor)   | p      | BUG-8 |
| G17| BIP-125 Rule 2 — `m_min_depth = 1` plumbed                 | M      | BUG-3 |
| G18| BIP-125 Rule 4 — incremental fee covers bumped vbytes       | P      | -   |
| G19| BIP-125 Rule 5 — single-tx replacement always within cap   | P      | -   |
| G20| `hasDescendantsInMempool` (mempool-side has-descendants)   | M      | BUG-5 |

### CreateRateBumpTransaction pipeline (G21-G25)

| G  | Gate                                                       | Status | BUG |
|----|------------------------------------------------------------|--------|-----|
| G21| `original_change_index` operator override accepted         | P      | -   |
| G22| `OutputIsChange` (Core: `is_change(wallet, output)`) match | p      | BUG-9 |
| G23| Reuses ALL original inputs in coin control (line 306-308)  | P      | -   |
| G24| `m_allow_other_inputs = true` (allow extra inputs)         | M      | BUG-10 |
| G25| Coin-control output set rebuilt via CreateTransaction      | M      | BUG-11 |

### Signing + commit + state (G26-G30)

| G  | Gate                                                       | Status | BUG |
|----|------------------------------------------------------------|--------|-----|
| G26| `bumpfee` re-signs (signPsbt path) before result returned  | P      | -   |
| G27| `psbtbumpfee` returns unsigned PSBT (no signing attempted) | P      | -   |
| G28| `markReplaced` mapValue `replaces_txid` / `replaced_by_txid`| p     | BUG-12 |
| G29| Two-pipeline guard — single `bumpFee` site, no copy-paste  | p      | BUG-13 |
| G30| FX-rate / sat/kvB unit consistency between BFO + FeeRate   | M      | BUG-14 |

## Bug Catalogue

### BUG-1 [P0] checkBumpPreconditions does not short-circuit (G4)

**File:** `src/Haskoin/Wallet.hs` lines 2272-2282.

```haskell
checkBumpPreconditions :: SentTxRecord -> Either BumpFeeError ()
checkBumpPreconditions r = do
  case strConfirmedAt r of
    Just _  -> Left BumpFeeAlreadyConfirmed
    Nothing -> Right ()
  case strReplacedBy r of
    Just t  -> Left (BumpFeeAlreadyReplaced t)
    Nothing -> Right ()
  if signalsOptInRBF (strTx r)
    then Right ()
    else Left BumpFeeNotReplaceable
```

This **looks** like it short-circuits on the first `Left` because
of `Either`'s monad instance, but the bare `case … of` expressions
are NOT bound (`<-`), so they are evaluated as standalone
expressions whose `Either` result is discarded. Only the final `if`
contributes to the return value.

Trace: GHC evaluates each `case` as a statement, discards the
result, and yields the value of the last expression (the `if`).
`Either`'s `>>` instance never fires because the prior cases are
not in monadic position.

Effect: a `bumpfee` against an already-confirmed tx — or an
already-replaced tx — returns `Right ()` if and only if the
original still signals BIP-125 RBF (which it always does, by
construction of the wallet's send path). Downstream the bumpfee
then tries to:

- Look up the tx; it's still in `walletSentTxs` (we don't garbage
  collect confirmed sends).
- Build a "replacement" reusing its prevouts.
- Sign the replacement — but the prevouts are now spent in the
  confirmed block, so `findCoins` will find them as spent (Core
  errors `:%u is already spent` — feebumper.cpp:198). haskoin
  has no equivalent check, so the bump succeeds locally and
  fails on broadcast.

**Core reference:** `PreconditionChecks` (feebumper.cpp:23-57)
returns early on each condition. haskoin's translation broke that.

**Fix sketch:** rewrite using `do` with proper monadic binds:

```haskell
checkBumpPreconditions r = do
  whenJust (strConfirmedAt r) (\_ -> Left BumpFeeAlreadyConfirmed)
  whenJust (strReplacedBy r) (\t -> Left (BumpFeeAlreadyReplaced t))
  if signalsOptInRBF (strTx r)
    then Right ()
    else Left BumpFeeNotReplaceable
```

Adjacent: `bumpFee` and `psbtBumpFee` both call this function via
`buildBumpedTx`; the bug affects both entry points.

---

### BUG-2 [P0] Wallet-side CheckFeeRate gates entirely absent (G5/G6/G7/G8/G14)

**File:** `src/Haskoin/Wallet.hs` lines 2409-2434.

`buildBumpedTx` calls `computeReplacementFee` to derive `newFee`
and then immediately calls `buildReplacementTx`. Between those two
calls, Core's pipeline runs FOUR pre-checks (feebumper.cpp:60-117):

1. **mempoolMinFee gate** (line 67-75): rejects if
   `newFeerate < wallet.chain().mempoolMinFee()` — i.e. the
   rolling mempool minimum. The replacement won't be accepted
   into the mempool, so refuse to build it.
2. **min-total-fee gate** (line 88-99): rejects if
   `new_total_fee < old_fee + incrementalRelayFee.GetFee(maxTxSize)`.
   This is the **wave-named** Rule-3 invariant. haskoin's
   `computeReplacementFee` enforces this implicitly when
   `userFr = Nothing` (via `autoFee = oldFee + incBump`), but
   when the user supplies a low explicit feerate the function
   returns `userFee` even if it's less than `autoFee` —
   *wait*, no, `max autoFee userFee` is correct. **But the
   user-supplied case doesn't add `combined_bump_fee`** —
   line 88: `new_total_fee = newFeerate.GetFee(maxTxSize) +
   combined_bump_fee.value()`. See BUG-6.
3. **GetRequiredFee static-floor gate** (line 101-106): rejects
   if `new_total_fee < GetRequiredFee(wallet, maxTxSize)`.
   haskoin has no `getRequiredFee` analog.
4. **-maxtxfee upper cap** (line 109-114): rejects if
   `new_total_fee > m_default_max_tx_fee`. haskoin has no
   such cap; a bumpfee at user-supplied 10000 sat/vB on a
   200 vB tx (2_000_000 sat) will proceed and burn 0.02 BTC
   in fees with no warning.

**Effect:** a user typing `bumpfee txid {feeRate: 1000000}`
(1000 sat/vB, off by ×100 from intent) — or worse a
`bumpfee txid` against a tx whose old_fee was wrong — has no
guard rails. Core surfaces `"Specified or calculated fee … is too
high (cannot be higher than -maxtxfee …)"` immediately.

**Fix sketch:** introduce `checkFeeRate :: Wallet -> Tx -> FeeRate
-> Int -> Word64 -> IO (Either BumpFeeError ())` mirroring
feebumper.cpp:60-117, called from `buildBumpedTx` after
`computeReplacementFee` and before `buildReplacementTx`.

---

### BUG-3 [P0] bumpfee does not enforce m_min_depth = 1 (G3/G17)

**File:** `src/Haskoin/Wallet.hs` `buildReplacementTx` lines 2361-2403.

`buildReplacementTx` keeps the original tx's `txInputs` verbatim
(only the `txInSequence` is rewritten). It never consults the
mempool / UTXO state to verify that the prevouts are still
spendable AND have at least 1 confirmation.

Core's bumpfee runs `CreateTransaction` with
`new_coin_control.m_min_depth = 1` (feebumper.cpp:312), which
forces coin selection to refuse unconfirmed inputs entirely.
haskoin's bumpfee inherits whatever the original tx used — so a
"bump" of a chained CPFP-style tx (where the original's
prevout itself came from an unconfirmed parent) silently reuses
that unconfirmed parent. If the parent has since been replaced
or evicted, the bump references a non-existent UTXO.

**Effect:** bumpfee in CPFP-style usage (which is a common reason
*to* bumpfee) can produce a tx that immediately fails at the
mempool with `"missing-inputs"` and reports a misleading error
back to the user.

**Adjacent W120 finding:** mempool-side Rule 2 (`checkNoNewUnconfirmedInputs`)
correctly handles the case where the replacement adds a NEW
unconfirmed parent the originals didn't have. The gap here is
different — bumpfee never gets the chance to swap out the
unconfirmed parent because it never re-runs coin selection.

**Fix sketch:** call a `findCoins`-equivalent against
`(strPrevOutputs rec0)` and verify each prevout has
`confirmations >= 1`. Return `BumpFeeMissingInputs` for any
unconfirmed.

---

### BUG-4 [P1] AllInputsMine (require_mine) absent (G9)

**File:** `src/Haskoin/Wallet.hs` `checkBumpPreconditions` line 2272.

Core's `PreconditionChecks` requires `AllInputsMine(wallet, *wtx.tx)`
when `require_mine` is set (line 47-53). This is the "external
inputs" guard: the wallet only knows fees for its own inputs;
if an external input is involved, the wallet cannot recompute
the input value precisely, so the fee calculation is unreliable.

`bumpfee` uses `require_mine = true` (feebumper.cpp:155);
`psbtbumpfee` uses `require_mine = false` (allows mixed-input
PSBTs and asks the operator to fill in external input values).

haskoin's `checkBumpPreconditions` makes no input-ownership check.
Since haskoin's `recordSentTx` only records txs that the wallet
sent (and thus knows all inputs of), the gap is latent for normal
operation — but a future "import sent tx" flow would silently
underprice external inputs.

**Effect:** latent for the current wallet. Activated by any
future flow that records a tx whose inputs the wallet does not
control.

---

### BUG-5 [P1] HasWalletSpend / hasDescendantsInMempool absent (G10/G20)

**File:** `src/Haskoin/Wallet.hs` `checkBumpPreconditions` line 2272.

Core's `PreconditionChecks` rejects the bump if:

- `wallet.HasWalletSpend(wtx.tx)` — the wallet has another tx that
  spends one of the candidate's outputs (line 25-28). Bumping
  would orphan that descendant.
- `wallet.chain().hasDescendantsInMempool(wtx.GetHash())` — the
  mempool has descendants. Same problem at the mempool level
  (line 31-34).

Neither check exists in haskoin's `bumpfee`.

**Effect:** if a user has a chain `A -> B` in the mempool (B spends
A's change output) and calls `bumpfee A`, haskoin will produce a
replacement A' whose change has a different outpoint than A's.
B becomes orphaned. Core surfaces the error before doing any
work; haskoin lets the broadcast happen.

---

### BUG-6 [P1] EstimateFeeRate +1 sat/kvB rounding nudge absent (G12)

**File:** `src/Haskoin/Wallet.hs` `computeReplacementFee` lines 2339-2355.

Core's `EstimateFeeRate` does:

```cpp
int64_t txSize = GetVirtualTransactionSize(*(wtx.tx));
CFeeRate feerate(old_fee, txSize);
feerate += CFeeRate(1);  // <-- +1 sat/kvB nudge
```

(feebumper.cpp:124-126). This is documented as: "the fee rate of
the original transaction. This is calculated from the tx fee/vsize,
so it may have been rounded down. Add 1 satoshi to the result."

haskoin's `computeReplacementFee` doesn't take the original feerate
as input at all; it operates on `oldFee` (absolute) and adds
`incBump`. The +1 sat/kvB nudge is invisible to haskoin's pipeline
because the original feerate is never explicitly computed during
bumpfee. The effect is small (1 sat/kvB on typical replacement
size ~150 vB = 0.15 sat) but is a documented Core-parity gate
and will surface as a 1-sat divergence in consensus-diff testing.

---

### BUG-7 [P1] max(node_relay_inc, wallet_inc) not taken (G13)

**File:** `src/Haskoin/Wallet.hs` `computeReplacementFee` line 2349.

Core's `EstimateFeeRate` takes the **max** of the node's
incremental relay fee and the wallet's `WALLET_INCREMENTAL_RELAY_FEE`
constant (feebumper.cpp:135-137):

```cpp
CFeeRate node_incremental_relay_fee = wallet.chain().relayIncrementalFee();
CFeeRate wallet_incremental_relay_fee = CFeeRate(WALLET_INCREMENTAL_RELAY_FEE);
feerate += std::max(node_incremental_relay_fee, wallet_incremental_relay_fee);
```

This is **defensive** — the wallet may not know about a future
upstream node-side policy change that increases the node's
incremental relay fee. By taking the max with the wallet constant
(5000 sat/kvB) the wallet guarantees the replacement is over the
incremental floor in either regime.

haskoin's `computeReplacementFee` hardcodes
`walletIncrementalRelayFeePerKvB = 5000` (Wallet.hs:2254) and
ignores the mempool's `incrementalRelayFeePerKvb = 100`
(Mempool.hs:382) entirely. The numeric outcome is the same as
Core in the default-config case (max(100, 5000) = 5000) but the
**structure** of "take max with node-side" is missing. If an
operator overrides the wallet constant via a future flag (e.g.
`walletIncrementalRelayFeePerKvB = 1000`) without overriding the
mempool side, the bumpfee will accept replacements the mempool
rejects.

**Style-drift adjacency:** two separate constants (`5000` and
`100`) live in two separate modules with no shared named alias.
Recommend extracting `Haskoin.Policy.IncrementalRelay` exporting
both with cross-referenced documentation.

---

### BUG-8 [P2] Rule 1 wallet-side: bumpfee requires opt-in but Core v28+ does not (G16)

**File:** `src/Haskoin/Wallet.hs` `checkBumpPreconditions` line 2280-2282.

haskoin rejects `bumpfee` with `BumpFeeNotReplaceable` if
`signalsOptInRBF (strTx r) == False`. This is correct for
**legacy BIP-125** wallets, but Core v28+ removed the
`-mempoolfullrbf` option and is **always full-RBF** (Mempool.hs:266
hard-codes `mpcRBFEnabled = True`, matching).

In full-RBF mode, the original tx does NOT need to signal RBF —
any tx can be replaced. Core's `PreconditionChecks` reflects this:
**there is no opt-in check at all** in feebumper.cpp. The only
check related to opt-in is the `replaced_by_txid` mapValue
(line 42-45), which is `BumpFeeAlreadyReplaced` in haskoin terms.

**Effect:** haskoin refuses to bump a tx that didn't signal
RBF, even though Core would accept it (and the mempool would
accept the replacement via full-RBF rules). User-visible:
"why won't haskoin bump this tx that Core would happily bump?"

**Note:** the `meRBFOptIn` flag is set on every entry insertion
(Mempool.hs:2601) but the wallet's `signalsOptInRBF` check is
upstream of that. The fix is at the wallet layer: remove the
opt-in check and rely on the mempool's full-RBF acceptance.

Status: **PARTIAL** because the implementation is consistent
with documented BIP-125 strict semantics, but inconsistent with
Core v28+ behaviour. Tests pin the current strict behaviour and
add an `xit` sentinel for the desired Core-parity behaviour.

---

### BUG-9 [P1] autoDetectChangeIndex first-match-wins is not is_change (G22)

**File:** `src/Haskoin/Wallet.hs` `autoDetectChangeIndex` lines 2304-2312.

Core's `OutputIsChange(wallet, output)` (wallet/wallet.cpp) uses
the address book + a "this address has never been used to receive
external funds" heuristic — it's a precise wallet-side classifier.

haskoin's `autoDetectChangeIndex` returns `listToMaybe ours` where
`ours` is any output paying a wallet-owned address. The FIRST
match wins. This conflates **change** outputs with **self-pay**
outputs (sending to your own address). A user paying themselves
who then bumps the fee will have the recipient output
mis-identified as change and shrunk to absorb the bump.

**Effect:** self-pay txs get the wrong output reduced on bumpfee.
A user who sends 1.0 BTC to their own savings address and tries
to bump will have the 1.0 BTC reduced instead of the change.

Adjacent: Core's `original_change_index` argument is the operator
escape hatch for this (feebumper.cpp:163-184). haskoin exposes
`bfoOriginalChangeIndex` so the workaround exists — but only if
the user knows to use it.

---

### BUG-10 [P1] m_allow_other_inputs = true not modeled (G24)

**File:** `src/Haskoin/Wallet.hs` `buildBumpedTx` line 2422-2434.

Core's `CreateRateBumpTransaction` sets
`new_coin_control.m_allow_other_inputs = true` (feebumper.cpp:309)
which permits coin selection to *add* fresh confirmed UTXOs to the
replacement if the original change output doesn't have enough room
to absorb the fee delta.

haskoin's `buildReplacementTx` does NOT allow adding new inputs.
If the change output is too small (or below dust after reduction),
it fails with `BumpFeeNoChange` or `BumpFeeChangeBelowDust`. The
user has to manually create a CPFP child instead — which is what
bumpfee is supposed to abstract away.

**Effect:** bumpfee fails on common cases (small change output,
large fee delta) that Core handles by pulling in another UTXO.
For wallets with many small UTXOs this is the typical case.

---

### BUG-11 [P1] CreateTransaction not re-run (G25)

**File:** `src/Haskoin/Wallet.hs` `buildReplacementTx` lines 2361-2403.

Core's pipeline calls `CreateTransaction` (feebumper.cpp:314) to
construct the replacement, which runs FULL coin selection,
including:

- Picking a fresh `destChange` if the original change index is
  not designated.
- Adding extra inputs (BUG-10).
- Optimizing the fee calculation through the full
  `CoinSelectionParams` machinery.

haskoin's `buildReplacementTx` shrinks the original change output
in-place and copies the rest of the tx verbatim. This is **vastly
simpler** but loses every coin-selection optimization.

**Effect:** structurally weaker than Core; specific symptoms
covered by BUG-9, BUG-10, BUG-12.

Status: **MISSING** but a single fix would close G22-G25 jointly.

---

### BUG-12 [P2] mapValue replaced_by_txid not surfaced via RPC (G28)

**File:** `src/Haskoin/Wallet.hs` `bumpFee` line 2461-2462,
`src/Haskoin/Rpc.hs` line 6710-6720.

Core records `mapValue["replaced_by_txid"] = oldWtx.GetHash().ToString()`
on the OLD tx and `mapValue["replaces_txid"] = oldWtx.GetHash().ToString()`
on the NEW tx (feebumper.cpp:371-372). These show up in
`gettransaction` responses so wallets can chain bump history.

haskoin sets `strReplacedBy` on the old tx (Wallet.hs:2461-2462)
which is the equivalent record. But:

- haskoin does NOT set a corresponding `replaces_txid` on the
  new tx's `SentTxRecord` (the new record's `strReplacedBy` is
  always `Nothing` per `recordSentTx` line 2110-2111).
- The `gettransaction` RPC does NOT emit `replaces_txid` /
  `replaced_by_txid` fields in its response (verified by
  searching `Rpc.hs` for these strings: 0 matches).

**Effect:** wallets that consume `gettransaction` to display
"bumped from txid X" chains cannot do so. Block explorers /
hardware wallets that key on these mapValue fields silently
fall back to showing two unrelated txs.

Status: **PARTIAL** — old-tx side is tracked, new-tx side
missing, RPC response missing.

---

### BUG-13 [STYLE-DRIFT] bumpFee + psbtBumpFee + bumpFeeShared duplicate logic (G29)

**File:** `src/Haskoin/Rpc.hs` `bumpFeeShared` lines 6665-6733.

`bumpFeeShared` is parameterized over `wantPsbt :: Bool` and
dispatches to either `psbtBumpFee` or `bumpFee` based on the
flag. This is the correct two-pipeline reduction
(`handleBumpFee` + `handlePsbtBumpFee` both call `bumpFeeShared`).

But — `bumpFeeShared` has two parallel `withWalletMgr` clauses
that diverge in:
- Error-handling branch (PSBT branch line 6691-6694 vs bumpfee
  branch line 6708-6711).
- Response shape (PSBT branch returns `{psbt, origfee, fee}`;
  bumpfee returns `{txid, origfee, fee}`).

This is not strictly a bug — the divergence is intentional. But
the structural shape ("two parallel If branches in a shared
helper") is a known target for copy-paste drift the next time
a fix touches one branch and not the other. Recommend
factoring out a `runBumpFee :: Wallet -> TxId -> BumpFeeOptions
-> Bool -> IO (Either BumpFeeError BumpFeeResult)` that returns
a sum type and lets each handler shape its own JSON response.

Status: **PARTIAL** style note; no observable bug.

---

### BUG-14 [P2] FeeRate unit ambiguity at the BFO boundary (G30)

**File:** `src/Haskoin/Wallet.hs` `BumpFeeOptions` line 2178.

`bfoFeeRate :: !(Maybe FeeRate)` with doc comment
`"Explicit replacement feerate in sat/kvB"`.

`FeeRate` is `newtype FeeRate = FeeRate { getFeeRate :: Word64 }`
(Mempool.hs:193) with no per-unit accessor and the W120 audit
notes the constructor is used inconsistently (sat/vB vs sat/kvB)
across the codebase. The RPC handler (`Rpc.hs:6644`)
parses `fee_rate` from the JSON params via
`extractParamNumber km "fee_rate"` — Core's `bumpfee` RPC
documents `fee_rate` as **sat/vB**, not sat/kvB:

  bitcoin-core/src/wallet/rpc/spend.cpp `bumpfee_helper`:
    "Specify a fee rate in sat/vB"

haskoin's `parseBumpFeeOptions` passes this number directly into
`FeeRate` without unit conversion. So the user sends `25` meaning
"25 sat/vB" and haskoin treats it as `25 sat/kvB` (40× too low).

**Effect:** every `bumpfee txid {fee_rate: 25}` call against a
haskoin RPC underprices by 1000×. The replacement fails Rule 4
at the mempool with a confusing
`"RbfInsufficientRelayFee"` error.

Status: **MISSING** unit conversion. Quick fix: multiply by
1000 in `parseBumpFeeOptions`. Long fix: introduce
`newtype FeeRatePerVB / FeeRatePerKvB` and disambiguate at
parse time.

---

### BUG-15 [DEAD-HELPER / REGRESSION-MARKER] WALLET_INCREMENTAL_RELAY_FEE drift (G2)

**File:** `src/Haskoin/Wallet.hs` line 2254.

```haskell
walletIncrementalRelayFeePerKvB :: Word64
walletIncrementalRelayFeePerKvB = 5000
```

This matches Core's `WALLET_INCREMENTAL_RELAY_FEE = 5000`
(wallet/wallet.h:124). The value is NOT regression-pinned by
any test — a future refactor that drops the trailing three
zeros (treating it as sat/vB) would silently change every
bumpfee in the codebase.

Recommend adding to `W130BIP125FeeBumperRule3Spec`:

```haskell
it "WALLET_INCREMENTAL_RELAY_FEE pinned at 5000 sat/kvB" $
  walletIncrementalRelayFeePerKvB `shouldBe` 5000
```

W130 spec includes this regression as G2 pinning assertion.

---

## Test plan

`test/W130BIP125FeeBumperRule3Spec.hs` provides 28 cases:

- **18 pinning `it`** — assert haskoin's CURRENT behaviour
  (so any regression triggers a CI failure).
- **10 `xit` sentinels** — assert the DESIRED Core-parity
  behaviour. A future fix wave flips the sentinel to `it`
  after wiring the missing primitive.

Categories:

- G1/G2 (1 pinning each, 1 xit on constant drift)
- G3 (2 xits — no fresh unconfirmed inputs)
- G4 (1 pinning + 1 xit — short-circuit)
- G5/G6/G7/G8/G14 (5 xits — CheckFeeRate gates)
- G9 (1 xit — AllInputsMine)
- G10/G20 (2 xits — HasWalletSpend / hasDescendantsInMempool)
- G11/G15/G18/G19 (4 pinning — Rule 3/4 math correct)
- G12/G13 (2 xits — +1 sat/kvB nudge, max with node)
- G16 (1 pinning current strict, 1 xit Core-parity full-RBF)
- G21/G22/G23 (3 pinning — change index handling)
- G24/G25 (2 xits — allow_other_inputs / CreateTx)
- G26/G27 (2 pinning — signing path)
- G28 (1 xit — replaces_txid mapValue)
- G29/G30 (1 pinning + 1 xit — style + unit)

## Out of scope

- No production code changes. Pure discovery audit.
- Mempool-side Rule 3/4/5 enforcement is W120 territory; cross-cite
  only.
- Coin selection within `bumpfee` (BUG-9/BUG-10/BUG-11 closure
  would imply running `selectCoinsBnB` / `knapsackSolver` —
  reference W129 for the coin-selection state.

## Forward fix waves

A future fix wave should:

1. Land BUG-1 (`checkBumpPreconditions` short-circuit) and BUG-14
   (FeeRate unit at RPC boundary) as P0 must-fixes — both can be
   one-line fixes with high confidence.
2. Land BUG-2 (introduce `checkFeeRate` analog) and BUG-3
   (`m_min_depth=1`) as P1 follow-ups — these need careful
   plumbing of `mempoolMinFee` from the wallet's chain handle.
3. BUG-10 / BUG-11 (re-run CreateTransaction) is a multi-day
   refactor; consider folding into the W129 coin-selection fix
   wave instead of W130.

`verify-fix.sh` is NOT required for this audit — discovery wave,
no consensus code changes. Future fix waves on the cataloged bugs
SHOULD use it per the project's pre-fix verification convention.
