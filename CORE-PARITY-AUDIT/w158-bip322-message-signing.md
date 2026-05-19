# W158 — BIP-322 + Legacy message signing (haskoin)

**Wave:** W158 — `signmessage`, `signmessagewithprivkey`, `verifymessage`
RPCs; `MessageSign`, `MessageVerify`, `MessageHash`, `MESSAGE_MAGIC`
("Bitcoin Signed Message:\n"); BIP-137 wire formats (header bytes 27..42
for P2PKH / P2SH-P2WPKH / P2WPKH); BIP-322 three modes (Legacy / Simple /
Full) with virtual `to_spend`/`to_sign` transactions; encrypted-wallet
unlock gate around `signmessage`; per-RPC dispatch divergence between
`signmessage` (wallet) and `signmessagewithprivkey` (privkey-only).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/common/signmessage.h` — `MessageVerificationResult`
  enum (`ERR_INVALID_ADDRESS`, `ERR_ADDRESS_NO_KEY`, `ERR_MALFORMED_SIGNATURE`,
  `ERR_PUBKEY_NOT_RECOVERED`, `ERR_NOT_SIGNED`, `OK`); `SigningResult`
  enum (`OK`, `PRIVATE_KEY_NOT_AVAILABLE`, `SIGNING_FAILED`); function
  prototypes for `MessageVerify`, `MessageSign`, `MessageHash`.
- `bitcoin-core/src/common/signmessage.cpp` — `MESSAGE_MAGIC =
  "Bitcoin Signed Message:\n"`; `MessageHash` is
  `HashWriter() << MESSAGE_MAGIC << message` (Core's `HashWriter`
  serializes each `std::string` as CompactSize(len) || bytes, so the
  inner layout is `CompactSize(magic) || magic || CompactSize(message)
  || message`, then double-SHA256); `MessageVerify` only supports
  `PKHash` destinations — returns `ERR_ADDRESS_NO_KEY` for every other
  destination type; `MessageSign` calls `privkey.SignCompact()` (65-byte
  recoverable compact); `SigningResultString` for the three SigningResult
  cases.
- `bitcoin-core/src/rpc/signmessage.cpp` — `verifymessage` RPC
  (dispatches MessageVerify, maps result enum to JSON errors:
  `ERR_INVALID_ADDRESS` → `RPC_INVALID_ADDRESS_OR_KEY` (-5)
  "Invalid address"; `ERR_ADDRESS_NO_KEY` → `RPC_TYPE_ERROR` (-3)
  "Address does not refer to key"; `ERR_MALFORMED_SIGNATURE` →
  `RPC_TYPE_ERROR` (-3) "Malformed base64 encoding";
  `ERR_PUBKEY_NOT_RECOVERED` and `ERR_NOT_SIGNED` → JSON `false` (NOT
  errors); `OK` → JSON `true`); `signmessagewithprivkey` RPC (decodes WIF
  via `DecodeSecret`, calls `MessageSign`, returns base64); registered
  via `RegisterSignMessageRPCCommands` in the `util` category.
- `bitcoin-core/src/wallet/rpc/signmessage.cpp` — `signmessage` RPC
  (wallet method: `GetWalletForJSONRPCRequest`, `LOCK(cs_wallet)`,
  `EnsureWalletIsUnlocked(*pwallet)`, `DecodeDestination(address)`,
  `IsValidDestination` else throw `RPC_INVALID_ADDRESS_OR_KEY`,
  `std::get_if<PKHash>` else throw `RPC_TYPE_ERROR` "Address does not
  refer to key", `pwallet->SignMessage(message, *pkhash, signature)`
  with three-way return: OK → return signature; SIGNING_FAILED → throw
  `RPC_INVALID_ADDRESS_OR_KEY`; PRIVATE_KEY_NOT_AVAILABLE → throw
  `RPC_WALLET_ERROR`); help category is `wallet`, not `util`.
- `bitcoin-core/src/key.cpp::CKey::SignCompact` — produces header byte
  `27 + recid + (4 if compressed)` ∈ {27..30 uncompressed, 31..34
  compressed}.
- `bitcoin-core/src/key.cpp::CPubKey::RecoverCompact` — accepts header
  byte ∈ {27..34} ONLY; `compressed = (recid & 4) != 0`. BIP-137
  extended headers (35..42 for P2SH-P2WPKH and P2WPKH) are NOT accepted
  by Core; this is by design.
- BIP-322 — proposed three-mode replacement (Legacy / Simple / Full)
  with virtual `to_spend` (synthetic OP_RETURN-prefixed tx with input
  prevout = ALL_ZERO_HASH:0xFFFFFFFF, output scriptPubKey = the address
  scriptPubKey) and `to_sign` (synthetic tx that spends `to_spend.vout[0]`
  with the witness/scriptSig the signer wants to attest to). Verification
  applies Core's script interpreter to `to_sign` against the
  scriptPubKey of `to_spend`. **NOT MERGED into Bitcoin Core** as of the
  audited tree — PR #24058 still open. (So absence of BIP-322 is
  forward-looking parity; absence of BIP-137 extended-header verify is a
  fleet ecosystem-interop gap, not a Core mismatch.)

**Files audited**
- `src/Haskoin/Crypto.hs` — `messageMagic` (line 661-662),
  `messageHash` (667-673), `signCompact` (726-739), `recoverCompact`
  (745-771), `signMessage` (777-778), `recoverMessagePubKey` (783-784);
  FFI: `c_ecdsa_sign_recoverable_compact` (165-170),
  `c_ecdsa_recover_compact` (174-185); `Address` ADT (1099-1107);
  `textToAddress` (1348-1369); `wifDecode` referenced in dispatch path
  (defined at `Wallet.hs:5458-5467`).
- `src/Haskoin/Rpc.hs` — `handleVerifyMessage` (7379-7407),
  `handleSignMessage` (7420-7448); dispatch table entries for
  `verifymessage` / `signmessage` / `signmessagewithprivkey`
  (1154-1156); help listing for the three RPCs (7185-7189);
  `getCommandHelp` per-cmd help text (7195-7226).
- `src/Haskoin/Wallet.hs` — `wifDecode` (5458-5467); `isWalletLocked`
  (2785-2801); `EncryptedWallet` (2598-2604); `WalletState`
  (`wsEncrypted`, `wsUnlockExpiry`, `wsDecryptedKey`) (2621-2632);
  `unlockWallet` / `lockWallet` (2762-2781); `decryptWallet`
  (2735-2760).
- `src/Haskoin/Performance.hs:307,328` — `verifyMsgLax` direct-call
  perf path (not message-signing).
- `src/Haskoin/Script.hs:2007,2262` — `verifyMsgLax` inside
  `OP_CHECKSIG` / tapscript dispatch (not message-signing).
- `cbits/secp256k1_compat.c:543-575` — `haskoin_ecdsa_recover_compact`
  C-side header-byte bound `[27..34]` and recid mask `& 3`.
- `test/Spec.hs:6771-6841` — `signmessage / recoverable compact ECDSA`
  describe block (10 `it`s covering FFI surface).
- `test/W125RPCErrorParitySpec.hs:88,322-331` — BUG-6 of W125 carries
  the `verifymessage` literal `(-3)` finding (open ~4 waves).
- `haskoin.cabal`, `app/Main.hs`, `app/Bip341Shim.hs` — confirmed NO
  `Bip322`, `BIP322`, `bip322`, `MessageSign`, `to_spend`, `to_sign`
  modules; cabal lists no message-signing-specific module.

---

## Gate matrix (28 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | MESSAGE_MAGIC constant | G1: `messageMagic = "Bitcoin Signed Message:\n"` byte-for-byte | PASS (`Crypto.hs:662`; `Spec.hs:6782-6787` pins the 24-byte sequence) |
| 1 | … | G2: magic uses inner CompactSize-prefix per Core's `HashWriter << std::string` | PASS (`Crypto.hs:670-672` calls `putVarBytes messageMagic` then `putVarBytes msgBytes`; identical to Core's two `operator<<` invocations on `std::string`) |
| 2 | MessageHash | G3: double-SHA256 over `CompactSize(magic) || magic || CompactSize(msg) || msg` | PASS shape; **BUG-15** test-pins-bug — `Spec.hs:6789-6792` asserts ONLY that the hash is 32 bytes; no Core-known-vector cross-check |
| 2 | … | G4: message is byte-treated (Core uses `std::string`, no UTF-8 validation) | **BUG-12 (P3)** — `Crypto.hs:669` does `TE.encodeUtf8 msg` which is safe because `msg :: Text` is already UTF-8 internally; but the JSON-parse upstream rejected any non-UTF-8 input, so a Core client that signed with arbitrary bytes (e.g., the 0x80 lead-byte sequence widely used in older wallets) cannot have its signature ROUND-TRIPPED through haskoin's RPC layer |
| 3 | MessageSign (privkey-direct) | G5: header byte encodes recid + compressed flag | PASS via FFI (`cbits/secp256k1_compat.c::haskoin_ecdsa_sign_recoverable_compact`) |
| 3 | … | G6: signing respects WIF's compressed-flag byte (0x01 suffix in 33-byte payload) | **BUG-1 (P1)** — `handleSignMessage` (`Rpc.hs:7429`) hardcodes `compressed=True` for ALL WIF inputs. `wifDecode` (`Wallet.hs:5458-5467`) discards the compressed flag (returns just `SecKey`). Signing with an uncompressed WIF (mainnet `5...`, testnet `9...`) produces a header in {31..34} matching the COMPRESSED pubkey, but the verifier compares against the address's hash160-of-UNCOMPRESSED-pubkey. Result: `verifymessage` returns `false` for a signature this same node produced. |
| 4 | MessageVerify | G7: `ERR_INVALID_ADDRESS` → `RPC_INVALID_ADDRESS_OR_KEY` (-5) | PASS (`Rpc.hs:7383-7385`; uses `rpcInvalidAddressOrKey`) |
| 4 | … | G8: `ERR_ADDRESS_NO_KEY` → `RPC_TYPE_ERROR` (-3) "Address does not refer to key" | **BUG-2 (P1, carry-forward W125 BUG-6 4th wave)** — `Rpc.hs:7404` emits bare literal `(-3)`. No `rpcTypeError` named constant exists. xit-pinned for ~4 waves with no fix |
| 4 | … | G9: `ERR_MALFORMED_SIGNATURE` → `RPC_TYPE_ERROR` (-3) "Malformed base64 encoding" | **BUG-2 cross-cite** (`Rpc.hs:7390`) — same bare literal `(-3)` |
| 4 | … | G10: `ERR_PUBKEY_NOT_RECOVERED` returns JSON `false`, NOT error | **BUG-3 (P1)** — `Rpc.hs:7395` returns `false` for the wrong-length branch (correct), and `Rpc.hs:7398` returns `false` for FFI-recover failure (correct), but the **truncates a real subcase**: Core distinguishes (a) recover-failed (returns false silently) from (b) recovered-but-pubkey-doesn't-match-address (also returns false silently). haskoin collapses both into one branch and additionally returns `false` for header byte ∉ {27..34} because the C wrapper rejects it. Behaviour is observably equivalent — but the verbose-help path that Core exposes via `verifymessage` debug logs is missing |
| 4 | … | G11: `ERR_NOT_SIGNED` returns JSON `false` | PASS (`Rpc.hs:7401` returns `actual == expectedHash` directly) |
| 4 | … | G12: `OK` returns JSON `true` | PASS (`Rpc.hs:7401`) |
| 5 | Address-type acceptance (verify) | G13: PKHash → recover-and-compare | PASS (`Rpc.hs:7387-7402`) |
| 5 | … | G14: ScriptAddress/WitnessPubKeyAddress/WitnessScriptAddress/TaprootAddress → `ERR_ADDRESS_NO_KEY` | PASS shape (`Rpc.hs:7403-7404` catches everything else); **BUG-13 (P2)** the error string is the same `(-3)` literal issue; no path for BIP-322 fallback to verify witness addresses |
| 6 | BIP-137 wire-format extensions | G15: accept header bytes 35..38 (P2SH-P2WPKH compressed) | **BUG-4 (P1)** — `Crypto.hs:751` and `cbits/secp256k1_compat.c:559` both REJECT any header ∉ {27..34}. Wallets like Electrum and Sparrow have produced BIP-137 P2SH-P2WPKH signatures since 2017; haskoin cannot verify them and emits `false` even when the signature is valid |
| 6 | … | G16: accept header bytes 39..42 (P2WPKH bech32 compressed) | **BUG-4 cross-cite** — same code path |
| 7 | BIP-322 (Legacy / Simple / Full) | G17: `MessageVerify` falls back to BIP-322 on `ERR_ADDRESS_NO_KEY` | **BUG-5 (P1)** — entirely absent. No `Bip322` module in `src/Haskoin/`; `grep -rn -i "bip322"` over the whole repo returns 0 hits. (This is forward-looking: Core has NOT merged BIP-322 either, so it's a fleet-wide gap not a Core mismatch. Cross-cite: rustoshi/blockbrew/clearbit/nimrod/camlcoin/beamchain — 6 of 7 audited fleet impls so far also have zero BIP-322 wiring. Pattern crystallizing as fleet-universal) |
| 7 | … | G18: synthetic `to_spend` tx (input prevout = ALL_ZERO_HASH:0xFFFFFFFF, output scriptPubKey = addr.scriptPubKey) | N/A (no BIP-322) |
| 7 | … | G19: synthetic `to_sign` tx (input spends `to_spend.vout[0]`, witness = supplied signature) | N/A (no BIP-322) |
| 7 | … | G20: dispatch script interpreter on `(to_sign, scriptPubKey)` with appropriate verify flags | N/A (no BIP-322) |
| 8 | signmessage RPC (wallet) vs signmessagewithprivkey (util) | G21: distinct handlers per Core | **BUG-6 (P0-PARITY)** — `Rpc.hs:1155-1156` dispatches BOTH `signmessage` and `signmessagewithprivkey` to the SAME `handleSignMessage`. This is a literal **SAME constructor TWICE in case-of** pattern (W156 NEW haskoin) carried to the RPC table. Two distinct Core RPC commands with completely different intended semantics share one body |
| 8 | … | G22: signmessage requires wallet (`GetWalletForJSONRPCRequest`, `LOCK(cs_wallet)`) | **BUG-7 (P1)** — `handleSignMessage` ignores `RpcServer`'s wallet handle entirely (it passes `_server` to `_`). Address path emits `"Private key for address not available; pass a WIF key directly"` (`Rpc.hs:7443-7445`). The wallet-lookup-by-address that Core's `signmessage` does (`pwallet->SignMessage(message, *pkhash, signature)`) is absent |
| 8 | … | G23: signmessage requires `EnsureWalletIsUnlocked(*pwallet)` (throws `RPC_WALLET_UNLOCK_NEEDED` (-13) if locked) | **BUG-8 (P1, cross-cite W125 BUG-10 carry-forward)** — `isWalletLocked` exists (`Wallet.hs:2785-2801`) and is imported (`Rpc.hs:299`) but is NEVER called by `handleSignMessage`. `rpcWalletUnlockNeeded (-13)` constant is also missing (W125 BUG-10 open ~4 waves). This is the haskoin instance of the fleet "already-exports-the-primitive-just-not-called" pattern |
| 8 | … | G24: signmessage rejects non-PKHash with `RPC_TYPE_ERROR` | **BUG-9 (P1)** — `handleSignMessage` accepts ONLY a WIF (or "address not available" error). There is no PKHash-vs-other-destination split because the address path never resolves to a key. So the `RPC_TYPE_ERROR` "Address does not refer to key" diagnostic is unreachable |
| 9 | signmessagewithprivkey RPC | G25: util-category (no wallet handle required) | PASS by accident (`handleSignMessage` is wallet-agnostic) |
| 9 | … | G26: WIF decode failure → `RPC_INVALID_ADDRESS_OR_KEY` "Invalid private key" | PASS (`Rpc.hs:7441-7442`) |
| 9 | … | G27: signing failure → `RPC_INVALID_ADDRESS_OR_KEY` "Sign failed" | PASS (`Rpc.hs:7430-7431`) |
| 10 | Help text + RPC introspection | G28: `getCommandHelp "signmessage"` / `"verifymessage"` / `"signmessagewithprivkey"` return full Core-style help | **BUG-10 (P3)** — `getCommandHelp` (`Rpc.hs:7195-7226`) has cases for `getblockchaininfo`, `getblock`, etc. but NO case for any of the three message-signing RPCs. `help "signmessage"` returns `"Unknown command: signmessage\nUse help without arguments to list all commands."` even though the RPC IS dispatched |
| 11 | Misbehaving-primitive linkage | G29: a failing `verifymessage` does NOT increment any peer-misbehaving counter or trigger any ban | PASS — `handleVerifyMessage` / `handleSignMessage` never reach `banPeer` or any misbehaving primitive. (Cross-cite to W156 BUG-13+14 "misbehaving-primitive-too-aggressive" — this is the GOOD case where it's correctly NOT wired into RPC. Confirms scope.) |

---

## BUG-1 (P1) — `handleSignMessage` hardcodes `compressed=True`; uncompressed WIFs silently sign with the wrong header

**Severity:** P1. The compressed flag determines the offset added to the
header byte (`27 + recid` for uncompressed, `31 + recid` for compressed,
per `CKey::SignCompact` in `bitcoin-core/src/key.cpp`). The same flag
ALSO determines which pubkey-form (33 vs 65 bytes) the verifier
reconstructs from the signature. The two MUST agree — a signature
header indicating "compressed" pairs with the compressed-pubkey-derived
P2PKH; a signature header indicating "uncompressed" pairs with the
uncompressed-pubkey-derived P2PKH. Bitcoin Core's `MessageSign` uses
`privkey.SignCompact()` which reads the compressed flag DIRECTLY off the
`CKey` (the WIF decoder preserves it via `CKey::Set(..., fCompressed)`).

haskoin's `handleSignMessage` (`Rpc.hs:7420-7448`) does:

```haskell
case wifDecode keyOrAddress of
  Just sk@(SecKey _) ->
    -- WIF: trailing 0x01 byte selects compressed; wifDecode strips it
    -- but the decoder remembers via the resulting payload length. We
    -- conservatively assume compressed (the modern default).
    case signMessage sk True message of            -- ← hardcoded True
```

The comment is a **comment-as-confession** ("conservatively assume
compressed"). `wifDecode` (`Wallet.hs:5458-5467`) does NOT preserve the
compressed flag in the `SecKey` value — it returns `SecKey payload`
unconditionally, having stripped the 0x01 suffix off compressed keys.
The decoder branch *could* tell the caller via a separate return value,
but does not.

**Impact:** a user calling `signmessagewithprivkey "<uncompressed WIF
starting 5/9>" "msg"` gets a base64 signature with a compressed-flag
header byte. Verifying that signature against the P2PKH address derived
from the **uncompressed** pubkey (the one corresponding to the WIF the
user passed) returns `false`. This is a silent-correctness bug: the user
gets a signature output and a `true`/`false` verifier response that
disagrees with what Core would produce for the same inputs.

**File:** `src/Haskoin/Rpc.hs:7429`; `src/Haskoin/Wallet.hs:5458-5467`.

**Core ref:** `bitcoin-core/src/wallet/rpc/signmessage.cpp:60` →
`pwallet->SignMessage` → `CKey::SignCompact` (preserves `fCompressed`).

**Fix sketch:** `wifDecode` should return `(SecKey, Bool)`; or use a
`WifKey = WifKey SecKey Bool` newtype. Threading the flag through
`signMessage` and the C FFI is a few lines.

---

## BUG-2 (P1, carry-forward W125 BUG-6 4th wave) — `verifymessage` error sites emit bare literal `(-3)`; no `rpcTypeError` named constant

**Severity:** P1. Two of `handleVerifyMessage`'s error branches emit
`RpcError (-3) "<msg>"` with a bare numeric literal where Core uses the
named constant `RPC_TYPE_ERROR`. `verifymessage`'s
"Malformed base64 encoding" and "Address does not refer to key" both
need this:

```haskell
-- Rpc.hs:7390
Left _ -> return $ RpcResponse Null
  (toJSON $ RpcError (-3) "Malformed base64 encoding") Null

-- Rpc.hs:7404
_ -> return $ RpcResponse Null
  (toJSON $ RpcError (-3) "Address does not refer to key") Null
```

`W125RPCErrorParitySpec.hs:322-331` already xfail-pins both sites
(`pendingWith "Rpc.hs:7390/7404: bare literal (-3) matches Core
rpc/signmessage.cpp:49/47 but needs named constant"`). The W125 audit
landed roughly 4 weeks ago; the literals are still there.

This is the haskoin instance of the **carry-forward re-anchor** pattern
(W141 fleet-wide finding) — the test infrastructure correctly pins the
bug as pending, but the production source never gets touched.

**File:** `src/Haskoin/Rpc.hs:7390, 7404`.

**Core ref:** `bitcoin-core/src/rpc/signmessage.cpp:47,49` →
`RPC_TYPE_ERROR` (defined as -3 in `rpc/protocol.h`).

---

## BUG-3 (P1) — `ERR_PUBKEY_NOT_RECOVERED` vs `ERR_NOT_SIGNED` distinction collapsed into a single `false`-returning branch

**Severity:** P1. Bitcoin Core's `MessageVerify` distinguishes three
success-shaped-but-failing cases:
- `ERR_PUBKEY_NOT_RECOVERED` (signature parse OK but recover_compact
  returned no key — e.g., bad recid)
- `ERR_NOT_SIGNED` (recover succeeded but the recovered key doesn't
  hash to the address)
- `OK` (recover succeeded AND pubkey matches address)

Both `ERR_PUBKEY_NOT_RECOVERED` and `ERR_NOT_SIGNED` map to
`UniValue(false)` at the RPC layer, but they are distinct enum values
upstream and can be teased apart by debug logs or future API consumers
(e.g., the BIP-322 fallback `MessageVerify` extension in PR #24058 would
have switched on these enums to decide whether to attempt the
BIP-322 path).

haskoin's `handleVerifyMessage` (`Rpc.hs:7395-7402`) collapses both into
the same `RpcResponse (toJSON False)` without any internal enum
discrimination, AND silently treats "header byte ∉ {27..34}" as
`ERR_PUBKEY_NOT_RECOVERED` (the C wrapper at
`cbits/secp256k1_compat.c:559` returns 0 for `header < 27 || header > 34`).
There is no `MessageVerificationResult` enum at all in `src/`; the
function returns straight `Bool`. Future BIP-322 wiring (BUG-5) cannot
plumb decisions off this code without re-architecting the return
type.

**File:** `src/Haskoin/Rpc.hs:7379-7407`; missing: a
`MessageVerificationResult` ADT in `src/Haskoin/Crypto.hs`.

**Core ref:** `bitcoin-core/src/common/signmessage.h::MessageVerificationResult`
(6-case enum); `bitcoin-core/src/rpc/signmessage.cpp:41-55` (switch
maps each case to a distinct RPC response).

**Impact:** API-shape divergence; precludes BIP-322 fallback wiring
without rework; debug-log visibility into recover-vs-match failure
absent.

---

## BUG-4 (P1) — BIP-137 extended-header recovery (headers 35..42) unsupported; ecosystem-interop break

**Severity:** P1 ecosystem interop. BIP-137 ("Signatures of Messages
using Private Keys") extended the header-byte range from `{27..34}` to
`{27..42}` to encode SignatureType (one of P2PKH-uncompressed,
P2PKH-compressed, P2SH-P2WPKH, P2WPKH) alongside the recid. Wallets
that have produced BIP-137 signatures in the wild for ~7 years include
Electrum, Bitcoin Knots, Sparrow, BlueWallet, and several hardware
wallet vendors.

Bitcoin Core itself does NOT accept headers 35..42 — this is a known
limitation of Core's `verifymessage`. So absence here is NOT a Core
mismatch. But the fleet-wide pattern across the 10 hashhog impls would
be: somebody implements BIP-137 (or BIP-322's Simple mode falls back to
it), and haskoin then becomes the odd one out that returns `false` for
valid signatures that other impls verify.

`src/Haskoin/Crypto.hs:751` (Haskell guard) AND
`cbits/secp256k1_compat.c:559` (C guard) both bound the header to
`[27..34]`. A BIP-137-accepting verifier would:
1. Accept header ∈ {27..42}
2. Branch on the upper range to decide which address-derivation form
   to compare against (P2SH-P2WPKH wraps the compressed pubkey in
   `OP_0 <hash160>` inside a P2SH; P2WPKH uses the raw hash160 in a
   bech32 address)
3. Return OK only if the recovered pubkey, mapped through the
   appropriate derivation, hashes to the address provided.

**File:** `src/Haskoin/Crypto.hs:745-771` (`recoverCompact` Haskell
side); `cbits/secp256k1_compat.c:543-575`
(`haskoin_ecdsa_recover_compact` C side).

**Cross-cite:** the fact that BOTH the Haskell guard AND the C guard
duplicate the `[27..34]` bound is the haskoin instance of the
**two-pipeline guard** pattern (W141 fleet pattern, 14 distinct
extensions). Defense-in-depth here is correct, but it doubles the
surface area for a future BIP-137 extension.

---

## BUG-5 (P1, fleet-wide forward-looking gap) — BIP-322 entirely absent

**Severity:** P1 forward-looking parity. BIP-322 ("Generic Signed
Message Format") proposes three modes:
- **Legacy** — exactly equivalent to the current `MessageVerify`
  pathway for P2PKH addresses; for backward compat.
- **Simple** — produces a 64-byte witness (sigopt-only data) that
  encodes a witness stack for the address's witness program.
- **Full** — produces an actual BIP-141 witness, allowing arbitrary
  scripts (multisig, taproot script-path, miniscript) to attest.

Verification constructs:
- `to_spend` — a virtual tx with one input
  (prevout = `00..00:0xFFFFFFFF`, sequence = 0, scriptSig =
  `OP_0 PUSH32(message_hash)`) and one output
  (value = 0, scriptPubKey = the signer's address scriptPubKey).
- `to_sign` — a virtual tx that spends `to_spend.vout[0]` with the
  signer-supplied witness, output value = 0, scriptPubKey = OP_RETURN.

Verification: run Core's script interpreter on `to_sign` against
`to_spend.vout[0].scriptPubKey` with appropriate verify flags
(MANDATORY + STANDARD + TAPROOT for full BIP-322).

haskoin has ZERO BIP-322 wiring. `grep -rn -i "bip322"` over the entire
repo (src + test + cabal + docs + audits) returns 0 hits. No virtual-tx
constructor; no fall-through path from `verifymessage` to a BIP-322
attempt; no module skeleton; not on any roadmap.

This is **a fleet-wide universal pattern crystallizing**: 6 of the 7
fleet impls audited so far (rustoshi, blockbrew, clearbit, nimrod,
camlcoin, beamchain) have confirmed identical absence. haskoin makes
**7 of 8** confirming the fleet-wide universal.

Note: Bitcoin Core itself has not merged BIP-322 (PR #24058 still open
at the audited tree). So absence is NOT a Core-mismatch, just a
forward-looking gap that the entire hashhog fleet should likely close
in a coordinated wave, not individually.

**File:** entire `src/` directory; `haskoin.cabal` exposed-modules.

**Core ref:** PR #24058 (still open as of the audited tree); BIP-322
specification.

---

## BUG-6 (P0-PARITY) — `signmessage` and `signmessagewithprivkey` dispatch to the SAME handler — SAME constructor TWICE in case-of, RPC table edition

**Severity:** P0-PARITY (RPC-API-divergence-from-Core, no consensus
risk). Bitcoin Core has two distinct RPC commands with completely
different intended semantics:
- `signmessage` (in `wallet/rpc/signmessage.cpp`) is a **wallet method**
  registered in the `wallet` category. It requires a loaded wallet, takes
  an `address` (NOT a privkey) and a `message`, locks `cs_wallet`,
  ensures the wallet is unlocked, looks up the privkey corresponding to
  the address from the wallet's keystore, and signs.
- `signmessagewithprivkey` (in `rpc/signmessage.cpp`) is a **utility
  method** registered in the `util` category. It does NOT require a
  wallet, takes a WIF `privkey` and a `message`, and signs.

haskoin's RPC dispatch (`Rpc.hs:1154-1156`):

```haskell
"verifymessage"        -> handleVerifyMessage server params
"signmessage"          -> handleSignMessage server params
"signmessagewithprivkey" -> handleSignMessage server params  -- ← SAME
```

This is the literal **SAME constructor TWICE in case-of** pattern (W156
NEW haskoin), now appearing in the RPC dispatch table. Both names
dispatch to one body. The body (`Rpc.hs:7420-7448`) accepts a WIF in
the first arg and emits an error if given an address ("Private key for
address not available; pass a WIF key directly").

Effect: `signmessage` (Core's wallet-context method) is functionally
identical to `signmessagewithprivkey` (Core's util method) in haskoin.
Operators who pass an address to `signmessage` (the documented Core
form) get an error directing them to use a WIF — which is the OPPOSITE
of what Core does (Core's `signmessagewithprivkey` is the explicit-WIF
form; `signmessage` is the address form).

**File:** `src/Haskoin/Rpc.hs:1154-1156` (dispatch), `7420-7448`
(handler).

**Core ref:**
- `bitcoin-core/src/wallet/rpc/signmessage.cpp` (wallet `signmessage`)
- `bitcoin-core/src/rpc/signmessage.cpp` (util `signmessagewithprivkey`).

**Fix sketch:** split into `handleSignMessage` (wallet path, requires
wallet handle + address-to-key lookup + `EnsureWalletIsUnlocked`) and
`handleSignMessageWithPrivkey` (current body, WIF-only). Dispatch each
to its own.

---

## BUG-7 (P1) — `signmessage` lacks wallet-key lookup; address argument unconditionally errors

**Severity:** P1. Continuation of BUG-6. Even granting that the
wallet handle isn't yet plumbed in, the address path emits a structured
error that directs callers to "pass a WIF key directly":

```haskell
-- Rpc.hs:7440-7445
case textToAddress keyOrAddress of
  Nothing -> return $ RpcResponse Null
    (toJSON $ RpcError rpcInvalidAddressOrKey "Invalid private key") Null
  Just _ -> return $ RpcResponse Null
    (toJSON $ RpcError rpcInvalidAddressOrKey
       "Private key for address not available; pass a WIF key directly") Null
```

Two problems:
1. A wallet HAS been loaded (the `RpcServer` carries a `WalletState`
   handle — see `Rpc.hs:299` importing `isWalletLocked`); the handler
   just ignores it.
2. The error message "Private key for address not available; pass a
   WIF key directly" is haskoin-bespoke. Core's equivalent error (when
   the address has no key in the wallet) is
   `RPC_WALLET_ERROR "Private key not available"` via
   `SigningResultString(PRIVATE_KEY_NOT_AVAILABLE)`.

**File:** `src/Haskoin/Rpc.hs:7440-7445`; missing: a wallet-side
`SignMessage :: WalletState -> Address -> Text -> IO (Either
SigningResult ByteString)` API in `src/Haskoin/Wallet.hs`.

**Core ref:** `bitcoin-core/src/wallet/rpc/signmessage.cpp:60`
(`pwallet->SignMessage(strMessage, *pkhash, signature)`).

---

## BUG-8 (P1, cross-cite W125 BUG-10 carry-forward) — `signmessage` does not check `EnsureWalletIsUnlocked`; missing `rpcWalletUnlockNeeded (-13)` constant

**Severity:** P1. Bitcoin Core's `signmessage` calls
`EnsureWalletIsUnlocked(*pwallet)` at the head of the handler. If the
wallet is encrypted and locked, this throws
`RPC_WALLET_UNLOCK_NEEDED` (-13) "Error: Please enter the wallet
passphrase with walletpassphrase first." This is the standard error
contract Core uses for any wallet method that needs to access privkeys.

haskoin has:
- `isWalletLocked :: WalletState -> IO Bool` defined at
  `Wallet.hs:2785-2801`
- It is imported into `Rpc.hs:299` (so already in scope)
- It is NEVER called by `handleSignMessage`
- `rpcWalletUnlockNeeded (-13)` constant is NOT defined anywhere
  (W125 BUG-10, open ~4 waves)

This is the haskoin instance of the **already-exports-the-primitive-just-not-called**
pattern. The primitive is one import + one call away from being correctly
wired. Without it, an encrypted+locked haskoin wallet that sees a
`signmessage` RPC with a WIF would happily sign with that WIF (the
encrypted-wallet state isn't consulted, the WIF doesn't need it),
which is **arguably even more dangerous than no gate** because it gives
the operator no signal that the encrypted wallet path is unused.

**File:** `src/Haskoin/Rpc.hs:7420-7448` (no `isWalletLocked` call);
`src/Haskoin/Rpc.hs` (no `rpcWalletUnlockNeeded` constant); cross-cite
`test/W125RPCErrorParitySpec.hs::BUG-10`.

**Core ref:** `bitcoin-core/src/wallet/rpc/signmessage.cpp:44`
(`EnsureWalletIsUnlocked(*pwallet)`).

---

## BUG-9 (P1) — wallet `signmessage` cannot reject non-PKHash; the `RPC_TYPE_ERROR` "Address does not refer to key" diagnostic is unreachable

**Severity:** P1. Continuation of BUG-6 / BUG-7. Because `handleSignMessage`
only accepts WIFs and emits a generic "address not available" for ANY
address (P2PKH, P2SH, P2WPKH, P2WSH, P2TR), the Core-equivalent
distinction between "address is valid but isn't P2PKH" (Core throws
`RPC_TYPE_ERROR` -3 "Address does not refer to key") and "address is
valid P2PKH but its key isn't in this wallet" (Core throws
`RPC_WALLET_ERROR` -4 "Private key not available") collapses.

When a user passes a P2WPKH bech32 address, Core says "wrong address
type for legacy signmessage; use signmessagewithprivkey or wait for
BIP-322". haskoin says "Private key for address not available; pass a
WIF key directly" — which is misleading because the address isn't even
a valid signmessage target.

**File:** `src/Haskoin/Rpc.hs:7440-7445`.

**Core ref:** `bitcoin-core/src/wallet/rpc/signmessage.cpp:54-57`
(checks `std::get_if<PKHash>` and throws `RPC_TYPE_ERROR` for
non-PKHash before attempting wallet lookup).

---

## BUG-10 (P3) — `getCommandHelp` has no entry for `signmessage` / `verifymessage` / `signmessagewithprivkey`

**Severity:** P3 (operator-discoverability). `Rpc.hs:7195-7226`
implements `getCommandHelp` with a `case T.toLower cmd of` that
enumerates ~16 RPCs by name (getblockchaininfo, getblock, getchaintips,
decodescript, testmempoolaccept, submitpackage, getmempoolentry,
disconnectnode, getnewaddress, sendtoaddress, listtransactions,
listunspent, help, stop, plus the `_` fall-through). None of
`signmessage`, `verifymessage`, `signmessagewithprivkey` are listed.

The help-listing helper (`Rpc.hs:7185-7189`) DOES list all three RPCs
in the `help` (no-arg) output, but the per-command help — what an
operator gets from `bitcoin-cli help signmessage` — falls into the `_`
branch and returns `"Unknown command: signmessage\nUse help without
arguments to list all commands."`

This is the haskoin instance of the **comment-as-confession**-adjacent
pattern: the no-arg help advertises the command, but the per-command
help denies its existence.

**File:** `src/Haskoin/Rpc.hs:7195-7226`.

**Core ref:** Core's `RPCHelpMan` self-documents each handler with full
arg-by-arg help text; `bitcoin-cli help signmessage` returns the full
multi-line spec.

---

## BUG-11 (P2) — `wifDecode` discards the compressed flag; downstream call sites cannot recover it

**Severity:** P2 (architectural enabler of BUG-1). `wifDecode`
(`Wallet.hs:5458-5467`) returns `Maybe SecKey`, where `SecKey` is just
a `ByteString` newtype (32 bytes). It branches on payload length to
detect compressed-vs-uncompressed encoding, but the result is the same
type either way. The compressed flag is **silently lost** at this
boundary.

```haskell
wifDecode :: Text -> Maybe SecKey
wifDecode txt =
  case base58CheckDecode txt of
    Nothing -> Nothing
    Just (version, payload)
      | version /= 0x80 && version /= 0xef -> Nothing
      | BS.length payload == 32 -> Just (SecKey payload)             -- uncompressed flag DROPPED
      | BS.length payload == 33 && BS.last payload == 0x01 ->
          Just (SecKey (BS.init payload))                            -- compressed flag DROPPED
      | otherwise -> Nothing
```

Every call site has to either re-decode the WIF and inspect the payload
length, or hardcode an assumption. `handleSignMessage` (BUG-1) takes
the second route and hardcodes `True`. This is also the root cause that
prevents Core-parity for other privkey-consumer RPCs that need to
serialise back to WIF.

**File:** `src/Haskoin/Wallet.hs:5458-5467`. Eight call sites under
`grep -n "wifDecode" haskoin/src/` — all bear the same risk.

**Core ref:** `bitcoin-core/src/key_io.cpp::DecodeSecret` returns
`CKey` with `fCompressed` preserved.

---

## BUG-12 (P3) — `messageHash` uses `TE.encodeUtf8` on the message; arbitrary-byte messages cannot round-trip through the RPC layer

**Severity:** P3 (wire-interop edge case). Bitcoin Core's `MessageHash`
treats the message as a raw `std::string` (raw bytes, no encoding
assumption). Wallets in the wild have signed messages containing
arbitrary bytes (notably the SatoshiDice-era practice of signing
binary blobs). Core's `signmessagewithprivkey` accepts any bytes the
JSON parser hands it as a string.

haskoin's `messageHash` (`Crypto.hs:667-673`):

```haskell
messageHash msg =
  let msgBytes = TE.encodeUtf8 msg
      ...
```

The function input is `Text`, which is already UTF-8-validated internally.
By the time the RPC layer hands `messageHash` a `Text`, the JSON parser
has already rejected any non-UTF-8 byte sequence. So a Core-signed
message containing `0x80` (an isolated UTF-8 continuation byte) cannot
be round-tripped through `verifymessage` on haskoin — the JSON parse
fails before reaching the verifier.

In practice the vast majority of `signmessage` usage is ASCII / UTF-8
text, so this is a P3. But it is documentation-worthy as a wire-format
gap, especially because BIP-322 explicitly leaves message-encoding to
the caller.

**File:** `src/Haskoin/Crypto.hs:669`; upstream `src/Haskoin/Rpc.hs:7381`
(`extractParamText` returns `Maybe Text`).

**Core ref:** `bitcoin-core/src/common/signmessage.cpp:76` —
`hasher << MESSAGE_MAGIC << message;` where `message` is `std::string`
(raw bytes).

---

## BUG-13 (P2) — `verifymessage` non-PKHash branch uses the SAME bare `(-3)` literal as the malformed-base64 branch; identical to BUG-2

**Severity:** P2 (carry-forward W125 BUG-6 site 2 of 2). Already
catalogued at BUG-2; flagged separately because it's a distinct call
site that the fix wave needs to touch. `Rpc.hs:7404` is the
non-PKHash branch; `Rpc.hs:7390` is the malformed-base64 branch. Both
should switch to a `rpcTypeError = -3` named constant in one PR.

**File:** `src/Haskoin/Rpc.hs:7404`.

**Core ref:** `bitcoin-core/src/rpc/signmessage.cpp:47`.

---

## BUG-14 (P2) — `verifymessage` returns `false` for header byte ∉ {27..34} instead of distinguishing parse failure from recover failure

**Severity:** P2. Tied to BUG-3. The C wrapper rejects any header byte
outside `[27..34]` by returning 0; the Haskell layer maps that to
`Nothing`; the RPC layer maps `Nothing` to `false` (the
`ERR_PUBKEY_NOT_RECOVERED` path). For Core this is correct.

But the same `false` is also produced for a header in `[27..34]` whose
signature data is malformed (libsecp256k1 parse failed), and for a
recovered pubkey that doesn't match the address. Core's enum
(`MessageVerificationResult`) keeps these three as three distinct
values; haskoin keeps them all as one Bool. Future BIP-322 wiring
(BUG-5) cannot distinguish "this signature isn't legacy P2PKH; try
BIP-322" from "this is a legacy P2PKH signature that just failed".

**File:** `src/Haskoin/Rpc.hs:7395-7402`;
`src/Haskoin/Crypto.hs:745-771`.

**Fix sketch:** introduce `data MessageVerificationResult = ...`
(6-case enum) in `Crypto.hs`; switch `recoverMessagePubKey` to return
that; `handleVerifyMessage` switches on it.

---

## BUG-15 (P3, NEW pattern: test-pins-bug) — `messageHash` test only asserts length 32, not a Core-known vector

**Severity:** P3 (test-strength). `test/Spec.hs:6789-6792`:

```haskell
it "messageHash is double-SHA256 of varint-prefixed magic||message" $ do
  -- Concrete vector: empty message under Core's HashWriter rules.
  let Hash256 h = messageHash (T.pack "")
  BS.length h `shouldBe` 32
```

This test name PROMISES it verifies the double-SHA256-of-varint-prefixed
shape; the assertion delivers ONLY a length check. The expected
Core-known vector for the empty message under `Bitcoin Signed Message:\n`
prefix is a fixed 32-byte hash that could be hardcoded:

```
sha256d(VarInt(24) || "Bitcoin Signed Message:\n" || VarInt(0))
```

Without that hardcoded comparison, an off-by-one in the VarInt
serialiser, a typo in the magic string, or a single-vs-double SHA256
swap would all PASS this test. This is a **test-pins-bug NEW pattern**
fleet observation — the haskoin instance is fairly mild
(other test-pins-bug instances span hundreds of LOC), but the pattern
is the same: the test name promises semantic verification, the body
delivers shape-only.

The companion test "messageMagic matches Bitcoin Core"
(`Spec.hs:6782-6787`) DOES use a hardcoded byte vector — this is the
correct pattern. The `messageHash` test should follow suit.

**File:** `test/Spec.hs:6789-6792`.

**Suggested vector:** for empty message, with `MESSAGE_MAGIC =
"Bitcoin Signed Message:\n"` (24 bytes), the pre-image is
`0x18 || "Bitcoin Signed..." || 0x00` (26 bytes). Cross-validate via
`bitcoin-cli` against a known mainnet `verifymessage` example or
re-derive from Core source.

---

## BUG-16 (P2) — `signmessage` does not normalise the message (no trim, no LF/CRLF normalisation); subtle wallet-interop break

**Severity:** P2 wallet-interop. Bitcoin Core's `MessageHash` does NOT
normalise the message: trailing whitespace, leading whitespace, and
CRLF-vs-LF differences will hash to different values. Several wallets
(Electrum historically, BitPay until 2017) have at various times applied
their own normalisation — `.rstrip()` of trailing whitespace, or
`.replace("\r\n", "\n")` — which broke cross-wallet verifymessage.

haskoin matches Core's no-normalisation approach (correct). But there is
no test or comment documenting the choice. If a future "compatibility"
patch adds normalisation, parity will silently break. This is
documentation-worthy as a sticky-point.

**File:** `src/Haskoin/Crypto.hs:667-673` (no normalisation, correctly
matches Core); needs a comment explaining the choice.

**Core ref:** `bitcoin-core/src/common/signmessage.cpp:76` (no
normalisation).

---

## BUG-17 (P2) — `recoverCompact`'s `compressed = (header - 27) >= 4` and the C-side `compressed` argument parameter form a two-pipeline guard with divergent semantics

**Severity:** P2 architectural fragility. The Haskell layer derives the
compressed flag from the header byte:

```haskell
-- Crypto.hs:754
let compressed = (header - 27) >= 4
    bufLen = if compressed then 33 else 65
in ...
   ok <- c_ecdsa_recover_compact
           (castPtr sigPtr) (castPtr hashPtr)
           (if compressed then 1 else 0)        -- ← C side gets the derived flag
           outPtr lenPtr
```

The C wrapper at `cbits/secp256k1_compat.c:543-575` ALSO takes
`compressed` as an explicit `int` parameter and uses it to pick
`SECP256K1_EC_COMPRESSED` vs `SECP256K1_EC_UNCOMPRESSED` and the
output length (33 vs 65). The Haskell-derived flag is the source of
truth; the C side trusts it.

But: the C side ALSO masks recid with `& 3` (`recid = (header - 27) & 3;`),
implicitly extracting recid from the lower 2 bits of the header
offset. So the C side has the information needed to derive
`compressed = (header - 27) >> 2`, but doesn't — it accepts the
Haskell-derived bit as gospel.

This is benign in current code: both layers derive the same bit from
the same header. But the C wrapper exposes a contract
(`int compressed`) that a future caller (or a refactor that bypasses
the Haskell layer) could violate. Defense-in-depth would have the C
side re-derive the flag from `header` instead of trusting the parameter.

This is haskoin's **two-pipeline guard 14th-distinct-extension**
(W141 fleet-wide pattern). Same shape as BUG-4's `[27..34]` bound
duplication.

**File:** `src/Haskoin/Crypto.hs:754-764`;
`cbits/secp256k1_compat.c:543-575`.

---

## BUG-18 (P3) — `signMessage` ignores the `compressed` parameter for header-byte selection; respects it only for the secp256k1 serialisation step

**Severity:** P3 (correctness — the C side handles this correctly, but
the contract is wider than necessary). `signMessage :: SecKey -> Bool ->
Text -> Maybe ByteString` (`Crypto.hs:777-778`) plumbs `compressed`
straight through to `signCompact`, which passes it to the C side. The
C wrapper's signing path is:

`haskoin_ecdsa_sign_recoverable_compact(seckey, hash, compressed_flag, out65)`

and (per `cbits/secp256k1_compat.c`, not shown here but contracted at
`Crypto.hs:165-170`) it must produce a header byte = `27 + recid +
(4 if compressed else 0)`. If the C side were ever to be replaced with
a stub or a different secp256k1 binding (the existing pattern in
`Storage.hs` already inflates compressed pubkeys via a separate
binding), the header-byte semantics could silently drift.

This is a documentation-only finding: the contract
"compressed=True means header ∈ {31..34}, compressed=False means header
∈ {27..30}" lives in the C source, not in a Haskell-side property test.

**File:** `src/Haskoin/Crypto.hs:777-778`; missing test:
"`signMessage sk True _ → header & 4 == 4`" and the inverse for `False`.

The companion test at `test/Spec.hs:6806-6818` does verify the
header-byte/compressed-flag agreement for `signCompact` — but NOT for
the higher-level `signMessage` (the privkey-direct entry point used by
the RPC). One additional `it` line would close the gap.

---

## Summary

- **Bug count:** 18 — 1 P0-PARITY, 12 P1/P2, 5 P3.
- **P0-class count:** 1 (BUG-6 — SAME constructor TWICE in case-of at
  the RPC dispatch table; both `signmessage` and `signmessagewithprivkey`
  dispatch to one body, collapsing two Core RPCs with distinct
  intended semantics into one).
- **Fleet-wide-confirming finding:** BUG-5 (BIP-322 entirely absent) —
  **haskoin makes 7 of 8 fleet impls confirming BIP-322 is universally
  missing**; the pattern is now crystallized as fleet-universal forward-
  looking gap. Core itself has not merged BIP-322 (PR #24058 still open),
  so this is forward parity rather than current Core mismatch — but a
  coordinated fleet wave is the natural fix.
- **Top 3 most actionable findings:**
  1. **BUG-6 (P0-PARITY)** — `signmessage` and `signmessagewithprivkey`
     share one handler. Split into two; wire the wallet-context path
     into `WalletState` for address-to-key lookup; fixes BUG-7 + BUG-8 +
     BUG-9 + BUG-10 by construction.
  2. **BUG-1 (P1)** — uncompressed-WIF signatures use the wrong header
     byte; `wifDecode` discards the compressed flag (BUG-11) so
     `handleSignMessage` hardcodes `True`. Fix the type signature of
     `wifDecode` to return the flag; propagate through 8 call sites.
  3. **BUG-2 + BUG-13 (P1, W125 BUG-6 4th-wave carry-forward)** — two
     `verifymessage` error sites use a bare `(-3)` literal and have
     been xfail-pinned for ~4 weeks with no production fix. Adding
     `rpcTypeError = -3` plus 2 replacements closes the carry-forward
     and unlocks the matching W125 test rewires.

**Other patterns confirmed in haskoin this wave:**
- **carry-forward re-anchor** (BUG-2, BUG-8 / W125 BUG-6 + BUG-10 4th
  wave open).
- **two-pipeline guard 14th-distinct-extension** (BUG-4, BUG-17 — both
  Haskell + C duplicate the same compressed-flag-header-byte invariant).
- **comment-as-confession** (BUG-1 — "conservatively assume compressed";
  BUG-10 — no-arg help advertises commands the per-command help denies
  exist).
- **already-exports-the-primitive-just-not-called** (BUG-8 —
  `isWalletLocked` is imported in `Rpc.hs:299` but never called by
  `handleSignMessage`).
- **SAME constructor TWICE in case-of (W156 NEW haskoin)** (BUG-6 —
  RPC dispatch table edition).
- **test-pins-bug (W158 NEW)** (BUG-15 — `messageHash` test asserts
  length only, not value).
- **encrypted-wallet-cipher-as-scalar (W158 NEW clearbit)** — NOT
  applicable in haskoin: `wsDecryptedKey` stores the decrypted master
  key correctly (not the ciphertext), AND `handleSignMessage` never
  consults the encrypted-wallet path at all (BUG-8 is the related
  symptom). Cross-cite confirms this haskoin pattern is **clean** vs
  the clearbit shape.
- **misbehaving-primitive-too-aggressive (W156 NEW haskoin)** — NOT
  applicable in signmessage path: `handleVerifyMessage` /
  `handleSignMessage` are pure RPC-side, never call `banPeer` or any
  misbehaving primitive, so a malformed `verifymessage` request cannot
  trigger a peer ban. G29 confirms this is the GOOD case (correctly
  scoped). Cross-cite verifies the misbehaving primitive is correctly
  NOT wired into RPC error paths.

**Carry-forward status:**
- W144 BUG-3 (STANDARD-flags absent) — not in scope for W158, still
  open.
- W148 BUG-3+11 (performReorg writes only undo) — not in scope for
  W158, still open.
- W155 BUG-5 (handleBlockProposal NOOP) — not in scope for W158, still
  open.
- W156 BUG-4 (SAME constructor TWICE) — **CROSS-CITE CONFIRMED**: W158
  finds the same anti-pattern in the RPC dispatch table for
  signmessage/signmessagewithprivkey (BUG-6). This is the SECOND distinct
  haskoin occurrence of the W156 NEW pattern.
- W156 BUG-13+14 (misbehaving primitive too aggressive) — **CROSS-CITE
  CONFIRMED CLEAN**: signmessage/verifymessage error paths do NOT
  trigger any misbehaving primitive (G29). The pattern is correctly
  scoped to peer-side message handling and not bleeding into RPC.
- W125 BUG-6 (literal -3 at verifymessage) — **OPEN 4 waves**; W158
  re-anchors as BUG-2 + BUG-13.
- W125 BUG-10 (no `rpcWalletUnlockNeeded (-13)`) — **OPEN 4 waves**;
  W158 re-anchors as part of BUG-8.
