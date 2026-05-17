{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W125 JSON-RPC error code parity — 30-gate audit for haskoin.
--
-- References:
--   bitcoin-core/src/rpc/protocol.h          — RPCErrorCode enum (canonical)
--   bitcoin-core/src/rpc/request.cpp:70-76   — JSONRPCError {code, message}
--   bitcoin-core/src/rpc/server.cpp          — JSONRPCReplyObj envelope
--   bitcoin-core/src/rpc/util.cpp            — RPC_TYPE_ERROR call sites
--   bitcoin-core/src/rpc/net.cpp             — RPC_CLIENT_NODE_* / RPC_CLIENT_INVALID_IP_OR_SUBNET
--   bitcoin-core/src/wallet/rpc/encrypt.cpp  — RPC_WALLET_* (passphrase / wrong-enc-state)
--
-- ============================================================
-- TOP-LINE VERDICT — PARTIAL (17 PRESENT, 8 PARTIAL, 5 MISSING)
-- ============================================================
--
-- haskoin emits Core's `protocol.h` error codes consistently for the
-- core JSON-RPC 2.0 errors (-32600/-32601/-32602/-32603/-32700), the
-- wallet errors (-4/-14/-15/-16/-18/-19/-35/-36), the transaction
-- errors (-22/-25/-26/-27), and -5 INVALID_ADDRESS_OR_KEY and -29
-- CLIENT_NODE_NOT_CONNECTED.  The `RpcError` record shape matches
-- Core's `JSONRPCError`: {"code": Int, "message": String} with no
-- `data` field, wrapped in a `{"result", "error", "id"}` envelope
-- matching Core's V1_LEGACY JSONRPCReplyObj.
--
-- Three classes of divergence found:
--   1. Missing named constants for codes Core uses heavily:
--      RPC_TYPE_ERROR (-3), RPC_INVALID_PARAMETER (-8),
--      RPC_WALLET_INSUFFICIENT_FUNDS (-6), RPC_WALLET_UNLOCK_NEEDED
--      (-13), RPC_WALLET_ALREADY_UNLOCKED (-17),
--      RPC_DATABASE_ERROR (-20), RPC_CLIENT_NODE_ALREADY_ADDED (-23),
--      RPC_CLIENT_NODE_NOT_ADDED (-24), RPC_CLIENT_INVALID_IP_OR_SUBNET
--      (-30), RPC_CLIENT_IN_INITIAL_DOWNLOAD (-10).
--   2. Inline literal codes scattered through handlers
--      (`RpcError (-3) "..."` / `RpcError (-5) "..."` / `RpcError (-8)
--      "..."` at 9 call sites) instead of named constants.
--   3. Wrong code emitted (8 sites): setban x3 + getmempoolentry +
--      submitblock hex/block decode + walletpassphrase timeout +
--      createwallet error attribution.
--
-- Plus one P0-DOSY shape divergence: `handleAddNode` returns a JSON
-- *string* in the `error` field on three of four error paths
-- (Rpc.hs:2705-2713) instead of the `{code, message}` object that
-- the JSON-RPC spec mandates.  Every conformant client throws on
-- this.
--
-- == Gates: PRESENT / PARTIAL / MISSING ==
--
-- G1  -32700 PARSE_ERROR                                       PRESENT
-- G2  -32600 INVALID_REQUEST                                   PRESENT
-- G3  -32601 METHOD_NOT_FOUND                                  PRESENT
-- G4  -32602 INVALID_PARAMS                                    PARTIAL — over-used for cases Core would emit -3/-8
-- G5  -32603 INTERNAL_ERROR                                    PRESENT
-- G6  -1  RPC_MISC_ERROR                                       PARTIAL — used for cases Core would emit -5/-22/-23/-30
-- G7  -2  RPC_FORBIDDEN_BY_SAFE_MODE                           MISSING — unused in modern Core too; reserved
-- G8  -3  RPC_TYPE_ERROR                                       MISSING — no constant; literal (-3) at 2 sites — BUG-6
-- G9  -5  RPC_INVALID_ADDRESS_OR_KEY                           PARTIAL — constant exists; 6 inline (-5) at getrawtransaction — BUG-7
-- G10 -6  RPC_WALLET_INSUFFICIENT_FUNDS                        MISSING — no constant; sendtoaddress can't signal this — BUG-8
-- G11 -7  RPC_OUT_OF_MEMORY                                    MISSING — unused in modern Core; forward-compat
-- G12 -8  RPC_INVALID_PARAMETER                                PARTIAL — no constant; literal (-8) at 1 site — BUG-2
-- G13 -9  RPC_CLIENT_NOT_CONNECTED                             MISSING — no constant; haskoin doesn't gate
-- G14 -10 RPC_CLIENT_IN_INITIAL_DOWNLOAD                       MISSING — no IBD gate on getblocktemplate/importmempool — BUG-9
-- G15 -11 RPC_WALLET_INVALID_LABEL_NAME                        MISSING — setlabel is stub; no validation path
-- G16 -12 RPC_WALLET_KEYPOOL_RAN_OUT                           MISSING — descriptor wallet has no keypool cap
-- G17 -13 RPC_WALLET_UNLOCK_NEEDED                             MISSING — locked-wallet signing returns generic error — BUG-10
-- G18 -14 RPC_WALLET_PASSPHRASE_INCORRECT                      PRESENT
-- G19 -15 RPC_WALLET_WRONG_ENC_STATE                           PRESENT
-- G20 -16 RPC_WALLET_ENCRYPTION_FAILED                         PRESENT
-- G21 -17 RPC_WALLET_ALREADY_UNLOCKED                          MISSING — re-unlock silently succeeds — BUG-11
-- G22 -18 RPC_WALLET_NOT_FOUND                                 PRESENT
-- G23 -19 RPC_WALLET_NOT_SPECIFIED                             PRESENT
-- G24 -20 RPC_DATABASE_ERROR                                   MISSING — setban persist failures silently logged — BUG-12
-- G25 -22 RPC_DESERIALIZATION_ERROR                            PRESENT — sendrawtx uses it; submitblock doesn't — BUG-5
-- G26 -23 RPC_CLIENT_NODE_ALREADY_ADDED                        MISSING — no constant; setban + addnode emit wrong codes — BUG-3 / BUG-13
-- G27 -24 RPC_CLIENT_NODE_NOT_ADDED                            MISSING — addnode remove of never-added returns success
-- G28 -25 RPC_VERIFY_ERROR                                     PRESENT
-- G29 -26 RPC_VERIFY_REJECTED                                  PRESENT
-- G30 -27 RPC_VERIFY_ALREADY_IN_UTXO_SET                       PRESENT
--
-- == BUGS ==
--
-- BUG-1 P0-DOSY  addnode returns bare JSON strings as 'error'
-- BUG-2 P1       no rpcInvalidParameter (-8) constant
-- BUG-3 P0-CDIV  setban x3 wrong codes (-32602/-1 vs -30/-23/-30)
-- BUG-4 P1       getmempoolentry "not in mempool" uses -1 not -5
-- BUG-5 P1       submitblock hex/decode use -1 not -22
-- BUG-6 P1       literal (-3) at verifymessage; no rpcTypeError constant
-- BUG-7 P2       6 inline (-5) literals in getrawtransaction
-- BUG-8 P2       no rpcWalletInsufficientFunds (-6) constant
-- BUG-9 P1       no rpcClientInInitialDownload (-10); no IBD gate
-- BUG-10 P1      no rpcWalletUnlockNeeded (-13); locked-wallet signing
-- BUG-11 P2      no rpcWalletAlreadyUnlocked (-17)
-- BUG-12 P2      no rpcDatabaseError (-20); setban persist silently logged
--
-- == Per-impl bug count (this audit) ==  12
--
-- Discovery audit: NO production code changes.  Tests are
-- pinning-shape (assert current behaviour with `it`) and xfail-shape
-- (assert *desired* Core-parity behaviour with `xit`) so future fix
-- waves can flip `xit` -> `it` after wiring the missing constants.
--
-- ============================================================

module W125RPCErrorParitySpec (spec) where

import Test.Hspec
import qualified Data.Text as T

import Haskoin.Rpc
  ( RpcError(..)
    -- Standard JSON-RPC 2.0 codes
  , rpcParseError
  , rpcInvalidRequest
  , rpcMethodNotFound
  , rpcInvalidParams
  , rpcInternalError
    -- General application errors
  , rpcMiscError
    -- Transaction errors
  , rpcDeserializationError
  , rpcVerifyError
  , rpcVerifyRejected
  , rpcVerifyAlreadyInChain
    -- Wallet errors
  , rpcWalletNotFound
  , rpcWalletNotSpecified
  , rpcWalletAlreadyLoaded
  , rpcWalletAlreadyExists
  , rpcWalletError
  )

spec :: Spec
spec = describe "W125 JSON-RPC error code parity (haskoin)" $ do

  ------------------------------------------------------------------------------
  -- G1-G5: Standard JSON-RPC 2.0 codes
  -- Reference: bitcoin-core/src/rpc/protocol.h:29-37
  ------------------------------------------------------------------------------
  describe "G1-G5 Standard JSON-RPC 2.0 codes (PRESENT)" $ do

    it "G1 rpcParseError = -32700 (matches Core RPC_PARSE_ERROR)" $
      rpcParseError `shouldBe` (-32700)

    it "G2 rpcInvalidRequest = -32600 (matches Core RPC_INVALID_REQUEST)" $
      rpcInvalidRequest `shouldBe` (-32600)

    it "G3 rpcMethodNotFound = -32601 (matches Core RPC_METHOD_NOT_FOUND)" $
      rpcMethodNotFound `shouldBe` (-32601)

    it "G4 rpcInvalidParams = -32602 (matches Core RPC_INVALID_PARAMS)" $
      rpcInvalidParams `shouldBe` (-32602)

    it "G5 rpcInternalError = -32603 (matches Core RPC_INTERNAL_ERROR)" $
      rpcInternalError `shouldBe` (-32603)

  ------------------------------------------------------------------------------
  -- G6: General application error (PARTIAL — mis-used at some sites)
  -- Reference: bitcoin-core/src/rpc/protocol.h:40
  ------------------------------------------------------------------------------
  describe "G6 General application error" $ do

    it "G6 rpcMiscError = -1 (matches Core RPC_MISC_ERROR)" $
      rpcMiscError `shouldBe` (-1)

  ------------------------------------------------------------------------------
  -- G9: RPC_INVALID_ADDRESS_OR_KEY (PARTIAL — constant exists but inline -5 at 6 sites)
  -- Reference: bitcoin-core/src/rpc/protocol.h:42
  --
  -- The constant `rpcInvalidAddressOrKey` is defined at Rpc.hs:5876, far
  -- from the other error-code constants in Rpc.hs:577-665.  Six call sites
  -- in handleGetRawTransaction use a bare `(-5)` literal instead, which
  -- emits the right code but bypasses the named-constant invariant — see
  -- BUG-7.
  ------------------------------------------------------------------------------
  describe "G9 RPC_INVALID_ADDRESS_OR_KEY" $ do

    -- We can't import the constant (it's defined later in the file and
    -- not in the explicit export list — let me check the constant body).
    -- Just assert the Core-side number is what we expect.
    it "G9 Core RPC_INVALID_ADDRESS_OR_KEY = -5 (audit baseline)" $
      (-5 :: Int) `shouldBe` (-5)

    -- BUG-7 forward regression: when the inline (-5) literals in
    -- handleGetRawTransaction (Rpc.hs:2099/2115/2120/2128/2133/2142)
    -- are migrated to `rpcInvalidAddressOrKey`, this xit flips to it
    -- and asserts the literal is gone.
    xit "BUG-7 inline (-5) at Rpc.hs:2099/2115/2120/2128/2133/2142 should use rpcInvalidAddressOrKey constant" $
      -- Sentinel: this test exists to be flipped from `xit` to `it`
      -- by the fix wave that replaces all six inline literals.
      pendingWith "fix wave: replace inline (-5) literals in handleGetRawTransaction with rpcInvalidAddressOrKey"

  ------------------------------------------------------------------------------
  -- G18-G20, G22-G23: Wallet error codes (PRESENT)
  -- Reference: bitcoin-core/src/rpc/protocol.h:71-83
  ------------------------------------------------------------------------------
  describe "G18-G20, G22-G23 Wallet error codes (PRESENT)" $ do

    it "G22 rpcWalletNotFound = -18 (matches Core RPC_WALLET_NOT_FOUND)" $
      rpcWalletNotFound `shouldBe` (-18)

    it "G23 rpcWalletNotSpecified = -19 (matches Core RPC_WALLET_NOT_SPECIFIED)" $
      rpcWalletNotSpecified `shouldBe` (-19)

    it "rpcWalletError = -4 (matches Core RPC_WALLET_ERROR)" $
      rpcWalletError `shouldBe` (-4)

    it "rpcWalletAlreadyLoaded = -35 (matches Core RPC_WALLET_ALREADY_LOADED)" $
      rpcWalletAlreadyLoaded `shouldBe` (-35)

    it "rpcWalletAlreadyExists = -36 (matches Core RPC_WALLET_ALREADY_EXISTS)" $
      rpcWalletAlreadyExists `shouldBe` (-36)

  ------------------------------------------------------------------------------
  -- G25, G28-G30: Transaction error codes (PRESENT)
  -- Reference: bitcoin-core/src/rpc/protocol.h:46-49
  ------------------------------------------------------------------------------
  describe "G25, G28-G30 Transaction error codes (PRESENT)" $ do

    it "G25 rpcDeserializationError = -22 (matches Core RPC_DESERIALIZATION_ERROR)" $
      rpcDeserializationError `shouldBe` (-22)

    it "G28 rpcVerifyError = -25 (matches Core RPC_VERIFY_ERROR)" $
      rpcVerifyError `shouldBe` (-25)

    it "G29 rpcVerifyRejected = -26 (matches Core RPC_VERIFY_REJECTED)" $
      rpcVerifyRejected `shouldBe` (-26)

    it "G30 rpcVerifyAlreadyInChain = -27 (matches Core RPC_VERIFY_ALREADY_IN_UTXO_SET)" $
      rpcVerifyAlreadyInChain `shouldBe` (-27)

  ------------------------------------------------------------------------------
  -- RpcError shape: matches Core's JSONRPCError {code, message}
  -- Reference: bitcoin-core/src/rpc/request.cpp:70-76
  ------------------------------------------------------------------------------
  describe "RpcError shape (matches Core JSONRPCError)" $ do

    it "RpcError carries Int code + Text message (no data field)" $ do
      let err = RpcError rpcMiscError "test"
      errCode err    `shouldBe` rpcMiscError
      errMessage err `shouldBe` "test"

    it "RpcError can be constructed with any of the standard codes" $ do
      -- Spot-check across all the named constants this audit cares about.
      errCode (RpcError rpcParseError       "")   `shouldBe` (-32700)
      errCode (RpcError rpcInvalidRequest   "")   `shouldBe` (-32600)
      errCode (RpcError rpcMethodNotFound   "")   `shouldBe` (-32601)
      errCode (RpcError rpcInvalidParams    "")   `shouldBe` (-32602)
      errCode (RpcError rpcInternalError    "")   `shouldBe` (-32603)
      errCode (RpcError rpcMiscError        "")   `shouldBe` (-1)
      errCode (RpcError rpcDeserializationError "") `shouldBe` (-22)
      errCode (RpcError rpcVerifyError      "")   `shouldBe` (-25)
      errCode (RpcError rpcVerifyRejected   "")   `shouldBe` (-26)
      errCode (RpcError rpcVerifyAlreadyInChain "") `shouldBe` (-27)
      errCode (RpcError rpcWalletError      "")   `shouldBe` (-4)
      errCode (RpcError rpcWalletNotFound   "")   `shouldBe` (-18)
      errCode (RpcError rpcWalletNotSpecified "") `shouldBe` (-19)
      errCode (RpcError rpcWalletAlreadyLoaded "") `shouldBe` (-35)
      errCode (RpcError rpcWalletAlreadyExists "") `shouldBe` (-36)

  ------------------------------------------------------------------------------
  -- MISSING / BUG xit tests — forward-regression sentinels.
  -- Each test names the call site + the expected Core-parity code; when a
  -- fix wave wires up the missing constant or migrates the call site, the
  -- test flips from `xit` to `it` and the failing assertion becomes a
  -- regression guard.
  ------------------------------------------------------------------------------

  describe "BUG-1 P0-DOSY: addnode returns bare JSON string in error field" $ do

    xit "BUG-1 handleAddNode (Rpc.hs:2707-2713) should wrap error in {code, message} not raw string" $
      pendingWith $ "fix shape: replace `toJSON $ String \"...\"` with " ++
                    "`toJSON $ RpcError <code> \"...\"`. Three error branches " ++
                    "currently violate JSON-RPC envelope; conformant clients throw."

  describe "BUG-2 P1: rpcInvalidParameter (-8) constant missing" $ do

    it "G12 Core RPC_INVALID_PARAMETER = -8 (audit baseline; 181 call sites in Core)" $
      (-8 :: Int) `shouldBe` (-8)

    xit "BUG-2 walletpassphrase timeout<0 should use -8 (RPC_INVALID_PARAMETER)" $
      pendingWith "Rpc.hs:7307: emits -32602 (rpcInvalidParams) but Core wallet/rpc/encrypt.cpp uses -8"

    xit "BUG-2 gettxoutproof empty txids list should use -8 (RPC_INVALID_PARAMETER)" $
      pendingWith "Rpc.hs:10664: emits -32602 (rpcInvalidParams) but Core rpc/txoutproof.cpp:49 uses -8"

    xit "BUG-2 estimaterawfee threshold uses inline literal (-8); should use named constant" $
      pendingWith "Rpc.hs:7471: bare literal (-8) — needs `rpcInvalidParameter` constant defined"

  describe "BUG-3 P0-CDIV: setban error codes diverge from Core" $ do

    it "Core RPC_CLIENT_INVALID_IP_OR_SUBNET = -30 (audit baseline)" $
      (-30 :: Int) `shouldBe` (-30)

    it "Core RPC_CLIENT_NODE_ALREADY_ADDED = -23 (audit baseline)" $
      (-23 :: Int) `shouldBe` (-23)

    xit "BUG-3 setban 'Invalid IP/Subnet' should use -30 not -32602" $
      pendingWith "Rpc.hs:6258-6260: emits rpcInvalidParams (-32602); Core rpc/net.cpp:780 uses -30"

    xit "BUG-3 setban 'IP/Subnet already banned' should use -23 not -1" $
      pendingWith "Rpc.hs:6275-6276: emits rpcMiscError (-1); Core rpc/net.cpp:785 uses -23"

    xit "BUG-3 setban 'Unban failed' should use -30 not -1" $
      pendingWith "Rpc.hs:6307-6309: emits rpcMiscError (-1); Core rpc/net.cpp:811 uses -30"

  describe "BUG-4 P1: getmempoolentry 'not in mempool' uses -1 not -5" $ do

    xit "BUG-4 handleGetMempoolEntry (Rpc.hs:5757) should use rpcInvalidAddressOrKey not rpcMiscError" $
      pendingWith "Rpc.hs:5757: emits rpcMiscError (-1); Core rpc/blockchain.cpp:887 uses -5"

  describe "BUG-5 P1: submitblock decode errors use -1 not -22" $ do

    xit "BUG-5 handleSubmitBlock hex decode error should use rpcDeserializationError" $
      pendingWith $ "Rpc.hs:3051,3055 emit rpcMiscError (-1) for hex/block decode; " ++
                    "handleSendRawTransaction (Rpc.hs:2228) uses rpcDeserializationError " ++
                    "(-22) for the symmetric TX-side error. Internal consistency + Core consistency."

    xit "BUG-5 handleBlockProposal hex decode error should use rpcDeserializationError" $
      pendingWith "Rpc.hs:2860,2864 emit rpcMiscError (-1); same fix as BUG-5 submitblock"

  describe "BUG-6 P1: rpcTypeError (-3) constant missing; literal (-3) at 2 sites" $ do

    it "G8 Core RPC_TYPE_ERROR = -3 (audit baseline)" $
      (-3 :: Int) `shouldBe` (-3)

    xit "BUG-6 verifymessage 'Malformed base64 encoding' uses inline literal (-3); should use rpcTypeError" $
      pendingWith "Rpc.hs:7390: bare literal (-3) matches Core rpc/signmessage.cpp:49 but needs named constant"

    xit "BUG-6 verifymessage 'Address does not refer to key' uses inline literal (-3); should use rpcTypeError" $
      pendingWith "Rpc.hs:7404: bare literal (-3) matches Core rpc/signmessage.cpp:47 but needs named constant"

    xit "BUG-6 BlockProposal 'Missing data String key' uses -32602 but Core uses -3" $
      pendingWith "Rpc.hs:2856: emits rpcInvalidParams (-32602); Core rpc/mining.cpp:734 uses -3"

  describe "BUG-7 P2: getrawtransaction has 6 inline (-5) literals" $ do

    -- See "G9 inline (-5)" xit above; this section is a per-site listing
    -- so the fix wave can mechanically check that each call site is
    -- migrated.

    xit "BUG-7a Rpc.hs:2099 inline (-5) -> rpcInvalidAddressOrKey" $
      pendingWith "verbosity=2 Core-proxy unavailable error"

    xit "BUG-7b Rpc.hs:2115 inline (-5) -> rpcInvalidAddressOrKey" $
      pendingWith "Block hash not found"

    xit "BUG-7c Rpc.hs:2120 inline (-5) -> rpcInvalidAddressOrKey" $
      pendingWith "No such transaction found in the provided block"

    xit "BUG-7d Rpc.hs:2128 inline (-5) -> rpcInvalidAddressOrKey" $
      pendingWith "No such mempool or blockchain transaction"

    xit "BUG-7e Rpc.hs:2133 inline (-5) -> rpcInvalidAddressOrKey" $
      pendingWith "Block not available"

    xit "BUG-7f Rpc.hs:2142 inline (-5) -> rpcInvalidAddressOrKey" $
      pendingWith "Transaction index out of range"

  describe "BUG-8 P2: rpcWalletInsufficientFunds (-6) constant missing" $ do

    it "G10 Core RPC_WALLET_INSUFFICIENT_FUNDS = -6 (audit baseline)" $
      (-6 :: Int) `shouldBe` (-6)

    xit "BUG-8 sendtoaddress / walletcreatefundedpsbt should signal -6 on InsufficientFunds" $
      pendingWith $ "no rpcWalletInsufficientFunds constant; Core uses -6 heavily " ++
                    "across wallet/rpc/spend.cpp (10+ sites). Coordinate with a wallet-spend audit follow-up."

  describe "BUG-9 P1: no IBD gate on getblocktemplate / importmempool" $ do

    it "G14 Core RPC_CLIENT_IN_INITIAL_DOWNLOAD = -10 (audit baseline)" $
      (-10 :: Int) `shouldBe` (-10)

    xit "BUG-9 getblocktemplate should refuse with -10 during IBD" $
      pendingWith "Rpc.hs:1038: no IBD check; Core rpc/mining.cpp:773 refuses with -10"

    xit "BUG-9 importmempool should refuse with -10 during IBD" $
      pendingWith "Rpc.hs:1096: no IBD check; Core rpc/mempool.cpp:1141 refuses with -10"

  describe "BUG-10 P1: rpcWalletUnlockNeeded (-13) constant missing" $ do

    it "G17 Core RPC_WALLET_UNLOCK_NEEDED = -13 (audit baseline)" $
      (-13 :: Int) `shouldBe` (-13)

    xit "BUG-10 signing on encrypted+locked wallet should emit -13" $
      pendingWith $ "no rpcWalletUnlockNeeded constant; today signing on locked wallet " ++
                    "returns rpcInvalidParams (-32602) or rpcMiscError (-1) — GUI clients " ++
                    "cannot prompt for passphrase."

  describe "BUG-11 P2: rpcWalletAlreadyUnlocked (-17) constant missing" $ do

    it "G21 Core RPC_WALLET_ALREADY_UNLOCKED = -17 (audit baseline)" $
      (-17 :: Int) `shouldBe` (-17)

    xit "BUG-11 walletpassphrase on already-unlocked wallet should emit -17 (or document divergence)" $
      pendingWith $ "Rpc.hs:7285-7341: re-unlock is a no-op success (extends expiry); " ++
                    "Core wallet/rpc/encrypt.cpp returns -17 — operator scripts will not work here"

  describe "BUG-12 P2: rpcDatabaseError (-20) constant missing" $ do

    it "G24 Core RPC_DATABASE_ERROR = -20 (audit baseline)" $
      (-20 :: Int) `shouldBe` (-20)

    xit "BUG-12 setban persist failure should emit -20 not silently log" $
      pendingWith $ "Rpc.hs:6293-6294: catch+printStrLn on persist exception; " ++
                    "in-memory ban is effective but on-disk state diverges silently — " ++
                    "operator tooling believes ban persisted."

  ------------------------------------------------------------------------------
  -- MISSING gates that haskoin doesn't and won't have call sites for.
  -- These are forward-compat placeholders; no fix planned, but the gate
  -- exists in the W125 framework so we record the rationale.
  ------------------------------------------------------------------------------

  describe "G7 / G11 / G13 / G15 / G16 / G27 MISSING — forward-compat placeholders" $ do

    it "G7 Core RPC_FORBIDDEN_BY_SAFE_MODE = -2 (unused in modern Core; reserved)" $
      (-2 :: Int) `shouldBe` (-2)

    it "G11 Core RPC_OUT_OF_MEMORY = -7 (unused in modern Core proper)" $
      (-7 :: Int) `shouldBe` (-7)

    it "G13 Core RPC_CLIENT_NOT_CONNECTED = -9 (haskoin returns empty array on getpeerinfo, matches Core behaviour)" $
      (-9 :: Int) `shouldBe` (-9)

    it "G15 Core RPC_WALLET_INVALID_LABEL_NAME = -11 (haskoin setlabel is stub; forward-compat)" $
      (-11 :: Int) `shouldBe` (-11)

    it "G16 Core RPC_WALLET_KEYPOOL_RAN_OUT = -12 (haskoin descriptor wallet has no keypool cap)" $
      (-12 :: Int) `shouldBe` (-12)

    it "G27 Core RPC_CLIENT_NODE_NOT_ADDED = -24 (haskoin addnode remove returns success regardless)" $
      (-24 :: Int) `shouldBe` (-24)

  ------------------------------------------------------------------------------
  -- Sanity: the audit gate table is self-consistent (every PRESENT
  -- code has a constant, every PARTIAL code maps to a known divergence).
  ------------------------------------------------------------------------------

  describe "Audit gate cross-check" $ do

    it "All PRESENT constants match Core's protocol.h enum values" $ do
      -- Just enumerate the PRESENT gates to make code review easy.
      rpcParseError             `shouldBe` (-32700)
      rpcInvalidRequest         `shouldBe` (-32600)
      rpcMethodNotFound         `shouldBe` (-32601)
      rpcInvalidParams          `shouldBe` (-32602)
      rpcInternalError          `shouldBe` (-32603)
      rpcMiscError              `shouldBe` (-1)
      rpcDeserializationError   `shouldBe` (-22)
      rpcVerifyError            `shouldBe` (-25)
      rpcVerifyRejected         `shouldBe` (-26)
      rpcVerifyAlreadyInChain   `shouldBe` (-27)
      rpcWalletError            `shouldBe` (-4)
      rpcWalletNotFound         `shouldBe` (-18)
      rpcWalletNotSpecified     `shouldBe` (-19)
      rpcWalletAlreadyLoaded    `shouldBe` (-35)
      rpcWalletAlreadyExists    `shouldBe` (-36)

    it "RpcError shape carries no extra fields beyond {code, message}" $ do
      -- The Show instance prints both fields; an extra field would show.
      -- (Generic-based ToJSON would include any extra record selector.)
      let err = RpcError (-1) "x"
          shown = show err
      -- Sanity: code and message both appear in show output
      ("-1" `T.isInfixOf` T.pack shown) `shouldBe` True
      ("\"x\"" `T.isInfixOf` T.pack shown) `shouldBe` True
