{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | createrawtransaction must REJECT an unparseable input, never drop it.
--
-- Found 2026-08-28 by the fleet sweep that started from clearbit's
-- unchecked-cast node-kill (an i64 JSON value @intCast to u32 panicked the
-- Zig node).  clearbit crashed on @{"txid": ..., "vout": -1}@; haskoin was
-- the silent-accept twin of the same bad input.
--
-- haskoin built its input list with
--
-- > let inputs = mapMaybe parseInput (V.toList inputsArr)
--
-- and @parseInput@ read @vout@ as a 'Word32', so a negative value yielded
-- 'Nothing' and 'mapMaybe' DISCARDED the whole input.  The live node
-- answered
--
-- > {"result":"02000000000000000000","error":null,"id":null}
--
-- to @createrawtransaction [{"txid":<64 hex>,"vout":-1}] {}@ — a valid
-- version-2 transaction with ZERO inputs, no error — while Bitcoin Core
-- rejects with RPC_INVALID_PARAMETER (-8) "Invalid parameter, vout cannot
-- be negative" (rpc/rawtransaction_util.cpp AddInputs, line 44).
--
-- That is the FABRICATION failure mode: a plausible result manufactured
-- from input that could not be honoured.  It is worse than a crash — the
-- caller gets a transaction that spends nothing and has no way to know the
-- outpoint it asked for was thrown away.
--
-- An out-of-range @sequence@ had the same shape one step further on: it
-- fell back to the default sequence instead of erroring.
--
-- References:
--   bitcoin-core/src/rpc/rawtransaction_util.cpp:33-70  AddInputs
--   bitcoin-core/src/rpc/util.cpp:117-125               ParseHashV
--   bitcoin-core/src/rpc/protocol.h                     RPC_INVALID_PARAMETER = -8
--                                                       RPC_MISC_ERROR = -1
module CreateRawTxDropSpec (spec) where

import Test.Hspec
import Data.Aeson (Value(..), toJSON, object, (.=))
import Data.Aeson.Types (Result(..), fromJSON)
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KM
import Data.Scientific (toBoundedInteger)
import qualified Data.Text as T

import Haskoin.Rpc
  ( RpcResponse(..)
  , handleCreateRawTransaction
  , rpcInvalidParameter
  , rpcMiscError
  )

-- A well-formed 64-hex txid.  Nothing about the txid is under test here;
-- it exists so the ONLY thing wrong with each request is the field named
-- by the test.
goodTxid :: T.Text
goodTxid = T.replicate 64 "a"

-- createrawtransaction params: [inputs, outputs].  Outputs are empty so a
-- successful build produces a transaction whose ONLY content is the inputs
-- — which makes "input silently dropped" observable as an empty tx.
callWith :: Value -> IO RpcResponse
callWith inputsArr =
  -- The handler ignores its RpcServer argument (it touches no chainstate),
  -- so 'undefined' is never forced.  Asserted by 'acceptsValidInput' below:
  -- if it were forced, that test would explode rather than pass.
  handleCreateRawTransaction (error "RpcServer must not be touched")
    (toJSON [inputsArr, object []])

oneInput :: [(T.Text, Value)] -> Value
oneInput fields = toJSON [object [Key.fromText k .= v | (k, v) <- fields]]

-- Extract (code, message) from an error response, or fail loudly.  Reading
-- the JSON shape (not the Haskell record) keeps the assertions tied to what
-- an RPC CLIENT actually sees.
errorOf :: RpcResponse -> IO (Int, T.Text)
errorOf resp = case resError resp of
  Object o ->
    let code = case KM.lookup "code" o of
          Just (Number n) -> maybe minBound id (toBoundedInteger n :: Maybe Int)
          _               -> minBound
        msg = case KM.lookup "message" o of
          Just (String t) -> t
          _               -> "<absent>"
    in return (code, msg)
  other -> do
    expectationFailure ("expected an RPC error object, got error=" ++ show other
                        ++ " result=" ++ show (resResult resp))
    return (0, "")

spec :: Spec
spec = describe "createrawtransaction: malformed input is rejected, not dropped" $ do

  -- THE REGRESSION.  At the parent commit this returned
  -- result="02000000000000000000", error=null.
  it "vout:-1 -> -8, NOT a zero-input transaction" $ do
    resp <- callWith (oneInput [("txid", String goodTxid), ("vout", Number (-1))])
    (code, msg) <- errorOf resp
    code `shouldBe` rpcInvalidParameter
    msg `shouldBe` "Invalid parameter, vout cannot be negative"
    -- Belt and braces: whatever else happens, the caller must NOT be handed
    -- a transaction.  This is the assertion the old code failed.
    resResult resp `shouldBe` Null

  it "missing vout -> -8 missing vout key" $ do
    resp <- callWith (oneInput [("txid", String goodTxid)])
    (code, msg) <- errorOf resp
    code `shouldBe` rpcInvalidParameter
    msg `shouldBe` "Invalid parameter, missing vout key"

  it "non-numeric vout -> -8 missing vout key (Core: !isNum)" $ do
    resp <- callWith (oneInput [("txid", String goodTxid), ("vout", String "0")])
    (code, msg) <- errorOf resp
    code `shouldBe` rpcInvalidParameter
    msg `shouldBe` "Invalid parameter, missing vout key"

  it "vout beyond int32 -> -1 JSON integer out of range (Core getInt<int>)" $ do
    resp <- callWith (oneInput [("txid", String goodTxid), ("vout", Number 2147483648)])
    (code, msg) <- errorOf resp
    code `shouldBe` rpcMiscError
    msg `shouldBe` "JSON integer out of range"

  it "malformed txid -> -8, NOT a dropped input" $ do
    resp <- callWith (oneInput [("txid", String "abc"), ("vout", Number 0)])
    (code, msg) <- errorOf resp
    code `shouldBe` rpcInvalidParameter
    msg `shouldBe` "txid must be of length 64 (not 3, for 'abc')"
    resResult resp `shouldBe` Null

  it "sequence out of range -> -8, NOT a silent fallback to the default" $ do
    resp <- callWith (oneInput
      [("txid", String goodTxid), ("vout", Number 0), ("sequence", Number 4294967296)])
    (code, msg) <- errorOf resp
    code `shouldBe` rpcInvalidParameter
    msg `shouldBe` "Invalid parameter, sequence number is out of range"

  it "negative sequence -> -8" $ do
    resp <- callWith (oneInput
      [("txid", String goodTxid), ("vout", Number 0), ("sequence", Number (-1))])
    (code, _) <- errorOf resp
    code `shouldBe` rpcInvalidParameter

  -- THE CONTROL.  Without this, every assertion above is satisfiable by a
  -- handler that rejects everything.
  it "a valid input still builds a transaction (control)" $ do
    resp <- callWith (oneInput [("txid", String goodTxid), ("vout", Number 0)])
    resError resp `shouldBe` Null
    case fromJSON (resResult resp) :: Result T.Text of
      Success hex -> do
        -- Must actually CONTAIN the input: the empty-tx bug produced
        -- "02000000000000000000", which is 20 hex chars.
        T.length hex `shouldSatisfy` (> 20)
        T.replicate 64 "a" `T.isInfixOf` hex `shouldBe` True
      Error m -> expectationFailure ("expected a hex transaction: " ++ m)

  -- The locktime argument had the SAME shape as the dropped input, and I
  -- missed it on the first pass: `fromMaybe 0 (extractParam params 2 ::
  -- Maybe Word32)` turned a negative locktime into Nothing and then into 0.
  -- The live node answered a transaction with nLockTime = 0 and no error.
  -- Core rejects with -8 "Invalid parameter, locktime out of range"
  -- (rawtransaction_util.cpp ConstructTransaction:151-155). The same
  -- expression appears in createpsbt and walletcreatefundedpsbt, which share
  -- ConstructTransaction in Core; all three now go through parseLocktimeArg.
  it "locktime:-1 -> -8, NOT a silent nLockTime of 0" $ do
    resp <- handleCreateRawTransaction (error "RpcServer must not be touched")
      (toJSON [oneInput [("txid", String goodTxid), ("vout", Number 0)],
               object [], Number (-1)])
    (code, msg) <- errorOf resp
    code `shouldBe` rpcInvalidParameter
    msg `shouldBe` "Invalid parameter, locktime out of range"

  it "locktime beyond LOCKTIME_MAX -> -8" $ do
    resp <- handleCreateRawTransaction (error "RpcServer must not be touched")
      (toJSON [oneInput [("txid", String goodTxid), ("vout", Number 0)],
               object [], Number 4294967296])
    (code, msg) <- errorOf resp
    code `shouldBe` rpcInvalidParameter
    msg `shouldBe` "Invalid parameter, locktime out of range"

  -- CONTROL: LOCKTIME_MAX itself is legal.
  it "locktime = 0xFFFFFFFF is accepted (control)" $ do
    resp <- handleCreateRawTransaction (error "RpcServer must not be touched")
      (toJSON [oneInput [("txid", String goodTxid), ("vout", Number 0)],
               object [], Number 4294967295])
    resError resp `shouldBe` Null

  -- Core ignores a NON-numeric sequence rather than erroring
  -- (rawtransaction_util.cpp: `if (sequenceObj.isNum())`).  Pinned so a
  -- later "tighten everything" pass cannot silently diverge from Core.
  it "non-numeric sequence is ignored, matching Core's isNum() guard" $ do
    resp <- callWith (oneInput
      [("txid", String goodTxid), ("vout", Number 0), ("sequence", String "nope")])
    resError resp `shouldBe` Null
