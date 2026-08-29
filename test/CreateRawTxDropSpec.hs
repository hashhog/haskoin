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
import Data.Char (digitToInt, isHexDigit)
import Data.Word (Word32)
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
spec = do
  dropSpec
  rbfContradictionSpec
  versionSpec

dropSpec :: Spec
dropSpec = describe "createrawtransaction: malformed input is rejected, not dropped" $ do

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

--------------------------------------------------------------------------------
-- ConstructTransaction's LAST check: replaceable vs. the sequence numbers
--------------------------------------------------------------------------------

-- A second well-formed txid, so the two-input row has two distinct outpoints
-- and the assertion on the decoded sequence list is order-revealing.
otherTxid :: T.Text
otherTxid = T.replicate 64 "b"

-- createrawtransaction params: [inputs, outputs, locktime, replaceable].
-- Outputs are empty and locktime is pinned to 0, so the ONLY things varying
-- across the rows below are the replaceable argument and the per-input
-- sequences — which is the whole point of the table.
callRbf :: Value -> Value -> IO RpcResponse
callRbf inputsArr rbfArg =
  handleCreateRawTransaction (error "RpcServer must not be touched")
    (toJSON [inputsArr, object [], Number 0, rbfArg])

-- Build an inputs array from N field-lists ('oneInput' is the N = 1 case).
inputsOf :: [[(T.Text, Value)]] -> Value
inputsOf entries =
  toJSON [ object [Key.fromText k .= v | (k, v) <- fields] | fields <- entries ]

-- | Decode one big-endian pair of hex characters.
hexByte :: T.Text -> Word32
hexByte t = case T.unpack t of
  [a, b] | isHexDigit a && isHexDigit b ->
    fromIntegral (16 * digitToInt a + digitToInt b)
  _ -> error ("not a hex byte: " ++ show t)

-- | Decode a little-endian 4-byte hex field (8 characters) to its value.
leWord32 :: T.Text -> Word32
leWord32 t = sum [ hexByte b * (256 ^ i)
                 | (i, b) <- zip [(0 :: Int) ..] (chunk2 t) ]
  where
    chunk2 s | T.null s  = []
             | otherwise = let (h, r) = T.splitAt 2 s in h : chunk2 r

-- | Pull the nSequence of every input out of a serialized legacy transaction.
--
-- Deliberately minimal: it understands exactly the shapes this spec builds
-- (fewer than 0xfd inputs, empty scriptSigs) and REPORTS anything else instead
-- of guessing, so a malformed decode can never masquerade as a passing
-- assertion.  Layout: version(4) | varint nIn | [ txid(32) vout(4) varint
-- scriptLen script nSequence(4) ] | varint nOut | ... | nLockTime(4).
sequencesOf :: T.Text -> Either String [Word32]
sequencesOf hex
  | T.length hex < 10 = Left ("transaction hex too short: " ++ T.unpack hex)
  | nIn >= 0xfd       = Left "input-count varint too large for this helper"
  | otherwise         = go nIn afterCount []
  where
    afterVersion = T.drop 8 hex
    nIn          = fromIntegral (hexByte (T.take 2 afterVersion)) :: Int
    afterCount   = T.drop 2 afterVersion

    go :: Int -> T.Text -> [Word32] -> Either String [Word32]
    go 0 _ acc = Right (reverse acc)
    go k rest acc
      | T.length rest < 64 + 8 + 2 = Left "truncated input"
      | otherwise =
          let afterOutpoint   = T.drop (64 + 8) rest        -- txid(32) + vout(4)
              scriptLen       = fromIntegral (hexByte (T.take 2 afterOutpoint)) :: Int
              afterScript     = T.drop (2 + 2 * scriptLen) afterOutpoint
              (seqHex, rest') = T.splitAt 8 afterScript
          in if T.length seqHex < 8
               then Left "truncated input (no nSequence)"
               else go (k - 1) rest' (leWord32 seqHex : acc)

-- | Assert the call SUCCEEDED and that the transaction it returned carries
-- exactly these nSequence values, in order.
--
-- The ACCEPT rows are the controls, and "no error was returned" is too weak a
-- control: it would also pass if the handler had quietly rewritten the caller's
-- sequence to resolve the contradiction — the exact fabrication this whole file
-- exists to forbid.  So decode the bytes and pin the real values.
expectSequences :: RpcResponse -> [Word32] -> IO ()
expectSequences resp expected = do
  resError resp `shouldBe` Null
  case fromJSON (resResult resp) :: Result T.Text of
    Error m -> expectationFailure ("expected a hex transaction: " ++ m)
    Success hex -> case sequencesOf hex of
      Left e      -> expectationFailure
                       ("could not decode " ++ T.unpack hex ++ ": " ++ e)
      Right seqs  -> seqs `shouldBe` expected

-- | Assert the call was REJECTED with Core's contradiction error, and that no
-- transaction leaked out alongside it.
expectContradiction :: RpcResponse -> IO ()
expectContradiction resp = do
  (code, msg) <- errorOf resp
  code `shouldBe` rpcInvalidParameter
  msg `shouldBe`
    "Invalid parameter combination: Sequence number(s) contradict replaceable option"
  resResult resp `shouldBe` Null

-- | createrawtransaction must REFUSE a request that says "replaceable" and
-- "not replaceable" at the same time.
--
-- `replaceable` and a per-input `sequence` are two ways of expressing the same
-- property, and a caller can set them to contradict each other: ask for
-- @replaceable=true@ while pinning every input to a FINAL sequence
-- (0xffffffff), which is precisely opting OUT of BIP-125.  Nine of the ten
-- nodes in this repo — haskoin included, before this commit — silently accept
-- that.  They resolve the contradiction in favour of the sequence, return a
-- transaction that CANNOT be fee-bumped, and report error=null.  The caller
-- asked for replaceability, was told nothing, and discovers the truth only when
-- the fee turns out too low and the bump is refused.  Core does not pick a
-- winner between two halves of a self-contradicting request; it rejects the
-- request with RPC_INVALID_PARAMETER (-8).
--
-- The check is ConstructTransaction's last act, run only after AddInputs AND
-- AddOutputs have both succeeded (rpc/rawtransaction_util.cpp:166-168):
--
-- >  if (rbf.has_value() && rbf.value() && rawTx.vin.size() > 0 &&
-- >      !SignalsOptInRBF(CTransaction(rawTx))) {
-- >      throw JSONRPCError(RPC_INVALID_PARAMETER,
-- >          "Invalid parameter combination: Sequence number(s) contradict "
-- >          "replaceable option");
-- >  }
--
-- so it fires only when ALL THREE hold: `replaceable` was EXPLICITLY given as
-- true, there is at least one input, and NO input signals opt-in RBF
-- (util/rbf.cpp SignalsOptInRBF: any nSequence <= MAX_BIP125_RBF_SEQUENCE,
-- 0xfffffffd, util/rbf.h:12).
--
-- THE ASYMMETRY IS DELIBERATE.  Core keeps rbf as std::optional<bool> that
-- stays nullopt when the argument isNull() (rpc/rawtransaction.cpp:398-401),
-- then reads it two different ways: AddInputs uses `rbf.value_or(true)`, so an
-- ABSENT argument still selects the RBF default sequence, while this check uses
-- `rbf.has_value() && rbf.value()`, so an absent argument expresses no opinion
-- and there is nothing to contradict.  Row 1 below is that distinction, and it
-- is the easiest one to break: a check written against `fromMaybe True` would
-- reject an ordinary final-sequence transaction that never mentioned
-- replaceability at all.
--
-- Every row was verified against a LIVE Bitcoin Core node before being written
-- down.  The four ACCEPT rows matter as much as the rejects — they are what
-- stops an over-eager check from breaking normal RBF usage.
rbfContradictionSpec :: Spec
rbfContradictionSpec =
  describe "createrawtransaction: replaceable must not contradict the sequences" $ do

    -- Row 1.  Rule 1 fails: no EXPLICIT rbf, so nothing was contradicted.
    -- The sequence the caller supplied must survive untouched.
    it "row 1: rbf ABSENT + sequence 0xffffffff -> ACCEPT" $ do
      resp <- callWith (oneInput
        [("txid", String goodTxid), ("vout", Number 0),
         ("sequence", Number 4294967295)])
      expectSequences resp [0xffffffff]

    -- Row 2.  Rule 3 fails: 0xfffffffd IS MAX_BIP125_RBF_SEQUENCE, the
    -- canonical opt-in signal.  The comparison is <=, not <.
    it "row 2: replaceable=true + sequence 0xfffffffd -> ACCEPT (that IS the signal)" $ do
      resp <- callRbf
        (oneInput [("txid", String goodTxid), ("vout", Number 0),
                   ("sequence", Number 4294967293)])
        (toJSON True)
      expectSequences resp [0xfffffffd]

    -- Row 3.  0xfffffffe is one above MAX_BIP125_RBF_SEQUENCE — the
    -- non-final-but-not-replaceable sequence.  Off-by-one boundary.
    it "row 3: replaceable=true + sequence 0xfffffffe -> REJECT -8" $ do
      resp <- callRbf
        (oneInput [("txid", String goodTxid), ("vout", Number 0),
                   ("sequence", Number 4294967294)])
        (toJSON True)
      expectContradiction resp

    -- Row 4.  THE HEADLINE CASE: "make it fee-bumpable" plus a final
    -- sequence.  This is what the live node used to answer with a
    -- non-replaceable transaction and error=null.
    it "row 4: replaceable=true + sequence 0xffffffff -> REJECT -8" $ do
      resp <- callRbf
        (oneInput [("txid", String goodTxid), ("vout", Number 0),
                   ("sequence", Number 4294967295)])
        (toJSON True)
      expectContradiction resp

    -- Row 5.  Rule 2 fails: vin.size() > 0 is false.  A transaction with no
    -- inputs signals nothing, and Core lets it through rather than treating
    -- "nothing to signal with" as a contradiction.
    it "row 5: replaceable=true + NO inputs -> ACCEPT" $ do
      resp <- callRbf (toJSON ([] :: [Value])) (toJSON True)
      expectSequences resp []

    -- Row 6.  Rule 3 fails: SignalsOptInRBF is ANY, not ALL.  BIP-125 is
    -- explicit that one party in a multi-party transaction must not be able
    -- to opt the whole thing out, so a single signalling input is enough
    -- even though the other input is final.  Easy to get wrong as `all`.
    it "row 6: replaceable=true + one final input and one signalling input -> ACCEPT" $ do
      resp <- callRbf
        (inputsOf
          [ [("txid", String goodTxid),  ("vout", Number 0),
             ("sequence", Number 4294967295)]
          , [("txid", String otherTxid), ("vout", Number 1),
             ("sequence", Number 0)]
          ])
        (toJSON True)
      expectSequences resp [0xffffffff, 0]

    -- Row 7.  Rule 1 fails the other way: replaceable=false plus a final
    -- sequence is agreement, not contradiction.
    it "row 7: replaceable=false + sequence 0xffffffff -> ACCEPT" $ do
      resp <- callRbf
        (oneInput [("txid", String goodTxid), ("vout", Number 0),
                   ("sequence", Number 4294967295)])
        (toJSON False)
      expectSequences resp [0xffffffff]

    -- Row 8.  No explicit sequence at all, so AddInputs' rbf.value_or(true)
    -- picks MAX_BIP125_RBF_SEQUENCE — the default already agrees with the
    -- request.  Pins that the new check did not disturb defaultSequence.
    it "row 8: replaceable=true + NO explicit sequence -> ACCEPT with 0xfffffffd" $ do
      resp <- callRbf
        (oneInput [("txid", String goodTxid), ("vout", Number 0)])
        (toJSON True)
      expectSequences resp [0xfffffffd]

    -- Beyond the table, guarding the subtlety row 1 depends on: Core treats an
    -- explicit JSON null exactly like an omitted argument (UniValue::isNull()),
    -- so null must behave as row 1 does — no check, but still the RBF default
    -- sequence for inputs that do not name one.
    it "explicit JSON null replaceable behaves as ABSENT, not as false" $ do
      resp <- callRbf
        (oneInput [("txid", String goodTxid), ("vout", Number 0),
                   ("sequence", Number 4294967295)])
        Null
      expectSequences resp [0xffffffff]
      resp2 <- callRbf (oneInput [("txid", String goodTxid), ("vout", Number 0)]) Null
      expectSequences resp2 [0xfffffffd]

-- ---------------------------------------------------------------------------
-- createrawtransaction must HONOUR the `version` argument, not ignore it.
--
-- THE DEFECT.  Core's createrawtransaction takes a 5th argument, `version`
-- (rpc/rawtransaction.cpp:122), reads it as self.Arg<uint32_t>("version"),
-- bounds it to [TX_MIN_STANDARD_VERSION, TX_MAX_STANDARD_VERSION] = [1, 3]
-- (policy/policy.h:152-153) and ASSIGNS it (rawtransaction_util.cpp:158-161).
--
-- haskoin hardcoded `txVersion = 2` and ignored the argument. Asked for
-- version 1, 2 or 3 it returned 02000000 every time, and version 4 -- which
-- Core rejects -- was accepted. A success reply for a request that was not
-- honoured. Version 3 is TRUC (BIP 431), so a caller who asked for v3 and got
-- v2 holds a transaction with different relay behaviour than the one
-- requested, with nothing in the reply saying so.
--
-- THE UNSIGNED WIDTH DECIDES WHICH ERROR YOU GET: `version` is uint32, unlike
-- the int32 used for vout, so 2147483648 survives the conversion and reaches
-- the DOMAIN error (-8), while -1 and 4294967296 fail the CONVERSION first
-- (-1). Both directions are asserted below.
--
-- A HASKELL-SPECIFIC HAZARD: `Int` here is 64-bit where Core's `int` is 32, so
-- bounding through `Int` would silently accept values Core refuses. The parser
-- compares against the uint32 range explicitly; the 2^32 case is what pins it.
--
-- THE ASSERTIONS DECODE THE VERSION BYTES from the returned hex. Checking only
-- that the call was accepted is exactly the pre-fix behaviour.

-- | createrawtransaction with an explicit version argument.
callWithVersion :: Maybe Value -> IO RpcResponse
callWithVersion mv =
  handleCreateRawTransaction (error "RpcServer must not be touched") $
    case mv of
      Nothing -> toJSON [inputs, object [], Number 0, Bool False]
      Just v  -> toJSON [inputs, object [], Number 0, Bool False, v]
  where
    inputs = oneInput [("txid", String goodTxid), ("vout", Number 0)]

-- | The transaction version is the first 4 bytes of the hex, little-endian.
versionOf :: RpcResponse -> IO Int
versionOf resp = case resResult resp of
  String h | T.length h >= 8 ->
    let byteAt i = case readHexByte (T.take 2 (T.drop (i * 2) h)) of
                     Just b  -> b
                     Nothing -> 0
    in return (byteAt 0 + byteAt 1 * 256 + byteAt 2 * 65536 + byteAt 3 * 16777216)
  other -> do
    expectationFailure ("expected a transaction hex, got result=" ++ show other
                        ++ " error=" ++ show (resError resp))
    return 0
  where
    readHexByte t = case T.unpack t of
      [a, b] -> (\x y -> x * 16 + y) <$> hexDigit a <*> hexDigit b
      _      -> Nothing
    hexDigit c
      | c >= '0' && c <= '9' = Just (fromEnum c - fromEnum '0')
      | c >= 'a' && c <= 'f' = Just (fromEnum c - fromEnum 'a' + 10)
      | c >= 'A' && c <= 'F' = Just (fromEnum c - fromEnum 'A' + 10)
      | otherwise            = Nothing

versionSpec :: Spec
versionSpec = describe "createrawtransaction: the version argument is honoured" $ do

  -- THE REGRESSION. At the parent commit all three returned 02000000.
  it "versions 1, 2 and 3 are emitted, not forced to 2" $
    mapM_ (\want -> do
             resp <- callWithVersion (Just (Number (fromIntegral (want :: Int))))
             got <- versionOf resp
             got `shouldBe` want)
          [1, 2, 3]

  it "version 0 -> -8 out of range(1~3)" $ do
    resp <- callWithVersion (Just (Number 0))
    (code, msg) <- errorOf resp
    code `shouldBe` rpcInvalidParameter
    msg `shouldBe` "Invalid parameter, version out of range(1~3)"

  it "version 4 -> -8 out of range(1~3), NOT accepted" $ do
    resp <- callWithVersion (Just (Number 4))
    (code, msg) <- errorOf resp
    code `shouldBe` rpcInvalidParameter
    msg `shouldBe` "Invalid parameter, version out of range(1~3)"
    resResult resp `shouldBe` Null

  it "version 2147483648 fits uint32 -> DOMAIN error (-8), not -1" $ do
    resp <- callWithVersion (Just (Number 2147483648))
    (code, msg) <- errorOf resp
    code `shouldBe` rpcInvalidParameter
    msg `shouldBe` "Invalid parameter, version out of range(1~3)"

  it "version 4294967296 is outside uint32 -> CONVERSION error (-1), not -8" $ do
    resp <- callWithVersion (Just (Number 4294967296))
    (code, msg) <- errorOf resp
    code `shouldBe` rpcMiscError
    msg `shouldBe` "JSON integer out of range"

  it "version -1 is outside uint32 -> CONVERSION error (-1)" $ do
    resp <- callWithVersion (Just (Number (-1)))
    (code, msg) <- errorOf resp
    code `shouldBe` rpcMiscError
    msg `shouldBe` "JSON integer out of range"

  -- CONTROLS. Without these a handler that rejected every version would
  -- satisfy every rejection above.
  it "CONTROL absent version defaults to 2 (Core DEFAULT_RAWTX_VERSION)" $ do
    resp <- callWithVersion Nothing
    got <- versionOf resp
    got `shouldBe` 2

  it "CONTROL explicit null version defaults to 2" $ do
    resp <- callWithVersion (Just Null)
    got <- versionOf resp
    got `shouldBe` 2
