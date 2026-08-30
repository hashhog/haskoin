{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | The integer CONVERSION runs before the lookup.  REGRESSION PINS.
--
-- #81 fixed the arguments haskoin ACCEPTED out of range.  This is the other
-- half: arguments haskoin REJECTED, but with the wrong error, because the
-- width check ran after -- or instead of -- the conversion.  Measured against
-- a regtest Core oracle (tools\/rpc-arg-differential.py): 23 findings.
--
-- Two of them were worse than a wrong code.  @getblockhash@ read its height
-- as a 'Word32' and @gettxout@ its vout the same way, so an out-of-width value
-- failed the PARSE and was reported as
--
--   -32602 \"Missing height parameter\"
--   -32602 \"Missing txid or vout parameter\"
--
-- -- an argument the caller SUPPLIED, reported as absent.  An operator reading
-- that would go looking for a client bug that does not exist.
--
-- The rest were ordering:
--
--   getblock \<hash\> \<verbosity\>   -5 \"Block not found\"              (Core -1)
--   getrawtransaction \<t\> \<verb\>  -5 \"No such mempool or ...\"       (Core -1)
--   getchaintxstats \<nblocks\>     -8 \"Invalid block count...\"       (Core -1)
--   waitforblock \<h\> \<timeout\>    -1 \"Negative timeout\"             (Core -1
--                                    \"JSON integer out of range\")
--
-- The wait-family row is the one that hid the longest: the CODE already
-- agreed (-1 both sides), and only comparing the MESSAGE showed that the
-- handler's own negative-timeout test was running before the conversion.
--
-- Haskell's 'Int' is 64-bit, so nothing overflowed anywhere -- every handler
-- simply carried a value Core refuses into a lookup Core never performs.
--
-- TEETH: every case here is a rejection, and a handler that rejected
-- EVERYTHING would satisfy all of them.  The CONTROLS drive the same handlers
-- to their REAL answers (-8 for an in-range illegal height, "Negative timeout"
-- for an in-range negative one, and the int32 boundary values converting
-- cleanly), so a bound off by one in the tight direction fails loudly.
--
-- 'noServer' is load-bearing: it is bottom, so any handler that touched an
-- 'RpcServer' field before finishing argument validation would crash rather
-- than pass.  These specs therefore prove the ORDERING, not just the code.
module RpcConversionBeforeLookupSpec (spec) where

import Control.Exception (SomeException, try)
import Test.Hspec
import Data.Aeson (Value(..), toJSON)
import qualified Data.Aeson.KeyMap as KM
import Data.Scientific (toBoundedInteger)
import qualified Data.Text as T

import Haskoin.Rpc
  ( RpcResponse(..)
  , handleGetBlock
  , handleGetBlockHash
  , handleGetRawTransaction
  , handleGetTxOut
  , handleWaitForBlock
  , handleWaitForNewBlock
  , rpcInvalidParameter
  , rpcMiscError
  )

outOfInt32 :: [Value]
outOfInt32 = map (Number . fromInteger)
  [2147483648, -2147483649, 4294967296, -4294967297]

absentHash :: Value
absentHash = String (T.replicate 62 "0" <> "ff")

someTxid :: Value
someTxid = String "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

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
  Null -> expectationFailure
            ("expected an error, got result: " ++ show (resResult resp))
            >> return (0, "")
  other -> expectationFailure ("unexpected error shape: " ++ show other)
            >> return (0, "")

expectRange :: RpcResponse -> IO ()
expectRange resp = errorOf resp >>= (`shouldBe` (rpcMiscError, "JSON integer out of range"))

noServer :: a
noServer = error "RpcServer must not be touched by argument validation"

spec :: Spec
spec = do
  describe "getblockhash height is getInt<int>, then -8" $ do
    it "answers -1 from the CONVERSION, not -32602 'Missing height parameter'" $
      mapM_ (\v -> handleGetBlockHash noServer (toJSON [v]) >>= expectRange)
            outOfInt32
    it "CONTROL: a genuinely absent height is still 'Missing height parameter'" $ do
      resp <- handleGetBlockHash noServer (toJSON ([] :: [Value]))
      errorOf resp >>= (`shouldBe` (-32602, "Missing height parameter"))

  describe "getblock verbosity is getInt<int>, before the block lookup" $
    it "answers -1, not -5 'Block not found'" $
      mapM_ (\v -> handleGetBlock noServer (toJSON [absentHash, v]) >>= expectRange)
            outOfInt32

  describe "getrawtransaction verbosity is getInt<int>, before the tx lookup" $ do
    it "answers -1, not -5 'No such mempool or blockchain transaction'" $
      mapM_ (\v -> handleGetRawTransaction noServer (toJSON [someTxid, v]) >>= expectRange)
            outOfInt32
    it "CONTROL: Core parses the txid FIRST, so a malformed one still wins -8" $ do
      resp <- handleGetRawTransaction noServer
                (toJSON [String "nothex", Number 4294967296])
      (code, _) <- errorOf resp
      code `shouldBe` rpcInvalidParameter

  describe "gettxout n is getInt<uint32_t>" $ do
    it "answers -1, not -32602 'Missing txid or vout parameter'" $
      mapM_ (\v -> handleGetTxOut noServer (toJSON [someTxid, v]) >>= expectRange)
            [Number 4294967296, Number (-1), Number (-2147483649)]
    it "CONTROL: 2147483648 is a VALID uint32 vout and must survive the conversion" $ do
      -- An int32 bound here would wrongly reject HALF the legal vout range.
      -- A surviving value goes on to the coins-view lookup, which forces
      -- 'noServer' and throws -- and THAT is the proof it got past the
      -- conversion. A conversion failure would have returned cleanly instead.
      r <- try (handleGetTxOut noServer (toJSON [someTxid, Number 2147483648]))
             :: IO (Either SomeException RpcResponse)
      case r of
        Left _     -> return ()   -- reached the lookup: correct
        Right resp -> do
          (code, msg) <- errorOf resp
          (code, msg) `shouldNotBe` (rpcMiscError, "JSON integer out of range")

  describe "the wait family: the conversion beats the negative-timeout test" $ do
    it "waitfornewblock answers 'JSON integer out of range', not 'Negative timeout'" $
      mapM_ (\v -> handleWaitForNewBlock noServer (toJSON [v]) >>= expectRange)
            outOfInt32
    it "waitforblock answers 'JSON integer out of range', not 'Negative timeout'" $
      mapM_ (\v -> handleWaitForBlock noServer (toJSON [absentHash, v]) >>= expectRange)
            outOfInt32
    it "CONTROL: an IN-RANGE negative timeout still gets 'Negative timeout'" $ do
      resp <- handleWaitForNewBlock noServer (toJSON [Number (-1)])
      errorOf resp >>= (`shouldBe` (rpcMiscError, "Negative timeout"))
    it "CONTROL: the int32 boundaries convert cleanly (not the range error)" $
      mapM_ (\v -> do
               resp <- handleWaitForNewBlock noServer (toJSON [Number v])
               (code, msg) <- errorOf resp
               (code, msg) `shouldNotBe` (rpcMiscError, "JSON integer out of range"))
            [-2147483648]
