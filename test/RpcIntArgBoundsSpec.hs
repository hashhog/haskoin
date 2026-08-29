{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | RPC integer arguments must be read at CORE'S WIDTH — and honoured.
--
-- Core reads every numeric RPC argument through @UniValue::getInt<T>()@
-- (univalue.h), which runs @std::from_chars@ INTO THE DESTINATION WIDTH.  The
-- width check therefore lives inside the CONVERSION and fires BEFORE the
-- handler's own domain test:
--
-- >   out of width / fractional  ->  RPC_MISC_ERROR (-1) "JSON integer out of
-- >                                  range"      (rpc/server.cpp:514-515)
-- >   converts, violates range   ->  RPC_INVALID_PARAMETER (-8)
--
-- Haskell's 'Int' is SIXTY-FOUR bits, so @toBoundedInteger n :: Maybe Int@
-- accepts 2147483648 without complaint and the handler then acts on it.
-- Measured against a regtest Bitcoin Core oracle
-- (tools/rpc-arg-differential.py), haskoin ACCEPTED 10 arguments Core refuses.
--
-- Two were FABRICATIONS — an argument read and then not honoured:
--
--   * @estimatesmartfee@ took ANY conf_target (no bound at all) and ignored
--     @estimate_mode@ entirely, so \"\" and any other garbage got an estimate.
--     Core's @ParseConfirmTarget@ (rpc/util.cpp) rejects outside
--     [1, HighestTargetTracked]; @FeeModeFromString@ (common/messages.cpp)
--     validates the mode, case-insensitively.
--   * @createpsbt@ never checked its 5th argument. Core builds
--     createrawtransaction AND createpsbt from one @ConstructTransaction@, so
--     both bound @version@ to [1,3] — only createrawtransaction did, and
--     @createpsbt [] [] 1 true 2147483648@ was accepted outright.
--
-- TEETH: every case here is a rejection, and a handler that rejected
-- EVERYTHING would satisfy all of them.  The CONTROLS drive the same handlers
-- to success at the boundary values (int32 max, conf_target 1 and 1008, the
-- three fee modes, version 1..3), so a bound off by one in the tight direction
-- fails loudly.
module RpcIntArgBoundsSpec (spec) where

import Test.Hspec
import Data.Aeson (Value(..), toJSON, object)
import qualified Data.Aeson.KeyMap as KM
import Data.Scientific (toBoundedInteger)
import qualified Data.Text as T

import Haskoin.Rpc
  ( RpcResponse(..)
  , handleCreatePsbt
  , handleEstimateSmartFee
  , handleGetNodeAddresses
  , handleWaitForBlockHeight
  , rpcInvalidParameter
  , rpcMiscError
  )

outOfInt32 :: [Value]
outOfInt32 = map (Number . fromInteger)
  [2147483648, -2147483649, 4294967296, -4294967297]

-- | (code, message) as an RPC CLIENT would see them, or a loud failure.
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

expectAccepted :: RpcResponse -> IO ()
expectAccepted resp = case resError resp of
  Null -> return ()
  other -> expectationFailure
             ("in-range argument was REJECTED: " ++ show other)

noServer :: a
noServer = error "RpcServer must not be touched by argument validation"

spec :: Spec
spec = do
  describe "waitforblockheight height/timeout are getInt<int>" $ do
    it "rejects an out-of-int32 height" $
      mapM_ (\v -> handleWaitForBlockHeight noServer (toJSON [v]) >>= expectRange)
            outOfInt32
    it "rejects an out-of-int32 timeout" $
      mapM_ (\v -> handleWaitForBlockHeight noServer (toJSON [Number 1, v]) >>= expectRange)
            outOfInt32
    it "CONTROL: an in-range negative timeout keeps Core's own message" $ do
      resp <- handleWaitForBlockHeight noServer (toJSON [Number 1, Number (-1)])
      errorOf resp >>= (`shouldBe` (rpcMiscError, "Negative timeout"))

  describe "getnodeaddresses count is getInt<int>, then -8" $ do
    it "rejects an out-of-int32 count with the CONVERSION error" $
      mapM_ (\v -> handleGetNodeAddresses noServer (toJSON [v]) >>= expectRange)
            outOfInt32
    it "CONTROL: an in-range negative count keeps the -8 domain error" $ do
      resp <- handleGetNodeAddresses noServer (toJSON [Number (-1)])
      errorOf resp >>= (`shouldBe` (rpcInvalidParameter, "Address count out of range"))

  describe "estimatesmartfee conf_target / estimate_mode" $ do
    it "rejects an out-of-int32 conf_target" $
      mapM_ (\v -> handleEstimateSmartFee noServer (toJSON [v]) >>= expectRange)
            outOfInt32
    it "rejects an in-range conf_target outside [1,1008] instead of answering" $
      mapM_ (\v -> do
               resp <- handleEstimateSmartFee noServer (toJSON [Number v])
               errorOf resp >>= (`shouldBe`
                 (rpcInvalidParameter, "Invalid conf_target, must be between 1 and 1008")))
            [0, -1, 1009, 99999]
    it "rejects an unknown estimate_mode instead of ignoring it" $
      mapM_ (\m -> do
               resp <- handleEstimateSmartFee noServer (toJSON [Number 6, String m])
               errorOf resp >>= (`shouldBe`
                 ( rpcInvalidParameter
                 , "Invalid estimate_mode parameter, must be one of: \"unset\", \"economical\", \"conservative\"")))
            ["", "garbage", "ECONOMICALLY"]

  describe "createpsbt version — the same argument createrawtransaction bounds" $ do
    it "rejects an out-of-uint32 version with the conversion error" $
      mapM_ (\v -> handleCreatePsbt noServer
                     (toJSON [toJSON ([] :: [Value]), object [], Number 1, Bool True, v])
                     >>= expectRange)
            [Number 4294967296, Number (-4294967297), Number (-2147483649)]
    it "rejects an in-range version outside [1,3] with the domain error" $
      mapM_ (\v -> do
               resp <- handleCreatePsbt noServer
                         (toJSON [toJSON ([] :: [Value]), object [], Number 1, Bool True, Number v])
               errorOf resp >>= (`shouldBe`
                 (rpcInvalidParameter, "Invalid parameter, version out of range(1~3)")))
            [0, 4, 2147483648]
