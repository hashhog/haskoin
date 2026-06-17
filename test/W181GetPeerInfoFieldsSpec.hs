{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W181 getpeerinfo wire-field parity (Bitcoin Core v31.99).
--
-- Reference: bitcoin-core/src/rpc/net.cpp (getpeerinfo).
--
-- Core v31.99 emits, in order:
--     ... relaytxes -> last_inv_sequence -> inv_to_send -> lastsend ...
--     ... bip152_hb_from -> presynced_headers ...    (NO startingheight)
--
--   * net.cpp:242  obj.pushKV("relaytxes", ...)
--   * net.cpp:243  obj.pushKV("last_inv_sequence", ...)   (NUM)
--   * net.cpp:244  obj.pushKV("inv_to_send", ...)         (NUM)
--   * net.cpp:245  obj.pushKV("lastsend", ...)
--   * net.cpp:269  obj.pushKV("bip152_hb_from", ...)
--   * net.cpp:270  obj.pushKV("presynced_headers", ...)
--
-- Bitcoin Core v31.99 no longer surfaces the legacy m_starting_height via
-- getpeerinfo: there is NO `startingheight` pushKV anywhere in net.cpp.
--
-- These tests exercise the production encoder 'Haskoin.Rpc.peerInfoToEncoding'
-- (the exact function 'handleGetPeerInfo' uses), so they pin the real wire
-- shape, not a re-implementation.  Field ORDER is asserted by inspecting the
-- serialized JSON byte stream, since aeson's 'pairs'/'Encoding' preserves
-- declaration order (mirroring Core's pushKV sequence) but a decoded 'Value'
-- Object would not.
module W181GetPeerInfoFieldsSpec (spec) where

import Test.Hspec

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text as T

import Data.Aeson (Value(..), decode)
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Aeson.Key as AK
import Data.Aeson.Encoding (encodingToLazyByteString)

import Network.Socket (SockAddr(..), tupleToHostAddress)

import Haskoin.Network (PeerInfo(..), PeerState(..))
import Haskoin.Rpc (peerInfoToEncoding)

--------------------------------------------------------------------------------
-- Fixture: a fully-populated PeerInfo (every field set; address is the only
-- value that matters structurally for the encoder, but we fill all fields so
-- the record is total and warning-clean).
--------------------------------------------------------------------------------

testAddr :: SockAddr
testAddr = SockAddrInet 8333 (tupleToHostAddress (203, 0, 113, 7))

testInfo :: PeerInfo
testInfo = PeerInfo
  { piAddress             = testAddr
  , piVersion             = Nothing
  , piState               = PeerConnected
  , piServices            = 9            -- NETWORK | WITNESS
  , piStartHeight         = 123456       -- MUST NOT surface as "startingheight"
  , piRelay               = True
  , piLastSeen            = 1700000000
  , piLastPing            = Nothing
  , piPingLatency         = Just 0.05
  , piBanScore            = 0
  , piBytesSent           = 4242
  , piBytesRecv           = 8484
  , piMsgsSent            = 10
  , piMsgsRecv            = 20
  , piConnectedAt         = 1699999000
  , piTimeOffset          = 0
  , piInbound             = False
  , piWantsAddrV2         = False
  , piWantsHeaders        = False
  , piFeeFilterReceived   = 0
  , piFeeFilterSent       = 0
  , piNextFeeFilterSend   = 0
  , piBlockOnly           = False
  , piUnconnectingHeaders = 0
  , piNoBan               = False
  , piIsManual            = False
  , piIsLocal             = False
  , piWtxidRelay          = False
  , piGetaddrRecvd        = False
  , piAddrTokenBucket     = 1.0
  , piAddrTokenTimestamp  = 0
  }

-- | The raw serialized JSON bytes (as Text) for one peer element, exactly as
-- handleGetPeerInfo emits per peer.
peerJsonText :: T.Text
peerJsonText =
  let lbs = encodingToLazyByteString (peerInfoToEncoding BS.empty 0 (testAddr, testInfo))
  in T.pack (map (toEnum . fromIntegral) (BSL.unpack lbs))

-- | Parse the peer element into an aeson Object for membership checks.
peerObject :: KM.KeyMap Value
peerObject =
  case decode (encodingToLazyByteString (peerInfoToEncoding BS.empty 0 (testAddr, testInfo))) of
    Just (Object o) -> o
    _               -> error "peerInfoToEncoding did not produce a JSON object"

-- | Byte position of a JSON key marker (e.g. @\"lastsend\":@) within the
-- serialized output, or a large sentinel if absent.
keyPos :: T.Text -> Int
keyPos k =
  let marker = T.concat ["\"", k, "\":"]
  in case T.breakOn marker peerJsonText of
       (pre, rest) | not (T.null rest) -> T.length pre
       _                               -> maxBound

hasKey :: T.Text -> Bool
hasKey k = KM.member (AK.fromText k) peerObject

--------------------------------------------------------------------------------

spec :: Spec
spec = describe "W181 getpeerinfo Core v31.99 wire fields" $ do

  describe "last_inv_sequence + inv_to_send present (net.cpp:243-244)" $ do
    it "emits last_inv_sequence as a number" $ do
      hasKey "last_inv_sequence" `shouldBe` True
      case KM.lookup (AK.fromText "last_inv_sequence") peerObject of
        Just (Number _) -> pure ()
        other -> expectationFailure $ "last_inv_sequence not a number: " ++ show other

    it "emits inv_to_send as a number" $ do
      hasKey "inv_to_send" `shouldBe` True
      case KM.lookup (AK.fromText "inv_to_send") peerObject of
        Just (Number _) -> pure ()
        other -> expectationFailure $ "inv_to_send not a number: " ++ show other

  describe "startingheight removed (Core v31.99 net.cpp has no such pushKV)" $
    it "does NOT emit startingheight" $
      -- piStartHeight is 123456 in the fixture; if the field were still
      -- emitted this would be True. It must be absent.
      hasKey "startingheight" `shouldBe` False

  describe "wire field ordering (aeson pairs preserves Core pushKV order)" $ do
    it "relaytxes < last_inv_sequence < inv_to_send < lastsend (net.cpp:242-245)" $ do
      let pRelay = keyPos "relaytxes"
          pLis   = keyPos "last_inv_sequence"
          pIts   = keyPos "inv_to_send"
          pLast  = keyPos "lastsend"
      pRelay `shouldSatisfy` (< pLis)
      pLis   `shouldSatisfy` (< pIts)
      pIts   `shouldSatisfy` (< pLast)

    it "bip152_hb_from immediately precedes presynced_headers (net.cpp:269-270)" $ do
      let pHbFrom = keyPos "bip152_hb_from"
          pPresync = keyPos "presynced_headers"
      pHbFrom `shouldSatisfy` (< pPresync)
      -- And nothing named startingheight sits between them.
      keyPos "startingheight" `shouldBe` (maxBound :: Int)
