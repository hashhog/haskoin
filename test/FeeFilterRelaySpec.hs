{-# LANGUAGE NumericUnderscores #-}
-- | BIP133 feefilter: haskoin must not tell its peers to withhold every
-- ordinary transaction.
--
-- Pre-fix the only feefilter haskoin ever sent was a hardcoded
-- @FeeFilter 100000@ (sat/kvB = 100 sat/vB) right after verack
-- ('postVerackFeatureMessages'); the periodic MaybeSendFeefilter port
-- ('sendFeeFilter' / 'shouldSendFeeFilter') had no caller, so the value
-- was never corrected.  Core peers honour feefilter when announcing
-- (net_processing.cpp SendMessages: txinfo.fee < filterrate -> skip), so
-- they announced only txs paying >= 100 sat/vB — the mainnet mempool sat
-- at 0 transactions with 7 peers.
--
-- Core PeerManagerImpl::MaybeSendFeefilter: currentFilter =
-- mempool.GetMinFee(), MAX_MONEY while in IBD, never below
-- min_relay_feerate (DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB), first sent
-- after verack then every Poisson(AVG_FEEFILTER_BROADCAST_INTERVAL).
module FeeFilterRelaySpec (spec, feeFilterTestPeer) where

import Test.Hspec
import qualified Data.ByteString as BS
import Data.Int (Int64)
import Network.Socket (SockAddr(..), tupleToHostAddress)

import Haskoin.Network
import Haskoin.Types (NetworkAddress(..), VarString(..))

coreMinRelayKvb :: Word
coreMinRelayKvb = 100   -- policy/policy.h DEFAULT_MIN_RELAY_TX_FEE

feeFilterTestPeer :: PeerInfo
feeFilterTestPeer = PeerInfo
  { piAddress             = SockAddrInet 18444 (tupleToHostAddress (127, 0, 0, 1))
  , piVersion             = Nothing
  , piState               = PeerConnected
  , piServices            = 0
  , piStartHeight         = 0
  , piRelay               = True
  , piLastSeen            = 0
  , piLastPing            = Nothing
  , piPingLatency         = Nothing
  , piBanScore            = 0
  , piBytesSent           = 0
  , piBytesRecv           = 0
  , piMsgsSent            = 0
  , piMsgsRecv            = 0
  , piConnectedAt         = 0
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
  , piWtxidRelay          = True
  , piProvidesCmpct       = False
  , piCmpctHBFrom         = False
  , piGetaddrRecvd        = False
  , piAddrTokenBucket     = 1.0
  , piAddrTokenTimestamp  = 0
  }

-- | Every feefilter value among the handshake messages.
handshakeFilters :: [Message] -> [Word]
handshakeFilters ms = [ fromIntegral (getMinFee f) | MFeeFilter f <- ms ]

now, poisson, expedite :: Int64
now = 1_000_000_000_000
poisson = 600_000_000
expedite = 1_000

spec :: Spec
spec = describe "BIP133 feefilter (Core MaybeSendFeefilter)" $ do
  it "the handshake never advertises a filter above Core's min relay fee" $ do
    -- Fails pre-fix: [100000] — 1000x DEFAULT_MIN_RELAY_TX_FEE.
    let fs = handshakeFilters (postVerackFeatureMessages 70016 True)
    filter (> coreMinRelayKvb) fs `shouldBe` []

  it "first send after verack is max(mempool min fee, min relay) when not in IBD" $
    feefilterStep False 0 100 now poisson expedite feeFilterTestPeer
      `shouldBe` (Just 100, now + poisson)

  it "follows the mempool minimum fee when it is above the floor" $
    feefilterStep False 2500 100 now poisson expedite feeFilterTestPeer
      `shouldBe` (Just 2500, now + poisson)

  it "advertises MAX_MONEY while in IBD (Core: tx invs are useless in IBD)" $
    feefilterStep True 0 100 now poisson expedite feeFilterTestPeer
      `shouldBe` (Just feeFilterMaxMoney, now + poisson)

  it "re-sends at once on leaving IBD even if the schedule is far away" $ do
    let p = feeFilterTestPeer { piFeeFilterSent = feeFilterMaxMoney
                 , piNextFeeFilterSend = now + 500_000_000 }
    feefilterStep False 0 100 now poisson expedite p
      `shouldBe` (Just 100, now + poisson)

  it "does not re-send an unchanged value, only reschedules" $ do
    let p = feeFilterTestPeer { piFeeFilterSent = 100 }
    feefilterStep False 0 100 now poisson expedite p
      `shouldBe` (Nothing, now + poisson)

  it "before the schedule: nothing sent; a >25% move expedites" $ do
    let p = feeFilterTestPeer { piFeeFilterSent = 100, piNextFeeFilterSend = now + 500_000_000 }
    feefilterStep False 100 100 now poisson expedite p
      `shouldBe` (Nothing, now + 500_000_000)
    feefilterStep False 1000 100 now poisson expedite p
      `shouldBe` (Nothing, now + expedite)

  it "never sends to block-relay-only peers or peers below FEEFILTER_VERSION" $ do
    fst (feefilterStep False 0 100 now poisson expedite feeFilterTestPeer { piBlockOnly = True })
      `shouldBe` Nothing
    fst (feefilterStep False 0 100 now poisson expedite
           feeFilterTestPeer { piVersion = Just (oldVersion 70012) })
      `shouldBe` Nothing
  where
    na = NetworkAddress 0 (BS.replicate 16 0) 0
    oldVersion v = Version v 0 0 na na 0 (VarString BS.empty) 0 True
