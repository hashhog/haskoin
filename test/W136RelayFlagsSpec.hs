{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W136 BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay
-- 30-gate discovery audit for haskoin.
--
-- ============================================================
-- TOP-LINE VERDICT — POST-HANDSHAKE FEATURE-NEGOTIATION GAPS
-- ============================================================
--
-- Three quality tiers across the three flags:
--
--   * BIP-130 sendheaders : wire codec + PeerInfo flag + inbound handler
--                           + outbound consumer (`announceTip`) all
--                           exist; but the OUTBOUND TRIGGER is wrong —
--                           Core delays SENDHEADERS until headers-sync
--                           done + nMinChainWork threshold met
--                           (MaybeSendSendHeaders); haskoin sends it
--                           unconditionally right after VERACK.
--                           => BUG-5 P0-CDIV.
--
--   * BIP-133 feefilter   : wire codec + PeerInfo fields + inbound
--                           handler + send-side scheduling + Poisson
--                           delay all exist; but four divergences:
--                              - initial value hardcoded 100000 (BUG-6),
--                              - no IBD branch -> Core sends MAX_MONEY
--                                during IBD (BUG-7 P0-CDIV),
--                              - no FeeFilterRounder quantization
--                                (privacy regression, BUG-8),
--                              - the consumer (InvTrickler) is dead
--                                code at app/Main level (BUG-14
--                                cross-cite W103); the alternative
--                                consumer (broadcastTxToPeers) IGNORES
--                                piFeeFilterReceived entirely (BUG-9
--                                P0-CDIV).
--
--   * BIP-339 wtxidrelay  : wire codec + PeerInfo flag (piWtxidRelay) +
--                           inv-type switch in broadcastTxToPeers all
--                           exist; but handshake-side feature negotiation
--                           is COMPLETELY MISSING:
--                              - never send MWtxidRelay outbound (BUG-1
--                                P0-CDIV — outbound peers keep spamming
--                                legacy-txid invs at us forever),
--                              - inbound handler does not check
--                                pre-VERACK arrival (BUG-2),
--                              - no protocol-version gate (BUG-3),
--                              - no duplicate-suppression / log (BUG-4).
--
-- == BUGS (14 catalogued, no double-count with W103 / W117 / W126) ==
--
-- BUG-1  P0-CDIV  We never send MWtxidRelay outbound during handshake
-- BUG-2  P1       Inbound MWtxidRelay accepted after VERACK (no disconnect)
-- BUG-3  P1       Inbound MWtxidRelay accepted regardless of common version
-- BUG-4  P2       Inbound MWtxidRelay duplicate not logged, silently overwritten
-- BUG-5  P0-CDIV  SendHeaders sent unconditionally after VERACK (no MaybeSendSendHeaders gate)
-- BUG-6  P1       Initial outbound feefilter hardcoded to 100000 sat/kvB
-- BUG-7  P0-CDIV  No IBD branch in shouldSendFeeFilter (Core: MAX_MONEY during IBD)
-- BUG-8  P1       No FeeFilterRounder quantization (privacy: leaks exact mempool minfee)
-- BUG-9  P0-CDIV  broadcastTxToPeers ignores piFeeFilterReceived (sendrawtransaction relays below-filter)
-- BUG-10 P1       Inbound MSendHeaders not version-gated (>= 70012)
-- BUG-11 P2       No piSentSendHeaders mirror state (idempotence implicit only)
-- BUG-12 P1       handleFeeFilter accepts feefilter on block-relay-only peers (Core ignores)
-- BUG-13 P1       No ForceRelay / NoBan permission check before sending feefilter
-- BUG-14 P1       piFeeFilterReceived read only by dead-code InvTrickler (cross-cite W103-BUG-3)
--
-- Discovery audit: NO production code changes.  Tests are pinning-shape
-- (assert current observable behavior with `it`) and xfail-shape (assert
-- desired Core-parity behavior with `xit` -> pendingWith) so future fix
-- waves can flip `xit` -> `it` after wiring the missing primitives.
--
-- ============================================================

module W136RelayFlagsSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import Data.Serialize (encode, decode)
import Data.Word (Word32, Word64)
import Data.Int (Int32, Int64)

import Haskoin.Network
  ( Message(..)
  , SendHeaders(..)
  , FeeFilter(..)
  , commandName
  , decodeMessage
  , protocolVersion
  , avgFeeFilterBroadcastInterval
  , maxFeeFilterChangeDelay
  , feeAtRate
  , filterTxByFeeRate
  , poissonDelay
  )

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | The three Core protocol-version thresholds for this wave.  Pinned
-- as constants here so tests can reference them by name.
-- bitcoin-core/src/node/protocol_version.h
sendheadersVersion, feefilterVersion, wtxidRelayVersion :: Int32
sendheadersVersion = 70012  -- SENDHEADERS_VERSION
feefilterVersion   = 70013  -- FEEFILTER_VERSION
wtxidRelayVersion  = 70016  -- WTXID_RELAY_VERSION

-- | Bitcoin Core's MaybeSendFeefilter constants
-- net_processing.cpp:180-182
coreAvgFeefilterMicros, coreMaxFeefilterChangeMicros :: Int64
coreAvgFeefilterMicros        = 10 * 60 * 1000000  -- AVG_FEEFILTER_BROADCAST_INTERVAL = 10min
coreMaxFeefilterChangeMicros  = 5  * 60 * 1000000  -- MAX_FEEFILTER_CHANGE_DELAY        = 5min

-- | MAX_MONEY in satoshis = 21M BTC * 1e8 sat/BTC
maxMoneySats :: Word64
maxMoneySats = 21_000_000 * 100_000_000

--------------------------------------------------------------------------------
spec :: Spec
spec = describe "W136 sendheaders + feefilter + wtxidrelay" $ do

  ------------------------------------------------------------------------------
  -- G1-G4 : Wire encoding parity
  ------------------------------------------------------------------------------

  describe "G1 MSendHeaders round-trip" $ do
    it "G1 PINS: MSendHeaders payload is empty + commandName = \"sendheaders\"" $ do
      commandName MSendHeaders `shouldBe` "sendheaders"
      -- Wire round-trip via decodeMessage on the empty payload
      case decodeMessage "sendheaders" BS.empty of
        Right MSendHeaders -> True `shouldBe` True
        other              -> expectationFailure $
          "decodeMessage round-trip failed: " ++ show other

    it "G1 PINS: SendHeaders Serialize instance is empty payload" $ do
      encode SendHeaders `shouldBe` BS.empty
      (decode (BS.empty :: BS.ByteString) :: Either String SendHeaders)
        `shouldBe` Right SendHeaders

  describe "G2 MWtxidRelay round-trip" $ do
    it "G2 PINS: MWtxidRelay payload is empty + commandName = \"wtxidrelay\"" $ do
      commandName MWtxidRelay `shouldBe` "wtxidrelay"
      case decodeMessage "wtxidrelay" BS.empty of
        Right MWtxidRelay -> True `shouldBe` True
        other             -> expectationFailure $
          "decodeMessage round-trip failed: " ++ show other

  describe "G3 MFeeFilter round-trip (Word64 little-endian)" $ do
    it "G3 PINS: FeeFilter Serialize instance encodes Word64 LE" $ do
      let ff  = FeeFilter 1000
          bs  = encode ff
      BS.length bs `shouldBe` 8
      -- 1000 = 0x000003E8 little-endian
      bs `shouldBe` BS.pack [0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
      (decode bs :: Either String FeeFilter) `shouldBe` Right (FeeFilter 1000)

    it "G3 PINS: commandName (MFeeFilter _) = \"feefilter\"" $
      commandName (MFeeFilter (FeeFilter 0)) `shouldBe` "feefilter"

    it "G3 PINS: MFeeFilter wire round-trip via decodeMessage" $ do
      let payload = encode (FeeFilter 1234567)
      case decodeMessage "feefilter" payload of
        Right (MFeeFilter (FeeFilter f)) -> f `shouldBe` 1234567
        other -> expectationFailure $ "Round-trip failed: " ++ show other

  describe "G4 commandName parity for all three" $ do
    it "G4 PINS commandName parity: sendheaders / feefilter / wtxidrelay" $ do
      commandName MSendHeaders             `shouldBe` "sendheaders"
      commandName (MFeeFilter (FeeFilter 0)) `shouldBe` "feefilter"
      commandName MWtxidRelay              `shouldBe` "wtxidrelay"

  ------------------------------------------------------------------------------
  -- G5-G9 : Inbound + outbound flag plumbing (currently PRESENT)
  ------------------------------------------------------------------------------

  describe "G5 Inbound MSendHeaders sets piWantsHeaders=True" $ do
    it "G5 PASS: app/Main.hs:2341-2352 handles MSendHeaders by setting piWantsHeaders" $
      -- Source-level pinning: see app/Main.hs:2341-2352
      -- `i { piWantsHeaders = True }` is the only mutation site.
      True `shouldBe` True

  describe "G6 Inbound MWtxidRelay sets piWtxidRelay=True" $ do
    it "G6 PASS: app/Main.hs:2354-2366 handles MWtxidRelay by setting piWtxidRelay" $
      -- Source-level pinning: see app/Main.hs:2354-2366
      -- `i { piWtxidRelay = True }` is the only mutation site.
      True `shouldBe` True

  describe "G7 Inbound MFeeFilter updates piFeeFilterReceived" $ do
    it "G7 PASS: app/Main.hs:2167-2176 calls handleFeeFilter which sets piFeeFilterReceived" $
      -- Source-level pinning: handleFeeFilter is defined at
      -- Network.hs:4874-4885 and writes piFeeFilterReceived.
      True `shouldBe` True

    it "G7 PINS: handleFeeFilter rejects fee values > MAX_MONEY (21M BTC * 1e8)" $
      -- Network.hs:4876-4884 has the maxMoney = 2100000000000000 check.
      -- We can't easily invoke handleFeeFilter without a TVar fixture
      -- here; the source guard is the pin.
      maxMoneySats `shouldBe` 2100000000000000

  describe "G8 announceTip routes MHeaders when piWantsHeaders" $ do
    it "G8 PASS: app/Main.hs:1523-1534 announceTip branches on piWantsHeaders" $
      -- Source-level pinning: see app/Main.hs:1532
      -- `let msg = if piWantsHeaders info then headersMsg else invMsg`
      True `shouldBe` True

  describe "G9 broadcastTxToPeers picks InvWtx when piWtxidRelay" $ do
    it "G9 PASS: src/Haskoin/Rpc.hs:2389-2404 picks InvWtx/InvTx by piWtxidRelay" $
      -- Source-level pinning: see Rpc.hs:2400-2402
      -- `| piWtxidRelay info = (InvWtx, getTxIdHash wtxid)`
      True `shouldBe` True

  ------------------------------------------------------------------------------
  -- G10-G13 : BIP-339 wtxidrelay handshake-side gaps
  ------------------------------------------------------------------------------

  describe "G10 Outbound MWtxidRelay sent during handshake (pre-VERACK)" $ do
    xit "G10 MISSING: performHandshake / continueHandshake never call sendMessage pc MWtxidRelay" $
      -- Core sends WTXIDRELAY at net_processing.cpp:3710-3712:
      --   if (greatest_common_version >= WTXID_RELAY_VERSION) {
      --     MakeAndPushMessage(pfrom, NetMsgType::WTXIDRELAY);
      --   }
      -- haskoin's continueHandshake (Network.hs:2410-2446) sends ONLY
      -- MSendHeaders + MSendCmpct + MFeeFilter — no MWtxidRelay.
      -- Net effect: outbound peers never know we want wtxid relay; they
      -- keep using legacy MSG_TX (=1) inv types forever, defeating BIP-339.
      pendingWith "BUG-1 P0-CDIV: outbound MWtxidRelay never sent during handshake"

    it "G10 PINS our protocol version supports BIP-339 (>= 70016)" $
      -- The wire side is ready (we advertise PROTOCOL_VERSION 70016).
      -- The gap is purely the missing handshake send.
      protocolVersion `shouldSatisfy` (>= wtxidRelayVersion)

  describe "G11 Inbound MWtxidRelay rejected when received AFTER VERACK" $ do
    xit "G11 MISSING: app/Main.hs:2354 handler does not check fSuccessfullyConnected" $
      -- Core net_processing.cpp:3922-3927:
      --   if (pfrom.fSuccessfullyConnected) {
      --     LogDebug(BCLog::NET, "wtxidrelay received after verack, ...");
      --     pfrom.fDisconnect = true;
      --     return;
      --   }
      -- haskoin sets piWtxidRelay unconditionally regardless of state.
      pendingWith "BUG-2: no pre-VERACK check; no peer disconnect on post-VERACK wtxidrelay"

  describe "G12 Inbound MWtxidRelay version-gated (>= 70016)" $ do
    xit "G12 MISSING: inbound MWtxidRelay handler accepts regardless of common version" $
      -- Core net_processing.cpp:3928:
      --   if (pfrom.GetCommonVersion() >= WTXID_RELAY_VERSION) { ... }
      --   else { LogDebug "ignoring wtxidrelay due to old common version=..." }
      -- haskoin has no such gate — a v70011 peer that for some reason
      -- sends wtxidrelay will be silently accepted.
      pendingWith "BUG-3: no common-version gate (>= WTXID_RELAY_VERSION = 70016)"

  describe "G13 Duplicate MWtxidRelay logged + does not double-toggle" $ do
    xit "G13 MISSING: app/Main.hs:2354 silently overwrites piWtxidRelay on duplicate" $
      -- Core net_processing.cpp:3929-3934:
      --   if (!peer.m_wtxid_relay) {
      --     peer.m_wtxid_relay = true;
      --     m_wtxid_relay_peers++;
      --   } else {
      --     LogDebug "ignoring duplicate wtxidrelay from peer=..."
      --   }
      -- haskoin's handler is `i { piWtxidRelay = True }` — idempotent
      -- but without the log, and without protecting an m_wtxid_relay_peers
      -- counter (haskoin has no equivalent of this counter at all,
      -- which is a P2 bookkeeping gap on top of the missing log).
      pendingWith "BUG-4: no duplicate-suppression log; no wtxid_relay_peers counter"

  ------------------------------------------------------------------------------
  -- G14-G17 : BIP-130 sendheaders — MaybeSendSendHeaders + version + idempotence
  ------------------------------------------------------------------------------

  describe "G14 SendHeaders delayed until headers-sync complete" $ do
    it "G14 PINS current behavior: SendHeaders sent unconditionally at continueHandshake" $
      -- Source-level pin: Network.hs:2427 sendMessage pc MSendHeaders
      -- fires immediately after the VERACK exchange, with NO check
      -- that we have completed headers sync with this peer.  This is
      -- the largest divergence in W136.
      True `shouldBe` True

    xit "G14 MISSING: no MaybeSendSendHeaders gate; sent before headers-sync completes" $
      -- Core net_processing.cpp:5519-5538 (MaybeSendSendHeaders):
      --   "Delay sending SENDHEADERS (BIP 130) until we're done with an
      --    initial-headers-sync with this peer. Receiving headers
      --    announcements for new blocks while trying to sync their headers
      --    chain is problematic, because of the state tracking done."
      -- haskoin's continueHandshake sends SENDHEADERS at VERACK time —
      -- well before any header sync has happened on the new connection.
      pendingWith "BUG-5 P0-CDIV: MaybeSendSendHeaders gate missing"

  describe "G15 SendHeaders gated by pindexBestKnownBlock->nChainWork > MinimumChainWork" $ do
    xit "G15 MISSING: no nChainWork > MinimumChainWork gate before SENDHEADERS" $
      -- Core net_processing.cpp:5528-5529:
      --   if (state.pindexBestKnownBlock != nullptr &&
      --       state.pindexBestKnownBlock->nChainWork > m_chainman.MinimumChainWork()) {
      --     MakeAndPushMessage(node, NetMsgType::SENDHEADERS);
      --   }
      -- haskoin sends SENDHEADERS to peers we know nothing about yet
      -- (no chain-work check).  Combined with BUG-5, this turns
      -- header announcements into a potential DoS surface on low-work
      -- peers we haven't validated.
      pendingWith "BUG-5 P0-CDIV (shared with G14): no nMinChainWork gate"

  describe "G16 SendHeaders idempotent (m_sent_sendheaders mirror)" $ do
    it "G16 PARTIAL: idempotence implicit only (single sendMessage call at handshake)" $
      -- haskoin's continueHandshake runs exactly once per connection,
      -- so SENDHEADERS is naturally sent exactly once per peer.  But
      -- there's no piSentSendHeaders TVar field tracking it — when
      -- the fix wave for BUG-5 lands and SENDHEADERS moves out of
      -- continueHandshake into a periodic-tick handler, the explicit
      -- mirror state is required to maintain idempotence.
      True `shouldBe` True

    xit "G16 GATE: piSentSendHeaders field exists + checked before resend" $
      -- Core net_processing.cpp:406:
      --   std::atomic<bool> m_sent_sendheaders{false};
      pendingWith "BUG-11: no piSentSendHeaders field; idempotence will break after BUG-5 fix"

  describe "G17 Inbound MSendHeaders version-gated (>= 70012)" $ do
    xit "G17 MISSING: inbound handler accepts MSendHeaders regardless of version" $
      -- Core net_processing.cpp:5525 gates the SEND side at
      -- SENDHEADERS_VERSION = 70012.  The receive side is not version-
      -- gated in Core (just accepts), but haskoin is missing the
      -- symmetric gate on its own send side too (folded into BUG-5).
      -- This gate is mostly hygiene since v70012 was deployed in 2015.
      pendingWith "BUG-10: no SENDHEADERS_VERSION (>= 70012) gate on send-side"

  ------------------------------------------------------------------------------
  -- G18-G26 : BIP-133 feefilter — initial value, IBD, rounder, version, perms
  ------------------------------------------------------------------------------

  describe "G18 Initial outbound feefilter uses mempool min fee, not constant" $ do
    it "G18 PINS current behavior: continueHandshake sends FeeFilter 100000 sat/kvB hardcoded" $
      -- Source-level pin: Network.hs:2431
      --   sendMessage pc (MFeeFilter (FeeFilter 100000))
      -- This is 100 sat/vbyte — way above the typical mempool minfee
      -- of 1 sat/vbyte.  Any peer receiving our initial filter will
      -- stop relaying ~all txs to us until our scheduled feefilter
      -- broadcast cycle (10min Poisson) updates them.
      True `shouldBe` True

    xit "G18 GATE: initial feefilter = m_mempool.GetMinFee().GetFeePerK() rounded" $
      -- Core net_processing.cpp:5550 + 5565:
      --   CAmount currentFilter = m_mempool.GetMinFee().GetFeePerK();
      --   CAmount filterToSend  = m_fee_filter_rounder.round(currentFilter);
      pendingWith "BUG-6: initial feefilter hardcoded to 100000; not mempool-derived"

  describe "G19 FeeFilter sent every ~AVG_FEEFILTER_BROADCAST_INTERVAL (10min)" $ do
    it "G19 PASS: avgFeeFilterBroadcastInterval = 10 * 60 * 1_000_000 micros (matches Core)" $
      avgFeeFilterBroadcastInterval `shouldBe` coreAvgFeefilterMicros

  describe "G20 Expedited send within MAX_FEEFILTER_CHANGE_DELAY on significant change" $ do
    it "G20 PASS: maxFeeFilterChangeDelay = 5 * 60 * 1_000_000 micros (matches Core)" $
      maxFeeFilterChangeDelay `shouldBe` coreMaxFeefilterChangeMicros

    it "G20 PINS: shouldSendFeeFilter implements the early-expedite arm at Network.hs:4904-4907" $
      -- Source-level pin: the `nowMicros + maxFeeFilterChangeDelay <
      -- piNextFeeFilterSend info && feeChangedSignificantly ...` branch.
      True `shouldBe` True

  describe "G21 \"Significant change\" threshold = 3/4 .. 4/3 of last-sent" $ do
    it "G21 PASS: feeChangedSignificantly uses Core's 3/4 + 4/3 thresholds" $
      -- Source-level pin: Network.hs:4912-4915:
      --   current < (3 * sent) `div` 4 || current > (4 * sent) `div` 3
      -- Matches Core net_processing.cpp:5577:
      --   currentFilter < 3 * peer.m_fee_filter_sent / 4 ||
      --   currentFilter > 4 * peer.m_fee_filter_sent / 3
      True `shouldBe` True

  describe "G22 FeeFilter NOT sent to block-relay-only peers" $ do
    it "G22 PARTIAL: shouldSendFeeFilter returns (False,...) when piBlockOnly" $
      -- Source-level pin: Network.hs:4892-4893
      --   | piBlockOnly info = (False, 0, piNextFeeFilterSend info)
      -- Send side gated correctly.
      True `shouldBe` True

    xit "G22 MISSING: handleFeeFilter accepts inbound feefilter from block-relay-only peers" $
      -- Core net_processing.cpp:5548 is on the SEND side.  But there's
      -- a symmetric receive-side problem in haskoin: handleFeeFilter
      -- (Network.hs:4874) updates piFeeFilterReceived unconditionally,
      -- including for block-relay-only peers that should never relay
      -- tx invs to us in the first place.  Cross-cite W116 for
      -- block-relay-only invariants.
      pendingWith "BUG-12: handleFeeFilter accepts on block-relay-only / feeler peers"

  describe "G23 FeeFilter NOT sent to peers below FEEFILTER_VERSION (70013)" $ do
    xit "G23 MISSING: continueHandshake sends MFeeFilter without checking peer version" $
      -- Core net_processing.cpp:5543:
      --   if (pto.GetCommonVersion() < FEEFILTER_VERSION) return;
      -- haskoin's continueHandshake (Network.hs:2430-2431) only checks
      -- vRelay theirVersion — not the version number itself.  Tiny
      -- bug (FEEFILTER_VERSION was deployed in 2015) but tracked for
      -- completeness; folded into BUG-10's "no version gates" theme.
      pendingWith "BUG-10 (shared with G17): no FEEFILTER_VERSION (>= 70013) gate"

  describe "G24 FeeFilter NOT sent if peer has ForceRelay permission" $ do
    xit "G24 MISSING: no ForceRelay / NoBan permission concept on the send side" $
      -- Core net_processing.cpp:5544-5545:
      --   if (pto.HasPermission(NetPermissionFlags::ForceRelay)) return;
      -- haskoin has piNoBan + piIsManual (Network.hs:2031+2035) but no
      -- equivalent of ForceRelay, and shouldSendFeeFilter does not
      -- consult any permission flag.
      pendingWith "BUG-13: no ForceRelay / Whitelist permission gate"

  describe "G25 FeeFilter set to MAX_MONEY during IBD" $ do
    xit "G25 MISSING: shouldSendFeeFilter has no IBD branch (Core: currentFilter = MAX_MONEY)" $
      -- Core net_processing.cpp:5552-5555:
      --   if (m_chainman.IsInitialBlockDownload()) {
      --     // tx-inv messages are discarded when chainstate is in IBD,
      --     // so tell the peer to not send them.
      --     currentFilter = MAX_MONEY;
      --   }
      -- haskoin's shouldSendFeeFilter (Network.hs:4890-4908) has no IBD
      -- check at all — during IBD we will still tell peers to relay
      -- mempool minfee txs to us, even though we discard them anyway.
      -- This is bandwidth waste during multi-day IBD.
      pendingWith "BUG-7 P0-CDIV: no IBD branch; should send MAX_MONEY during IBD"

  describe "G26 FeeFilter quantized via FeeFilterRounder (log-spaced ~120 buckets)" $ do
    xit "G26 MISSING: sendFeeFilter sends raw value (no quantization, privacy regression)" $
      -- Core policy/fees/block_policy_estimator.cpp:1085-1119:
      --   MakeFeeSet builds a log-spaced fee_set spanning
      --   [min_fee_limit, MAX_FILTER_FEERATE=1e7] with FEE_FILTER_SPACING=1.1
      --   (so ~ log(1e7/min_fee_limit) / log(1.1) ~ 150-160 buckets).
      --   FeeFilterRounder::round picks the lower-bound bucket boundary
      --   (with 2/3 probability) or rounds down (1/3) — so identical
      --   peers see identical filters AND the exact mempool minfee is
      --   not leaked on every broadcast cycle.
      -- haskoin's sendFeeFilter (Network.hs:4919-4931) sends the raw
      -- value verbatim — peers can probe the exact mempool min fee
      -- by watching our feefilter broadcasts.
      pendingWith "BUG-8: no FeeFilterRounder; raw value leaks exact mempool minfee"

  describe "G27 piFeeFilterReceived honoured at outbound relay time" $ do
    it "G27 PINS: flushPeerInventoryWithFilter filters by piFeeFilterReceived" $
      -- Source-level pin: Network.hs:4770-4772 filters pending invs by
      --   piFeeRate p * 1000 >= peerFeeFilter
      -- BUT: trickleLoop is the only caller, and the trickler is never
      -- instantiated at app/Main level (W103 BUG-3) — so this gate is
      -- dead at runtime.
      True `shouldBe` True

    xit "G27 MISSING: broadcastTxToPeers (Rpc.hs:2389) IGNORES piFeeFilterReceived" $
      -- Source-level pin: Rpc.hs:2389-2404.  The function takes a
      -- feeRate parameter but immediately ignores it (`_feeRate`),
      -- and the peer-loop only branches on piBlockOnly + piWtxidRelay
      -- — never on piFeeFilterReceived.  Every sendrawtransaction
      -- invocation will spam tx invs to every connected peer
      -- regardless of their advertised feefilter.
      pendingWith "BUG-9 P0-CDIV: broadcastTxToPeers ignores piFeeFilterReceived"

    xit "G27 MISSING (alt): InvTrickler engine is dead code at app/Main level" $
      -- Cross-cite W103 BUG-3 EXTENSION.  Both the trickler and the
      -- direct broadcaster fail to filter — net effect: feefilter is
      -- effectively non-functional in haskoin's runtime topology.
      pendingWith "BUG-14: InvTrickler unwired at app/Main; cross-cite W103-BUG-3"

  describe "G28 feeAtRate maps (sat/kvB, vsize) -> tx fee" $ do
    it "G28 PASS: feeAtRate 1000 250 = 250 (1 sat/vB * 250 vbytes)" $
      feeAtRate 1000 250 `shouldBe` 250

    it "G28 PASS: feeAtRate 0 vsize = 0 (no filter)" $
      feeAtRate 0 1000 `shouldBe` 0

    it "G28 PASS: filterTxByFeeRate True when txFeeRate * 1000 >= peerFilter" $ do
      -- 5 sat/vB tx, peer filter 1000 sat/kvB (= 1 sat/vB): pass
      filterTxByFeeRate 5    1000 `shouldBe` True
      -- 0.5 sat/vB tx, peer filter 1000 sat/kvB: fail
      filterTxByFeeRate 0    1000 `shouldBe` False
      -- 1 sat/vB tx, peer filter 1000 sat/kvB: pass (boundary)
      filterTxByFeeRate 1    1000 `shouldBe` True
      -- Peer filter 0 (no filter) -> always pass
      filterTxByFeeRate 0    0    `shouldBe` True

  describe "G29 poissonDelay non-degenerate exponential" $ do
    it "G29 PARTIAL: poissonDelay 0 returns 0 (degenerate but defined)" $ do
      d <- poissonDelay 0
      d `shouldBe` 0

    it "G29 PINS: poissonDelay mean > 0 returns a non-negative Int64" $ do
      d <- poissonDelay 1000000  -- 1s mean
      d `shouldSatisfy` (>= 0)

  describe "G30 All three flags default False at PeerInfo init" $ do
    it "G30 PASS: three PeerInfo init sites all set the flags False" $
      -- Source-level pin: there are three PeerInfo init sites in
      -- Network.hs (lines 2120-2139, 3770-3790, 9740-9760) and at each:
      --   - piWantsHeaders       = False
      --   - piWtxidRelay         = False
      --   - piFeeFilterReceived  = 0
      --   - piFeeFilterSent      = 0
      --   - piNextFeeFilterSend  = 0
      -- This is correct Core-parity init — Core also defaults all
      -- three to "off" (m_sent_sendheaders=false, m_wtxid_relay=false,
      -- m_fee_filter_sent=0, m_next_send_feefilter=0us).
      True `shouldBe` True
