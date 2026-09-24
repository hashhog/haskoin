{-# LANGUAGE OverloadedStrings #-}

-- | Download-stall discriminator after the 2026-09-24 mainnet read.
--
-- Peers are fixed (getconnectioncount held at 10). Bodies are not:
-- validated moved 911866 -> 911868 in 30 min, kicker windows were
-- 3x branch=stall, 1x branch=receipt, 0x branch=progress, and 29
-- @requestFromPeer@ sends died with "resource vanished". Three
-- blocks 48–63 ahead of next-needed were logged
-- @reason=validation@ with no underlying error — that tag is the
-- classifier catch-all, and the raw string was only printed when
-- height == next-needed.
--
-- This spec does not change refill, inflight accounting, or peer
-- selection. It pins the logs the next read needs:
--
--   (1) every connect-reject carries @err=@, including heights that
--       are not next-needed
--   (2) every issued window names each peer, whether that peer was
--       still connected at send time, and whether the send returned
--   (3) the next-needed height names its peer and the fate of that
--       request (assigned / already-inflight / not-requested)
--   (4) a requestFromPeer failure names the message type and the
--       peer state, so "resource vanished" can be told apart from
--       an unknown-peer drop and from a non-getdata send
--
-- Control: cabal run haskoin-test --enable-tests -- -m stall-discriminator
--
-- A green here is not a rate fix. Do not deploy from this spec.
module W199StallDiscriminatorSpec (spec) where

import Data.List (isInfixOf, isPrefixOf)
import Test.Hspec

import Haskoin.Consensus
  ( UnconnectedReason (..)
  , classifyConnectReject
  , formatUnconnectedArrivalDetail
  )
import Haskoin.Network
  ( LinearFillBranch (..)
  , NextNeededFate (..)
  , PeerState (..)
  , formatNextNeededAssignment
  , formatRequestSendFailure
  , formatRequestUnknownPeer
  , formatWindowPeerSend
  , peerConnectedAtSend
  )

flat :: String -> String
flat = unwords . words

errField :: String -> String
errField s = go s
  where
    tag = " err="
    go [] = ""
    go xs
      | tag `isPrefixOf` xs = drop (length tag) xs
      | otherwise = go (tail xs)

mainHs :: IO String
mainHs = readFile "app/Main.hs"

netHs :: IO String
netHs = readFile "src/Haskoin/Network.hs"

-- | Source of a top-level binding, from its equation through the line
-- before the next named binding. Whitespace-sensitive tests squash
-- with 'flat'.
bindingBody :: String -> String -> String -> String
bindingBody src equation nextName =
  let dropped = dropWhile (not . (equation `isInfixOf`)) (lines src)
      body = takeWhile (not . (nextName `isInfixOf`)) dropped
   in unlines body

spec :: Spec
spec = describe "stall-discriminator" $ do
  describe "stall-discriminator: unconnected error string" $ do
    it "a validation reject ahead of next-needed carries the underlying error" $ do
      -- Live line was height=911915 next-needed=911867 reason=validation
      -- and nothing else. The tag alone cannot say mislabel vs real reject.
      let err = "Core full-block validation: bad-txns-inputs-missingorspent"
          reason = classifyConnectReject err
          line = formatUnconnectedArrivalDetail (Just 911915) 911867 reason 3 err
      reason `shouldBe` UnconnValidation
      line `shouldSatisfy` ("height=911915" `isInfixOf`)
      line `shouldSatisfy` ("next-needed=911867" `isInfixOf`)
      line `shouldSatisfy` ("reason=validation" `isInfixOf`)
      line `shouldSatisfy` ("count=3" `isInfixOf`)
      errField line `shouldBe` err

    it "err= is one field: newlines flattened, capped at 500, blank omitted" $ do
      let raw = "Core full-block validation: aa\nbb" ++ replicate 600 'c'
          line = formatUnconnectedArrivalDetail (Just 1) 2 UnconnValidation 1 raw
      '\n' `elem` line `shouldBe` False
      '\r' `elem` line `shouldBe` False
      length (errField line) `shouldBe` 500
      errField line `shouldSatisfy` ("aa bb" `isInfixOf`)
      let blank1 = formatUnconnectedArrivalDetail (Just 1) 1 UnconnTooFarAhead 1 ""
          blank2 = formatUnconnectedArrivalDetail (Just 1) 1 UnconnTooFarAhead 1 "\n\r"
      blank1 `shouldSatisfy` (not . ("err=" `isInfixOf`))
      blank2 `shouldSatisfy` (not . ("err=" `isInfixOf`))
      blank1 `shouldSatisfy` ("reason=too-far-ahead" `isInfixOf`)

    it "a reject the classifier does not name still keeps the raw string" $ do
      -- If 911915 was a mislabel, err= is the only way to see that.
      let weird = "connectBlockAt h: something-unexpected"
          line = formatUnconnectedArrivalDetail
                   (Just 911915) 911867 (classifyConnectReject weird) 1 weird
      classifyConnectReject weird `shouldBe` UnconnOther
      line `shouldSatisfy` ("reason=other" `isInfixOf`)
      errField line `shouldBe` weird

  describe "stall-discriminator: window peers and next-needed" $ do
    it "connected-at-send is listed AND PeerConnected, nothing else" $ do
      peerConnectedAtSend True PeerConnected `shouldBe` True
      -- Left the map while the TVar still says connected: stale snapshot.
      peerConnectedAtSend False PeerConnected `shouldBe` False
      peerConnectedAtSend True PeerDisconnecting `shouldBe` False
      peerConnectedAtSend True PeerDisconnected `shouldBe` False
      peerConnectedAtSend True PeerHandshaking `shouldBe` False
      peerConnectedAtSend False PeerDisconnecting `shouldBe` False

    it "a dead socket still listed is not the same line as a stale peer" $ do
      -- resource vanished while pmPeers still has the address.
      let dead =
            formatWindowPeerSend
              FillStall 911867 911994 2 "203.0.113.5:8333" 16
              True False True
              "Network.Socket.sendBuf: resource vanished"
          stale =
            formatWindowPeerSend
              FillStall 911867 911994 2 "203.0.113.5:8333" 16
              False False True
              "Network.Socket.sendBuf: resource vanished"
          okLine =
            formatWindowPeerSend
              FillReceipt 911868 911994 0 "203.0.113.9:8333" 16
              True True False ""
      dead `shouldSatisfy` ("branch=stall" `isInfixOf`)
      dead `shouldSatisfy` ("heights=911867-911994" `isInfixOf`)
      dead `shouldSatisfy` ("idx=2" `isInfixOf`)
      dead `shouldSatisfy` ("addr=203.0.113.5:8333" `isInfixOf`)
      dead `shouldSatisfy` ("hashes=16" `isInfixOf`)
      dead `shouldSatisfy` ("connected-at-send=yes" `isInfixOf`)
      dead `shouldSatisfy` ("send=fail" `isInfixOf`)
      dead `shouldSatisfy` ("next-needed=yes" `isInfixOf`)
      errField dead `shouldBe` "Network.Socket.sendBuf: resource vanished"
      stale `shouldSatisfy` ("connected-at-send=no" `isInfixOf`)
      stale `shouldSatisfy` ("send=fail" `isInfixOf`)
      okLine `shouldSatisfy` ("branch=receipt" `isInfixOf`)
      okLine `shouldSatisfy` ("connected-at-send=yes" `isInfixOf`)
      okLine `shouldSatisfy` ("send=ok" `isInfixOf`)
      okLine `shouldSatisfy` ("next-needed=no" `isInfixOf`)
      okLine `shouldSatisfy` (not . ("err=" `isInfixOf`))
      dead `shouldNotBe` stale

    it "next-needed fate names the peer and what happened to the request" $ do
      let assigned =
            formatNextNeededAssignment
              FillStall 911867
              (NextNeededAssigned 2 "203.0.113.5:8333" True False
                 "Network.Socket.sendBuf: resource vanished")
          inflight =
            formatNextNeededAssignment
              FillStall 911867
              (NextNeededAlreadyInflight 4 "203.0.113.8:8333")
          none =
            formatNextNeededAssignment FillProgress 911868 NextNeededNotRequested
      assigned `shouldSatisfy` ("branch=stall" `isInfixOf`)
      assigned `shouldSatisfy` ("height=911867" `isInfixOf`)
      assigned `shouldSatisfy` ("fate=assigned" `isInfixOf`)
      assigned `shouldSatisfy` ("peer=2" `isInfixOf`)
      assigned `shouldSatisfy` ("addr=203.0.113.5:8333" `isInfixOf`)
      assigned `shouldSatisfy` ("connected-at-send=yes" `isInfixOf`)
      assigned `shouldSatisfy` ("send=fail" `isInfixOf`)
      errField assigned `shouldBe` "Network.Socket.sendBuf: resource vanished"
      inflight `shouldSatisfy` ("fate=already-inflight" `isInfixOf`)
      inflight `shouldSatisfy` ("peer=4" `isInfixOf`)
      inflight `shouldSatisfy` ("addr=203.0.113.8:8333" `isInfixOf`)
      inflight `shouldSatisfy` (not . ("send=" `isInfixOf`))
      none `shouldSatisfy` ("branch=progress" `isInfixOf`)
      none `shouldSatisfy` ("height=911868" `isInfixOf`)
      none `shouldSatisfy` ("fate=not-requested" `isInfixOf`)
      none `shouldSatisfy` (not . ("peer=" `isInfixOf`))

  describe "stall-discriminator: requestFromPeer failure" $ do
    it "a vanished send names the message and the state; unknown peer stays a drop" $ do
      let vanished =
            formatRequestSendFailure
              "203.0.113.5:8333" "getdata" "PeerConnected"
              "Network.Socket.sendBuf: resource vanished"
          dropped = formatRequestUnknownPeer "203.0.113.5:8333" "getdata"
          other = formatRequestSendFailure "203.0.113.5:8333" "pong" "PeerConnected" "resource vanished"
      ("requestFromPeer: send to " `isPrefixOf` vanished) `shouldBe` True
      vanished `shouldSatisfy` ("msg=getdata" `isInfixOf`)
      vanished `shouldSatisfy` ("state=PeerConnected" `isInfixOf`)
      vanished `shouldSatisfy` ("FAILED:" `isInfixOf`)
      vanished `shouldSatisfy` ("resource vanished" `isInfixOf`)
      -- The old grep still hits. msg= is what makes the 29 lines classifiable.
      ("requestFromPeer: unknown peer " `isPrefixOf` dropped) `shouldBe` True
      dropped `shouldSatisfy` ("msg=getdata" `isInfixOf`)
      dropped `shouldSatisfy` ("message DROPPED" `isInfixOf`)
      other `shouldSatisfy` ("msg=pong" `isInfixOf`)
      other `shouldNotBe` vanished

  describe "stall-discriminator: wired into the live path" $ do
    it "connect-reject logs cbErr on every arrival, not only next-needed" $ do
      src <- mainHs
      let afterLeft = dropWhile (not . ("Left cbErr" `isInfixOf`)) (lines src)
          (pre, post) = break ("when (height == nb)" `isInfixOf`) afterLeft
          preFlat = flat (unlines pre)
      preFlat `shouldSatisfy` ("formatUnconnectedArrivalDetail" `isInfixOf`)
      -- The error argument sits on the arrival call, before the guard
      -- that used to be the only place cbErr was printed.
      preFlat `shouldSatisfy` ("nUnc cbErr" `isInfixOf`)
      unlines post `shouldSatisfy` ("[W163 diag]" `isInfixOf`)
      -- Header-reject during IBD used to suppress the string entirely
      -- (`unless isIBD`). The arrival line carries it regardless.
      let hdr = bindingBody src "UnconnHeaderRejected" "UnconnTooFarAhead"
      flat hdr `shouldSatisfy` ("UnconnHeaderRejected nUnc err" `isInfixOf`)

    it "each window re-reads the peer map and logs send fate, including next-needed" $ do
      src <- mainHs
      let body = bindingBody src "requestBlockRange pm hc fromHeight" "fillLinearPipeline"
          flatBody = flat body
          flatSrc = flat src
      flatBody `shouldSatisfy` ("formatWindowPeerSend" `isInfixOf`)
      flatBody `shouldSatisfy` ("peerConnectedAtSend" `isInfixOf`)
      flatBody `shouldSatisfy` ("formatNextNeededAssignment" `isInfixOf`)
      -- Re-read at send time. getConnectedPeerList's earlier snapshot
      -- is what a stale index would trust alone.
      flatBody `shouldSatisfy` ("readTVarIO (pmPeers pm)" `isInfixOf`)
      -- Instrumentation only: a failed send still records inflight.
      flatBody `shouldSatisfy` ("Map.union added" `isInfixOf`)
      flatBody `shouldSatisfy` (not . ("when sendOk" `isInfixOf`))
      flatSrc `shouldSatisfy`
        ("requestBlockRange pm hc fromHeight toHeight rot failed inflight now cap branch nextNeeded" `isInfixOf`)
      flatSrc `shouldSatisfy`
        ("requestBlockRange pm' hc refillFrom windowEnd rot failed2 infAfterMute nowKick perPeerCap branch nextBlock" `isInfixOf`)
      flatSrc `shouldSatisfy`
        ("requestBlockRange pm hc nextBlock windowEnd rot failed0 infPruned nowKick cap FillReceipt nextBlock" `isInfixOf`)

    it "requestFromPeerChecked names the message type and the peer state" $ do
      src <- netHs
      let body = bindingBody src "requestFromPeerChecked pm addr msg" "getPeerCount"
          flatBody = flat body
      flatBody `shouldSatisfy` ("formatRequestSendFailure" `isInfixOf`)
      flatBody `shouldSatisfy` ("formatRequestUnknownPeer" `isInfixOf`)
      flatBody `shouldSatisfy` ("msgTypeName msg" `isInfixOf`)
      flatBody `shouldSatisfy` ("piState info" `isInfixOf`)
