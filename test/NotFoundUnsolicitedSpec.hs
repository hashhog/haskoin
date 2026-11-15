{-# LANGUAGE CPP #-}
-- | secfix-haskoin-notfound-unsolicited (H6).
--
-- A @notfound@ naming 50,000 block hashes nobody asked for used to put all
-- 50,000 into the global, uncapped @blockNotFoundRef@ (rebuilt per message,
-- read on every planner tick).  Core (net_processing.cpp NOTFOUND) only acts
-- on items in flight to that peer.  The fix keeps a ledger of the block
-- getdata this node sent each peer ('noteBlockRequested', called from
-- 'sendMessage'), records a notfound only for hashes in it, and caps both
-- maps.
--
-- The tests call "Haskoin.BlockNotFound", which the fix adds.  They sit
-- behind @HASKOIN_NOTFOUND_SOLICITED@, which the fix commit sets in this
-- suite's cabal stanza (Template Haskell cannot load the haskoin library
-- here because of the libzmq shared object).  Without it this file still
-- compiles and every test fails on its assertion.
module NotFoundUnsolicitedSpec (spec) where

import Test.Hspec

#ifdef HASKOIN_NOTFOUND_SOLICITED
import qualified Data.ByteString as BS
import Data.IORef
import qualified Data.Map.Strict as Map
import Network.Socket (tupleToHostAddress)

import Haskoin.Types
import Haskoin.Network
import Haskoin.BlockNotFound
#endif

#ifdef HASKOIN_NOTFOUND_SOLICITED
hashN :: Int -> BlockHash
hashN i = BlockHash (Hash256 (BS.pack [ fromIntegral (i `div` 65536)
                                      , fromIntegral (i `div` 256)
                                      , fromIntegral (i `mod` 256) ]
                              <> BS.replicate 29 9))

peerA, peerB :: SockAddr
peerA = SockAddrInet 8333 (tupleToHostAddress (10, 0, 0, 1))
peerB = SockAddrInet 8333 (tupleToHostAddress (10, 0, 0, 2))

reset :: IO ()
reset = writeIORef blockNotFoundRef Map.empty >> writeIORef blockRequestedRef Map.empty

spec :: Spec
spec = describe "secfix-haskoin-notfound-unsolicited" $ do
  it "unsolicited_notfound_ignored" $ do
    reset
    noteBlockNotFound peerA (map hashN [0 .. 49999])
    nf <- readBlockNotFound
    Map.size nf `shouldBe` 0
    blockNotFoundEntryCount >>= (`shouldBe` 0)

  it "solicited_notfound_recorded (only the hash in flight to that peer)" $ do
    reset
    noteBlockRequested peerA [hashN 7]
    noteBlockNotFound peerA (map hashN [0 .. 999])
    nf <- readBlockNotFound
    Map.keys nf `shouldBe` [hashN 7]
    fmap Map.keys (Map.lookup (hashN 7) nf) `shouldBe` Just [peerA]

  it "a hash repeated 50,000 times in one notfound is recorded once" $ do
    reset
    noteBlockRequested peerA [hashN 9]
    noteBlockNotFound peerA (replicate 50000 (hashN 9))
    blockNotFoundEntryCount >>= (`shouldBe` 1)

  it "notfound_from_other_peer_ignored" $ do
    reset
    noteBlockRequested peerA [hashN 1]
    noteBlockNotFound peerB [hashN 1]
    blockNotFoundEntryCount >>= (`shouldBe` 0)
    noteBlockNotFound peerA [hashN 1]
    blockNotFoundEntryCount >>= (`shouldBe` 1)

  it "notfound consumes the request (a repeat is not re-recorded)" $ do
    reset
    noteBlockRequested peerA [hashN 3]
    noteBlockNotFound peerA [hashN 3]
    req <- readIORef blockRequestedRef
    Map.member (hashN 3) req `shouldBe` False

  it "a delivered block answers the request (a later notfound is ignored)" $ do
    reset
    noteBlockRequested peerA [hashN 5]
    noteBlockRequestAnswered peerA (hashN 5)
    noteBlockNotFound peerA [hashN 5]
    blockNotFoundEntryCount >>= (`shouldBe` 0)

  it "getdata block hashes are what sendMessage records" $ do
    let ivs = [ InvVector InvWitnessBlock (getBlockHashHash (hashN 1))
              , InvVector InvTx (getBlockHashHash (hashN 2))
              , InvVector InvBlock (getBlockHashHash (hashN 3)) ]
    blockGetDataHashes (MGetData (GetData ivs)) `shouldBe` [hashN 1, hashN 3]
    blockGetDataHashes (MNotFound (NotFound ivs)) `shouldBe` []

  it "notfound_map_capped" $ do
    let n = maxBlockNotFoundEntries + 5000
        req = insertRequestedAt 1000 peerA (map hashN [0 .. n - 1]) Map.empty
        (_, nf) = recordNotFoundAt 1001 peerA (map hashN [0 .. n - 1]) req Map.empty
    entryCount req `shouldBe` n
    entryCount nf `shouldBe` maxBlockNotFoundEntries
    -- oldest-first eviction keeps the newest answer
    let nf2 = capEntries 1 (Map.fromList [ (hashN 1, Map.singleton peerA 5)
                                         , (hashN 2, Map.singleton peerA 9) ])
    Map.keys nf2 `shouldBe` [hashN 2]

  it "request ledger capped" $ do
    let req = insertRequestedAt 1000 peerA
                (map hashN [0 .. maxBlockRequestedEntries + 999]) Map.empty
    entryCount req `shouldBe` maxBlockRequestedEntries

  it "expired requests do not admit a notfound" $ do
    let req = insertRequestedAt 1000 peerA [hashN 4] Map.empty
        (_, nf) = recordNotFoundAt (1000 + blockRequestTtl) peerA [hashN 4] req Map.empty
    entryCount nf `shouldBe` 0
#else
spec :: Spec
spec = describe "secfix-haskoin-notfound-unsolicited" $ do
  let absent = expectationFailure
        ("no solicited-only notfound filter on this commit: every hash in a "
         ++ "notfound goes into blockNotFoundRef (app/Main.hs noteBlockNotFound)")
  mapM_ (\n -> it n absent)
    [ "unsolicited_notfound_ignored"
    , "solicited_notfound_recorded (only the hash in flight to that peer)"
    , "a hash repeated 50,000 times in one notfound is recorded once"
    , "notfound_from_other_peer_ignored"
    , "notfound consumes the request (a repeat is not re-recorded)"
    , "a delivered block answers the request (a later notfound is ignored)"
    , "getdata block hashes are what sendMessage records"
    , "notfound_map_capped"
    , "request ledger capped"
    , "expired requests do not admit a notfound"
    ]
#endif
