{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Fork-aware download + prefix reorg (mainnet stall at 966499).
--
-- Live symptom (receipt haskoin-fork-reorg-download-stuck-966499-2026-09-16):
-- header tip well ahead of the connected tip, fork below the connected tip,
-- kicker REQUESTS the heavier-branch bodies from every peer, reorg stays
-- "deferred", block tip frozen.  clearbit reorged past the same fork.
--
-- Two production defects this suite pins:
--
--   1. tryP2PReorg waits for EVERY body fork+1..header-tip before calling
--      performReorg.  Core ActivateBestChain connects the downloaded
--      prefix as soon as it out-works the connected tip.
--   2. requestForkBlocks round-robins historical getdata to
--      NODE_NETWORK_LIMITED peers.  BIP-159 peers only serve the last
--      288 blocks; a 700-block-deep fork child is never served.
--
-- Control: a staged reorg whose heavier branch is only PARTIALLY on
-- disk must still advance the connected tip (prefix), and a 781-deep
-- hash must be assigned only to a NODE_NETWORK peer.
module W191ForkReorgDownloadSpec (spec) where

import Test.Hspec
import Control.Concurrent.STM (atomically, modifyTVar', readTVarIO, writeTVar)
import Control.Monad (foldM)
import Data.Word (Word8, Word32, Word64)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set

import Haskoin.Types
  ( BlockHash(..), Hash256(..), TxId(..), Block(..), BlockHeader(..)
  , Tx(..), TxIn(..), TxOut(..), OutPoint(..)
  )
import Haskoin.Crypto (computeBlockHash, computeTxId)
import Haskoin.Consensus
  ( regtest, netGenesisBlock
  , connectBlockAt
  , performReorg
  , initHeaderChain
  , HeaderChain(..)
  , ChainEntry(..)
  , BlockStatus(..)
  , mkCandidateKey
  , headerWork
  , computeMerkleRoot
  , encodeBip34Height
  , heavierBranchHashes
  , connectableForkTip
  )
import qualified Haskoin.Storage as S
import Haskoin.Storage
  ( defaultDBConfig, withDB
  , getBestBlockHash
  , putBlock
  , newUTXOCache
  )
import Haskoin.Network
  ( nodeNetwork, nodeNetworkLimited, nodeWitness
  , combineServices
  , peerCanServeBlock
  , ForkGetDataPeer(..)
  , planForkGetData
  , nodeNetworkLimitedMinBlocks
  )

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

--------------------------------------------------------------------------------
-- Service bits
--------------------------------------------------------------------------------

fullNode, limitedNode, noWitness :: Word64
fullNode    = combineServices [nodeNetwork, nodeWitness]
limitedNode = combineServices [nodeNetworkLimited, nodeWitness]
noWitness   = combineServices [nodeNetwork]

spec :: Spec
spec = do
  describe "fork-reorg-download" $ do
    describe "peerCanServeBlock (BIP-159)" $ do
      it "NODE_NETWORK serves a 781-deep fork child" $
        peerCanServeBlock fullNode 967281 966500 `shouldBe` True
      it "NODE_NETWORK_LIMITED refuses a 781-deep fork child" $
        peerCanServeBlock limitedNode 967281 966500 `shouldBe` False
      it "NODE_NETWORK_LIMITED serves a block 81 below the header tip" $
        peerCanServeBlock limitedNode 967281 967200 `shouldBe` True
      it "pre-segwit (no NODE_WITNESS) serves nothing" $
        peerCanServeBlock noWitness 967281 967200 `shouldBe` False
      it "NODE_NETWORK_LIMITED window is 288-2" $
        nodeNetworkLimitedMinBlocks `shouldBe` 288

    describe "planForkGetData does not send historical hashes to LIMITED peers" $ do
      let hDeep = BlockHash (Hash256 (BS.replicate 32 0x11))
          hNear = BlockHash (Hash256 (BS.replicate 32 0x22))
          limited = ForkGetDataPeer 0 limitedNode
          full    = ForkGetDataPeer 1 fullNode
          assigned pid plan = lookup pid plan
      it "a 781-deep missing body is assigned only to NODE_NETWORK" $ do
        -- Production shape: fork@966499, header tip 967281, first
        -- bridging body at 966500.  rot=0 would previously hand the
        -- first batch to peer 0 (LIMITED) which cannot serve it.
        let plan = planForkGetData [limited, full]
                                   [(hDeep, 966500)]
                                   967281
                                   0
        assigned 0 plan `shouldBe` Nothing
        assigned 1 plan `shouldBe` Just [hDeep]
      it "a near-tip missing body MAY go to NODE_NETWORK_LIMITED" $ do
        let plan = planForkGetData [limited, full]
                                   [(hNear, 967200)]
                                   967281
                                   0
        assigned 0 plan `shouldBe` Just [hNear]
      it "no capable peer → empty plan (do not spray LIMITED)" $ do
        let plan = planForkGetData [limited]
                                   [(hDeep, 966500)]
                                   967281
                                   0
        plan `shouldBe` []

    describe "connectableForkTip advances on a downloaded prefix" $ do
      it "walks the heavier branch by cePrev, not height" $ do
        let forkH = BlockHash (Hash256 (BS.replicate 32 0xaa))
            w1    = BlockHash (Hash256 (BS.replicate 32 0xbb))
            w2    = BlockHash (Hash256 (BS.replicate 32 0xcc))
            entries = Map.fromList
              [ (forkH, mkSyn forkH Nothing 2 10)
              , (w1,    mkSyn w1 (Just forkH) 3 11)
              , (w2,    mkSyn w2 (Just w1)    4 12)
              ]
        heavierBranchHashes entries forkH w2 `shouldBe` Just [w1, w2]

      it "reorgs to the heaviest downloaded prefix, not only the header tip" $ do
        -- Connected at L (work 11).  Heavier headers W1(work 11 equal),
        -- W2(12), W3(13).  Bodies for W1 and W2 on disk, W3 missing.
        -- PRE-FIX connectableForkTip waits for W3 → Nothing (stall).
        -- POST-FIX returns W2, which out-works L, so the reorg can run.
        let forkH = BlockHash (Hash256 (BS.replicate 32 0xa1))
            lH    = BlockHash (Hash256 (BS.replicate 32 0xa2))
            w1    = BlockHash (Hash256 (BS.replicate 32 0xb1))
            w2    = BlockHash (Hash256 (BS.replicate 32 0xb2))
            w3    = BlockHash (Hash256 (BS.replicate 32 0xb3))
            entries = Map.fromList
              [ (forkH, mkSyn forkH Nothing     2 10)
              , (lH,    mkSyn lH    (Just forkH) 3 11)
              , (w1,    mkSyn w1    (Just forkH) 3 11)
              , (w2,    mkSyn w2    (Just w1)    4 12)
              , (w3,    mkSyn w3    (Just w2)    5 13)
              ]
            hasBody h = h == w1 || h == w2
        connectableForkTip entries forkH w3 lH hasBody
          `shouldBe` Just w2

      it "does not reorg onto an equal-work first fork child alone" $ do
        let forkH = BlockHash (Hash256 (BS.replicate 32 0xc1))
            lH    = BlockHash (Hash256 (BS.replicate 32 0xc2))
            w1    = BlockHash (Hash256 (BS.replicate 32 0xc3))
            w2    = BlockHash (Hash256 (BS.replicate 32 0xc4))
            entries = Map.fromList
              [ (forkH, mkSyn forkH Nothing     2 10)
              , (lH,    mkSyn lH    (Just forkH) 3 11)
              , (w1,    mkSyn w1    (Just forkH) 3 11)
              , (w2,    mkSyn w2    (Just w1)    4 12)
              ]
        connectableForkTip entries forkH w2 lH (== w1)
          `shouldBe` Nothing

    describe "staged reorg: heavier prefix on disk advances the connected tip" $ do
      it "performReorg onto the downloaded prefix moves PrefixBestBlock" $ do
        withTestDB "prefix-reorg" $ \db -> do
          (hc, lHash, w2Hash, w3Hash) <- setupPartialFork db
          cache <- newUTXOCache db 100000
          ents <- readTVarIO (hcEntries hc)
          let forkHash = case Map.lookup lHash ents >>= cePrev of
                Just p  -> p
                Nothing -> error "losing tip has no parent"
              hasBody h = h /= w3Hash
          connectableForkTip ents forkHash w3Hash lHash hasBody
            `shouldBe` Just w2Hash
          res <- performReorg regtest cache db hc Nothing lHash w2Hash
          res `shouldBe` Right ()
          mBest <- getBestBlockHash db
          mBest `shouldBe` Just w2Hash

--------------------------------------------------------------------------------
-- Synthetic header-index entries (hash-keyed walk only)
--------------------------------------------------------------------------------

mkSyn :: BlockHash -> Maybe BlockHash -> Word32 -> Integer -> ChainEntry
mkSyn h prevHash height work = ChainEntry
  { ceHeader     = BlockHeader 0x20000000
                               (fromMaybe (BlockHash (Hash256 (BS.replicate 32 0))) prevHash)
                               (Hash256 (BS.replicate 32 0))
                               0 0x207fffff 0
  , ceHash       = h
  , ceHeight     = height
  , ceChainWork  = work
  , cePrev       = prevHash
  , ceStatus     = StatusValid
  , ceMedianTime = 0
  , ceSequenceId = 0
  }
  where
    fromMaybe d m = case m of
      Just x  -> x
      Nothing -> d

--------------------------------------------------------------------------------
-- Chain fixture
--
--   genesis..2     common, CONNECTED
--        \-- 3 L   losing branch, CONNECTED (active tip)
--        \-- 3 W1  winning, body on disk
--            4 W2  winning, body on disk   ← prefix the reorg should adopt
--            5 W3  winning, HEADER ONLY    ← the missing suffix
--------------------------------------------------------------------------------

withTestDB :: String -> (S.HaskoinDB -> IO a) -> IO a
withTestDB tag action =
  withSystemTempDirectory ("haskoin-w191-" ++ tag) $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) action

opTrue :: BS.ByteString
opTrue = BS.pack [0x51]

nullOutPoint :: OutPoint
nullOutPoint = OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff

coinbaseTxAt :: Word32 -> Word8 -> Tx
coinbaseTxAt h tag = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn
      { txInPrevOutput = nullOutPoint
      , txInScript     = encodeBip34Height h `BS.snoc` tag
      , txInSequence   = 0xffffffff
      } ]
  , txOutputs  = [ TxOut { txOutValue = 5000000000, txOutScript = opTrue } ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

mkBlock :: BlockHash -> Word32 -> Word32 -> [Tx] -> Block
mkBlock prevHash ts nonce txns = Block
  { blockHeader = BlockHeader
      { bhVersion    = 0x20000000
      , bhPrevBlock  = prevHash
      , bhMerkleRoot = computeMerkleRoot (map computeTxId txns)
      , bhTimestamp  = ts
      , bhBits       = 0x207fffff
      , bhNonce      = nonce
      }
  , blockTxns = txns
  }

mkEntry :: Block -> Word32 -> BlockHash -> Integer -> Word64 -> ChainEntry
mkEntry blk h prevHash work seqId = ChainEntry
  { ceHeader     = blockHeader blk
  , ceHash       = computeBlockHash (blockHeader blk)
  , ceHeight     = h
  , ceChainWork  = work
  , cePrev       = Just prevHash
  , ceStatus     = StatusValid
  , ceMedianTime = bhTimestamp (blockHeader blk)
  , ceSequenceId = seqId
  }

insertActiveTip :: HeaderChain -> ChainEntry -> IO ()
insertActiveTip hc ce = atomically $ do
  modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
  modifyTVar' (hcByHeight hc)   (Map.insert (ceHeight ce) (ceHash ce))
  modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))
  writeTVar (hcTip hc)    ce
  writeTVar (hcHeight hc) (ceHeight ce)

insertSideEntry :: HeaderChain -> ChainEntry -> IO ()
insertSideEntry hc ce = atomically $ do
  modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
  modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))

baseTime :: Word32
baseTime = 1296688700

-- | Returns (hc, losing tip L@3, W2@4 on disk, W3@5 header-only).
setupPartialFork :: S.HaskoinDB
                 -> IO (HeaderChain, BlockHash, BlockHash, BlockHash)
setupPartialFork db = do
  let net     = regtest
      genesis = netGenesisBlock net
      gHash   = computeBlockHash (blockHeader genesis)
      gWork   = headerWork (blockHeader genesis)
  hc <- initHeaderChain net
  rG <- connectBlockAt db net genesis 0 Map.empty
  rG `shouldBe` Right ()

  let step (prevHash, work) h = do
        let blk   = mkBlock prevHash (baseTime + h) h [coinbaseTxAt h 0x01]
            work' = work + headerWork (blockHeader blk)
            ce    = mkEntry blk h prevHash work' (fromIntegral h)
        r <- connectBlockAt db net blk h Map.empty
        r `shouldBe` Right ()
        insertActiveTip hc ce
        return (ceHash ce, work')
  (forkHash, forkWork) <- foldM step (gHash, gWork) [1, 2]

  let lBlk  = mkBlock forkHash (baseTime + 3) 30 [coinbaseTxAt 3 0x0a]
      lWork = forkWork + headerWork (blockHeader lBlk)
      lCe   = mkEntry lBlk 3 forkHash lWork 1003
  rL <- connectBlockAt db net lBlk 3 Map.empty
  rL `shouldBe` Right ()
  insertActiveTip hc lCe

  let w1Blk  = mkBlock forkHash (baseTime + 13) 31 [coinbaseTxAt 3 0x0b]
      w1Work = forkWork + headerWork (blockHeader w1Blk)
      w1Ce   = mkEntry w1Blk 3 forkHash w1Work 2003
      w1Hash = ceHash w1Ce
      w2Blk  = mkBlock w1Hash (baseTime + 14) 32 [coinbaseTxAt 4 0x0c]
      w2Work = w1Work + headerWork (blockHeader w2Blk)
      w2Ce   = mkEntry w2Blk 4 w1Hash w2Work 2004
      w2Hash = ceHash w2Ce
      w3Blk  = mkBlock w2Hash (baseTime + 15) 33 [coinbaseTxAt 5 0x0d]
      w3Work = w2Work + headerWork (blockHeader w3Blk)
      w3Ce   = mkEntry w3Blk 5 w2Hash w3Work 2005
      w3Hash = ceHash w3Ce

  putBlock db w1Hash w1Blk
  putBlock db w2Hash w2Blk
  insertSideEntry hc w1Ce
  insertSideEntry hc w2Ce
  insertSideEntry hc w3Ce
  atomically $ do
    modifyTVar' (hcByHeight hc) (Map.insert 4 w2Hash)
    modifyTVar' (hcByHeight hc) (Map.insert 5 w3Hash)
    writeTVar (hcTip hc)    w3Ce
    writeTVar (hcHeight hc) 5

  (w3Work > lWork) `shouldBe` True
  (w2Work > lWork) `shouldBe` True
  return (hc, ceHash lCe, w2Hash, w3Hash)
