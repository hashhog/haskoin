{-# LANGUAGE OverloadedStrings #-}

-- | A reorg starts from the CONNECTED tip (PrefixBestBlock), never from the
-- best header 'hcTip'.
--
-- Core: Chainstate::ActivateBestChain (validation.cpp:3323) and
-- Chainstate::PreciousBlock (:3490) work from m_chain.Tip(); DisconnectTip
-- (:2929) takes pindexDelete = m_chain.Tip() (:2934), so only the connected
-- tip is ever disconnected.
--
-- Pre-fix, 'activateBestChain', 'preciousBlock' and 'preciousReactivate'
-- read 'hcTip' (the best header) and handed it to 'performReorg' as the old
-- tip, and the disconnect step never checked that the block it rewinds is
-- PrefixBestBlock:
--
--   * hcTip a header-only descendant of the connected tip: the disconnect
--     list starts at a block with no body, the reorg fails, and the node
--     stays on the lighter chain (or, with the work test also reading hcTip,
--     never even tries).
--   * hcTip on a stale branch whose bodies and undo are still on disk: the
--     undo of a block that is not connected is applied to the UTXO set and
--     PrefixBestBlock is moved onto that branch.
module ReorgOldTipSpec (spec) where

import Test.Hspec
import Control.Concurrent.STM (atomically, modifyTVar', writeTVar, readTVarIO)
import Control.Monad (foldM, forM_)
import Data.List (isInfixOf)
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
  , activateBestChain
  , preciousBlock
  , initHeaderChain
  , HeaderChain(..)
  , ChainEntry(..)
  , BlockStatus(..)
  , mkCandidateKey
  , headerWork
  , computeMerkleRoot
  , encodeBip34Height
  , blockRewardForNet
  )
import qualified Haskoin.Storage as S
import Haskoin.Storage
  ( defaultDBConfig, withDB
  , getBestBlockHash
  , getUTXO
  , putBlock
  , newUTXOCache
  )

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

--------------------------------------------------------------------------------
-- Fixture
--------------------------------------------------------------------------------

withTestDB :: String -> (S.HaskoinDB -> IO a) -> IO a
withTestDB tag action =
  withSystemTempDirectory ("haskoin-reorg-oldtip-" ++ tag) $ \dir ->
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
  , txOutputs  = [ TxOut { txOutValue = blockRewardForNet regtest h, txOutScript = opTrue } ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

cbOut :: Word32 -> Word8 -> OutPoint
cbOut h tag = OutPoint (computeTxId (coinbaseTxAt h tag)) 0

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

mkEntry :: Block -> Word32 -> BlockHash -> Integer -> Word64 -> BlockStatus
        -> ChainEntry
mkEntry blk h prevHash work seqId st = ChainEntry
  { ceHeader     = blockHeader blk
  , ceHash       = computeBlockHash (blockHeader blk)
  , ceHeight     = h
  , ceChainWork  = work
  , cePrev       = Just prevHash
  , ceStatus     = st
  , ceMedianTime = bhTimestamp (blockHeader blk)
  , ceSequenceId = seqId
  }

baseTime :: Word32
baseTime = 1296688700

-- Branch tags: A is the connected chain, B the rival.
tagA, tagB :: Word8
tagA = 0x0a
tagB = 0x0b

branchBlock :: Word8 -> BlockHash -> Word32 -> Block
branchBlock tag prev h =
  mkBlock prev (baseTime + fromIntegral tag * 1000 + h)
          (fromIntegral tag * 100000 + h) [coinbaseTxAt h tag]

data Fx = Fx
  { fxHc    :: HeaderChain
  , fxA     :: [ChainEntry]   -- ^ connected branch, height 1 first
  , fxB     :: [ChainEntry]   -- ^ rival branch (bodies on disk), height 1 first
  , fxHdr   :: [ChainEntry]   -- ^ header-only descendants of the A tip
  }

-- | Genesis + branch A @1..aLen@ connected (PrefixBestBlock = A tip);
-- branch B @1..bLen@ forking at genesis, bodies stored, StatusValid, in the
-- candidate set; @hdrLen@ header-only blocks on top of the A tip.  When
-- @hdrLen > 0@ 'hcTip' is the last of them (the best header), as
-- 'recalculateBestHeader' leaves it after headers sync; otherwise 'hcTip'
-- is the A tip.
setupFx :: S.HaskoinDB -> Word32 -> Word32 -> Word32 -> IO Fx
setupFx db aLen bLen hdrLen = do
  let net     = regtest
      genesis = netGenesisBlock net
      gHash   = computeBlockHash (blockHeader genesis)
      gWork   = headerWork (blockHeader genesis)
  hc <- initHeaderChain net
  connectBlockAt db net genesis 0 Map.empty `shouldReturn` Right ()

  let stepA (acc, prev, work) h = do
        let blk   = branchBlock tagA prev h
            work' = work + headerWork (blockHeader blk)
            ce    = mkEntry blk h prev work' (fromIntegral h) StatusValid
        connectBlockAt db net blk h Map.empty `shouldReturn` Right ()
        atomically $ do
          modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
          modifyTVar' (hcByHeight hc)   (Map.insert h (ceHash ce))
          modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))
          writeTVar (hcTip hc) ce
          writeTVar (hcHeight hc) h
        return (acc ++ [ce], ceHash ce, work')
  (as, aTip, aWork) <- foldM stepA ([], gHash, gWork) [1 .. aLen]

  let stepB (acc, prev, work) h = do
        let blk   = branchBlock tagB prev h
            work' = work + headerWork (blockHeader blk)
            ce    = mkEntry blk h prev work' (10000 + fromIntegral h) StatusValid
        putBlock db (ceHash ce) blk
        atomically $ do
          modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
          modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))
        return (acc ++ [ce], ceHash ce, work')
  (bs, _, _) <- foldM stepB ([], gHash, gWork) [1 .. bLen]

  let stepH (acc, prev, work) h = do
        let blk   = branchBlock tagA prev h
            work' = work + headerWork (blockHeader blk)
            ce    = mkEntry blk h prev work' (20000 + fromIntegral h)
                            StatusHeaderValid
        atomically $ do
          modifyTVar' (hcEntries hc)  (Map.insert (ceHash ce) ce)
          modifyTVar' (hcByHeight hc) (Map.insert h (ceHash ce))
          writeTVar (hcTip hc) ce
          writeTVar (hcHeight hc) h
        return (acc ++ [ce], ceHash ce, work')
  (hs, _, _) <- foldM stepH ([], aTip, aWork) [aLen + 1 .. aLen + hdrLen]

  getBestBlockHash db `shouldReturn` Just aTip
  return Fx { fxHc = hc, fxA = as, fxB = bs, fxHdr = hs }

lastHash :: [ChainEntry] -> BlockHash
lastHash = ceHash . last

-- | B tip is the connected tip and its coins are the UTXO set: every B
-- coinbase present, every A coinbase gone.
shouldBeOnB :: S.HaskoinDB -> Fx -> IO ()
shouldBeOnB db fx = do
  getBestBlockHash db `shouldReturn` Just (lastHash (fxB fx))
  forM_ (fxB fx) $ \ce -> do
    m <- getUTXO db (cbOut (ceHeight ce) tagB)
    fmap txOutScript m `shouldBe` Just opTrue
  forM_ (fxA fx) $ \ce ->
    getUTXO db (cbOut (ceHeight ce) tagA) `shouldReturn` Nothing

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "reorg old tip is the connected tip (Core m_chain.Tip())" $ do

  describe "activateBestChain" $ do

    -- hcTip = A6 (header-only), connected = A4, rival B5.  B5 out-works the
    -- connected tip, so Core reorgs to it; pre-fix the work test read hcTip
    -- (A6 > B5) and nothing happened.
    it "reorgs to a rival heavier than the connected tip but not the best header" $
      withTestDB "abc-lighter-than-header" $ \db -> do
        fx <- setupFx db 4 5 2
        cache <- newUTXOCache db 100000
        activateBestChain regtest cache db (fxHc fx) Nothing
        shouldBeOnB db fx

    -- hcTip = A6 (header-only), connected = A4, rival B7 out-works both.
    -- Pre-fix the disconnect list started at A6, which has no body, so the
    -- reorg failed and the node stayed on A.
    it "reorgs to a rival heavier than the best header when the best header is header-only" $
      withTestDB "abc-heavier-than-header" $ \db -> do
        fx <- setupFx db 4 7 2
        cache <- newUTXOCache db 100000
        activateBestChain regtest cache db (fxHc fx) Nothing
        shouldBeOnB db fx

    -- Stale best header WITH bodies: connected = B4 after a reorg off A3;
    -- the A branch is extended by stored bodies A4, A5 (A5 out-works B4)
    -- and hcTip is left at A3.  Pre-fix the reorg ran from A3: an empty
    -- disconnect list and A4, A5 connected on top of B's UTXO set.
    it "reorgs from the connected tip when the best header is a stale branch with bodies" $
      withTestDB "abc-stale-branch" $ \db -> do
        fx <- setupFx db 3 4 0
        let hc = fxHc fx
        cache <- newUTXOCache db 100000
        performReorg regtest cache db hc Nothing (lastHash (fxA fx)) (lastHash (fxB fx))
          `shouldReturn` Right ()
        getBestBlockHash db `shouldReturn` Just (lastHash (fxB fx))
        -- extend A with bodies to A5
        let a3 = last (fxA fx)
            mk prevCe h = do
              let blk = branchBlock tagA (ceHash prevCe) h
                  ce  = mkEntry blk h (ceHash prevCe)
                          (ceChainWork prevCe + headerWork (blockHeader blk))
                          (30000 + fromIntegral h) StatusValid
              putBlock db (ceHash ce) blk
              atomically $ do
                modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
                modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))
              return ce
        a4 <- mk a3 4
        a5 <- mk a4 5
        atomically $ do
          writeTVar (hcTip hc) a3
          writeTVar (hcHeight hc) 3
        activateBestChain regtest cache db hc Nothing
        getBestBlockHash db `shouldReturn` Just (ceHash a5)
        -- A's coins, all of them; B's coins gone.
        forM_ [1 .. 5] $ \h -> do
          m <- getUTXO db (cbOut h tagA)
          fmap txOutScript m `shouldBe` Just opTrue
        forM_ [1 .. 4] $ \h ->
          getUTXO db (cbOut h tagB) `shouldReturn` Nothing

    -- Consensus control: hcTip == connected tip (no header-only blocks).
    it "control: still reorgs when the best header is the connected tip" $
      withTestDB "abc-control" $ \db -> do
        fx <- setupFx db 4 5 0
        cache <- newUTXOCache db 100000
        (ceHash <$> readTVarIO (hcTip (fxHc fx))) `shouldReturn` lastHash (fxA fx)
        activateBestChain regtest cache db (fxHc fx) Nothing
        shouldBeOnB db fx

    it "control: does not reorg to a rival lighter than the connected tip" $
      withTestDB "abc-control-lighter" $ \db -> do
        fx <- setupFx db 4 3 2
        cache <- newUTXOCache db 100000
        activateBestChain regtest cache db (fxHc fx) Nothing
        getBestBlockHash db `shouldReturn` Just (lastHash (fxA fx))

  describe "preciousblock" $ do

    -- Equal work to the connected tip A4; hcTip = A6 (header-only).  Core
    -- compares against m_chain.Tip() and reorgs onto the precious block.
    it "reorgs onto an equal-work precious block when the best header is header-only" $
      withTestDB "precious-equal" $ \db -> do
        fx <- setupFx db 4 4 2
        cache <- newUTXOCache db 100000
        r <- preciousBlock regtest cache db (fxHc fx) Nothing (lastHash (fxB fx))
        r `shouldBe` Right ()
        shouldBeOnB db fx

    -- B7 out-works hcTip A6 too, so the pre-fix work test passed and the
    -- reorg itself ran from A6 (no body) and failed.
    it "reorgs onto a heavier precious block when the best header is header-only" $
      withTestDB "precious-heavier" $ \db -> do
        fx <- setupFx db 4 7 2
        cache <- newUTXOCache db 100000
        r <- preciousBlock regtest cache db (fxHc fx) Nothing (lastHash (fxB fx))
        r `shouldBe` Right ()
        shouldBeOnB db fx

    it "control: reorgs onto an equal-work precious block when the best header is the connected tip" $
      withTestDB "precious-control" $ \db -> do
        fx <- setupFx db 4 4 0
        cache <- newUTXOCache db 100000
        r <- preciousBlock regtest cache db (fxHc fx) Nothing (lastHash (fxB fx))
        r `shouldBe` Right ()
        shouldBeOnB db fx

  describe "disconnect step" $ do

    -- The disconnect step must refuse a block that is not PrefixBestBlock.
    -- After a reorg A3 -> B4 the A blocks keep their bodies and checksum-
    -- valid undo, so Phase A (undo verification) passes and only the
    -- disconnect step's tip check stands between A3's undo and B's UTXO
    -- set.  Pre-fix: A3's undo applied, PrefixBestBlock moved to A2 while
    -- the coins are B's.
    it "refuses to disconnect a block that is not the connected tip" $
      withTestDB "disconnect-not-tip" $ \db -> do
        fx <- setupFx db 3 4 0
        let hc = fxHc fx
            a2 = fxA fx !! 1
            a3 = fxA fx !! 2
        cache <- newUTXOCache db 100000
        performReorg regtest cache db hc Nothing (ceHash a3) (lastHash (fxB fx))
          `shouldReturn` Right ()
        r <- performReorg regtest cache db hc Nothing (ceHash a3) (ceHash a2)
        -- The tip check, not Phase A (A3's body and undo are on disk).
        r `shouldSatisfy` either ("is not the connected tip" `isInfixOf`)
                                 (const False)
        shouldBeOnB db fx

    it "control: disconnects the connected tip" $
      withTestDB "disconnect-tip" $ \db -> do
        fx <- setupFx db 3 0 0
        let hc = fxHc fx
            a2 = fxA fx !! 1
            a3 = fxA fx !! 2
        cache <- newUTXOCache db 100000
        performReorg regtest cache db hc Nothing (ceHash a3) (ceHash a2)
          `shouldReturn` Right ()
        getBestBlockHash db `shouldReturn` Just (ceHash a2)
        getUTXO db (cbOut 3 tagA) `shouldReturn` Nothing
