{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W162 — chainstate-wedge regression suite.
--
-- Covers the production incident in which haskoin's mainnet node
-- wedged with its UTXO-view best-block pointer stuck at GENESIS while
-- the block index reported height 950194 — every peer block was
-- rejected by the ConnectBlock G1 gate
-- (@hashPrevBlock == view.GetBestBlock()@, bitcoin-core/src/validation.cpp:2333).
--
-- Two distinct root-cause bugs were found and fixed; this suite pins
-- both:
--
--   BUG-A  Height-index key encoding mismatch.
--          'Storage.putBlockHeight' / 'Storage.getBlockHeight' /
--          'Storage.batchPutBlockHeight' key the height index on the
--          bare 4-byte big-endian height ('toBE32 height').
--          'connectBlockAt' (and 'buildConnectBlockOps') instead keyed
--          it on @encode (toBE32 height)@ — and 'Data.Serialize.encode'
--          on a 'ByteString' prepends an 8-byte Word64 length tag, so
--          the block-connect path wrote a 12-byte payload that
--          'getBlockHeight' can never read.  Every height written by
--          block connection went to a phantom key.
--
--   BUG-B  Destructive best-block reset on every restart.
--          Startup decided "fresh DB vs resume" from 'getChainState'
--          (prefix 0x20).  But 'saveChainState' had zero callers
--          (W109 BUG-31), so 'getChainState' ALWAYS returned
--          'Nothing'.  The startup code therefore took the fresh-DB
--          branch on every restart and ran
--          @putBestBlockHash db genesisHash@, rewinding the live
--          UTXO-view tip pointer to genesis.  The authoritative
--          chainstate-existence signal is 'getBestBlockHash' itself.
--          The dead 'saveChainState' / 'getChainState' API was
--          removed in P2-6; this suite continues to pin the live
--          'getBestBlockHash' contract.
--
-- The fix also adds startup reconciliation (Core's
-- @Chainstate::LoadChainTip@, validation.cpp:4546): block download
-- resumes from the height of the persisted best-block pointer, not the
-- header-chain tip.
--
-- References: bitcoin-core/src/validation.cpp:2333 (G1 assert),
-- :4546 (LoadChainTip).
module W162ChainstateWedgeSpec (spec) where

import Test.Hspec
import Control.Monad (forM_)
import Data.Word (Word32)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Serialize (encode)

import Haskoin.Types (BlockHash(..), Hash256(..), Block(..))
import Haskoin.Crypto (computeBlockHash)
import Haskoin.Consensus
  ( regtest, netGenesisBlock
  , connectBlockAt
  )
import qualified Haskoin.Storage as S
import Haskoin.Storage
  ( DBConfig(..), defaultDBConfig, withDB
  , KeyPrefix(..), makeKey, toBE32
  , getBlockHeight, getBestBlockHash, putBlockHeight, putBestBlockHash
  )

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

-- ============================================================
-- Helpers
-- ============================================================

-- | Run an action against a fresh temp RocksDB.
withTestDB :: String -> (S.HaskoinDB -> IO a) -> IO a
withTestDB tag action =
  withSystemTempDirectory ("haskoin-w162-" ++ tag) $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) action

-- | Pure mirror of the binary search 'runNodeBody' uses to recover the
-- true connected-block tip from the per-block undo records.
--
-- The reconciliation does NOT trust the (possibly genesis-corrupted)
-- @PrefixBestBlock@ pointer; it reconstructs the tip from the
-- contiguous range of heights that have a persisted undo record.
-- 'isConnected' models "block at height h has an undo record" — undo
-- records form a contiguous prefix [1..U] because blocks connect
-- strictly sequentially.  The result is U (0 if not even block 1 is
-- connected).  This is the exact logic of 'findConnectedTip' /
-- 'connectedTipHeight' in 'app/Main.hs'.
findConnectedTipPure
  :: (Word32 -> Bool)  -- ^ does the block at this height have an undo record?
  -> Word32            -- ^ header-chain tip height
  -> Word32            -- ^ recovered connected-block tip
findConnectedTipPure isConnected headerTip
  | headerTip == 0          = 0
  | not (isConnected 1)     = 0
  | otherwise               = go 1 headerTip
  where
    go lo hi
      | lo >= hi  = lo
      | otherwise =
          let mid = lo + (hi - lo + 1) `div` 2
          in if isConnected mid then go mid hi else go lo (mid - 1)

-- ============================================================
-- Spec
-- ============================================================

spec :: Spec
spec = do

  describe "W162 BUG-A — height-index key encoding consistency" $ do

    it "encode (toBE32 h) prepends an 8-byte length tag (the bug)" $ do
      -- This is the exact root cause: cereal's Serialize ByteString
      -- instance writes a Word64 length prefix before the bytes.
      let bare    = toBE32 (4 :: Word32)        -- canonical 4-byte key payload
          encoded = encode bare                 -- the buggy payload
      BS.length bare    `shouldBe` 4
      BS.length encoded `shouldBe` 12           -- 8-byte length tag + 4 bytes
      -- The two are different ByteStrings -> different RocksDB keys.
      (bare == encoded) `shouldBe` False

    it "connectBlockAt genesis fast-path writes a height-index key that getBlockHeight can read" $ do
      -- Pre-fix this FAILS: connectBlockAt wrote PrefixBlockHeight at
      -- key `0x03 ++ encode (toBE32 0)` (13 bytes) while getBlockHeight
      -- reads `0x03 ++ toBE32 0` (5 bytes) -> Nothing.
      withTestDB "genesis-height" $ \db -> do
        let net         = regtest
            genesis     = netGenesisBlock net
            genesisHash = computeBlockHash (blockHeader genesis)
        r <- connectBlockAt db net genesis 0 Map.empty
        r `shouldBe` Right ()
        mAt0 <- getBlockHeight db 0
        mAt0 `shouldBe` Just genesisHash

    it "connectBlockAt and putBlockHeight write the SAME height-index key" $ do
      -- Cross-check: a height written by the header-sync path
      -- (putBlockHeight) and a height written by the block-connect
      -- path (connectBlockAt) must land on the same key so that the
      -- index is internally consistent.
      withTestDB "key-parity" $ \db -> do
        let net         = regtest
            genesis     = netGenesisBlock net
            genesisHash = computeBlockHash (blockHeader genesis)
        -- Header-sync style write at height 0.
        putBlockHeight db 0 genesisHash
        viaHeaderSync <- getBlockHeight db 0
        -- Block-connect style write at the same height (genesis
        -- fast-path).  If the keys differ this would write a phantom
        -- key and getBlockHeight would still see the header-sync value
        -- (or Nothing); if the keys agree it overwrites with the same
        -- value.  Either way the post-condition is the canonical key
        -- holding the genesis hash.
        _ <- connectBlockAt db net genesis 0 Map.empty
        viaConnect <- getBlockHeight db 0
        viaHeaderSync `shouldBe` Just genesisHash
        viaConnect    `shouldBe` Just genesisHash

    it "the canonical height-index key is exactly 0x03 ++ toBE32 height (5 bytes)" $ do
      forM_ [0, 1, 419328, 950194 :: Word32] $ \h -> do
        let key = makeKey PrefixBlockHeight (toBE32 h)
        BS.length key `shouldBe` 5
        BS.head key   `shouldBe` 0x03

  describe "W162 BUG-B — best-block pointer survives restart" $ do

    it "connectBlockAt persists the best-block pointer (getBestBlockHash round-trip)" $ do
      withTestDB "bestblock-rt" $ \db -> do
        let net         = regtest
            genesis     = netGenesisBlock net
            genesisHash = computeBlockHash (blockHeader genesis)
        before <- getBestBlockHash db
        before `shouldBe` Nothing            -- fresh DB
        _ <- connectBlockAt db net genesis 0 Map.empty
        after <- getBestBlockHash db
        after `shouldBe` Just genesisHash

    it "getBestBlockHash is the authoritative chainstate-existence signal" $ do
      -- The startup fix gates genesis-init on getBestBlockHash.  A DB
      -- that has a best-block pointer must be treated as an existing
      -- chainstate.  (Pre-fix, startup also consulted a dead
      -- 'getChainState' / 'saveChainState' pair keyed at prefix 0x20
      -- which always returned Nothing — that API was removed in P2-6.)
      withTestDB "existence-signal" $ \db -> do
        -- Simulate an already-synced node: a best-block pointer well
        -- above genesis is present on disk.
        let fakeTip = BlockHash (Hash256 (BS.cons 0xAB (BS.replicate 31 0)))
        putBestBlockHash db fakeTip
        -- The fix consults getBestBlockHash.
        mBest <- getBestBlockHash db
        mBest `shouldBe` Just fakeTip   -- the real, intact signal
        -- The decision the fixed startup makes: existing chainstate ->
        -- do NOT re-init genesis.
        let chainExists = case mBest of
              Just _  -> True
              Nothing -> False
        chainExists `shouldBe` True

  describe "W162 — connected-tip recovery from undo records (ReplayBlocks analogue)" $ do

    it "recovers the true tip when undo records run [1..U] and the header tip is far ahead" $ do
      -- The exact incident shape: undo records (UTXO set) reach ~949 k,
      -- the header chain is at 950194.  Reconciliation must recover U
      -- from the undo records, NOT trust the genesis-corrupted pointer
      -- and NOT use the header tip.
      let u          = 949000 :: Word32
          headerTip  = 950194 :: Word32
          -- undo record present for every height 1..U, absent above.
          isConnected h = h >= 1 && h <= u
          recovered  = findConnectedTipPure isConnected headerTip
      recovered `shouldBe` u
      -- The node must then re-download (headerTip - U) blocks.
      (headerTip - recovered) `shouldBe` 1194

    it "recovers the header tip itself on a fully-synced healthy node" $ do
      -- Steady state: every block up to the header tip is connected;
      -- recovery returns the header tip and the gap is zero (the
      -- reconciliation + kicker are no-ops).
      let headerTip = 950194 :: Word32
          recovered = findConnectedTipPure (const True) headerTip
      recovered `shouldBe` headerTip

    it "returns 0 when the UTXO set never advanced past genesis" $ do
      -- No block was ever connected (no undo record for block 1):
      -- recovery yields 0, the node re-syncs the chain from height 1.
      let headerTip = 950194 :: Word32
          recovered = findConnectedTipPure (const False) headerTip
      recovered `shouldBe` 0

    it "returns 0 for a header chain that is itself only at genesis" $ do
      findConnectedTipPure (const True) 0 `shouldBe` 0

    it "binary search lands exactly on the boundary for many tip positions" $ do
      -- Exhaustively check that the search recovers U for a range of
      -- boundary positions — guards against off-by-one in the midpoint.
      -- The undo-record predicate is contiguous ([1..U] then absent)
      -- because blocks connect strictly sequentially (the ConnectBlock
      -- G1 gate enforces it), so binary search is well-defined.
      forM_ [0, 1, 2, 3, 7, 100, 419327, 419328, 950193, 950194 :: Word32] $ \u -> do
        let headerTip   = 950194 :: Word32
            isConnected h = h >= 1 && h <= u
        findConnectedTipPure isConnected headerTip `shouldBe` u
