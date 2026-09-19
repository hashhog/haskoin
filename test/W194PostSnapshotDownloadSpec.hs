{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Post-snapshot catch-up: the gap-kicker is the sole block requester,
-- and a restart must reload headers persisted ABOVE the connected tip.
--
-- Live 2026-09-19 after 2ab99af (receipt
-- haskoin-2ab99af-deployed-spread-works-blocks-still-zero-2026-09-19):
--
--   * "Loaded 910120 headers from database" then 29 × 2000-header
--     batches, on a node whose header chain had already reached 967631
--     before the restart. PrefixBlockHeader rows were on disk; the
--     reload walked bhPrevBlock from PrefixBestBlock (the UTXO tip)
--     and dropped everything above it.
--   * Every getdata this run came from the block-gap kicker
--     ("Block-gap kicker: pipelining …"). Sync.startIBD is never
--     called from app/Main.hs — that is a design finding, not a bug.
--   * After headers re-caught-up, every v2 pipeline head looked mute
--     at 16s: receiveV1 stamps first-byte on command=="block" before
--     the payload; receiveV2 never stamped, so mutePipelineHeads
--     rotated peers mid-transfer (HARD STALL, "thread killed").
--
-- Controls:
--   * collectPersistedHeadersAbove from connected tip 10 with headers
--     0..20 on disk returns 11..20 (pre-fix: [])
--   * a hole / prev-unlink stops the walk (stale height-index pocket)
--   * v2PacketLooksLikeBlock is True for a block-sized length prefix
--     and False for a max 2000-header batch (pre-fix: always False)
module W194PostSnapshotDownloadSpec (spec) where

import Test.Hspec
import Control.Monad (forM_)
import Data.Word (Word32)
import qualified Data.ByteString as BS
import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
  ( BlockHash (..), Hash256 (..), BlockHeader (..)
  )
import Haskoin.Crypto (computeBlockHash)
import Haskoin.Storage
  ( HaskoinDB
  , defaultDBConfig, withDB
  , putBlockHeader, putBlockHeight
  , collectPersistedHeadersAbove
  )
import Haskoin.Network
  ( v2BlockFirstByteMinLen
  , v2PacketLooksLikeBlock
  , blockFirstByteTimeout
  , PipelineInflight (..)
  , mutePipelineHeads
  )

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

zeroHash :: Hash256
zeroHash = Hash256 (BS.replicate 32 0)

mkHdr :: BlockHash -> Word32 -> Word32 -> BlockHeader
mkHdr prev ts nonce =
  BlockHeader
    { bhVersion    = 1
    , bhPrevBlock  = prev
    , bhMerkleRoot = zeroHash
    , bhTimestamp  = ts
    , bhBits       = 0x1d00ffff
    , bhNonce      = nonce
    }

-- | Genesis + n linked children. Returns (genesisHash, rows 0..n).
chainUpTo :: Word32 -> (BlockHash, [(Word32, BlockHash, BlockHeader)])
chainUpTo n =
  let genesisHdr  = mkHdr (BlockHash zeroHash) 1231006505 0
      genesisHash = computeBlockHash genesisHdr
      loop h prev acc
        | h > n     = (genesisHash, reverse acc)
        | otherwise =
            let hdr = mkHdr prev (1231006505 + h) h
                hh  = computeBlockHash hdr
             in loop (h + 1) hh ((h, hh, hdr) : acc)
   in loop 1 genesisHash [(0, genesisHash, genesisHdr)]

withTestDB :: String -> (HaskoinDB -> IO a) -> IO a
withTestDB tag action =
  withSystemTempDirectory ("haskoin-w194-" ++ tag) $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) action

persistChain
  :: HaskoinDB
  -> [(Word32, BlockHash, BlockHeader)]
  -> IO ()
persistChain db rows =
  forM_ rows $ \(h, hh, hdr) -> do
    putBlockHeader db hh hdr
    putBlockHeight db h hh

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do
  describe "reload walks headers persisted above the connected tip" $ do
    it "returns 11..20 when best-block is 10 and 0..20 are on disk" $
      withTestDB "above-tip" $ \db -> do
        let (_, rows) = chainUpTo 20
            Just (_, h10, _) = lookupRow 10 rows
        persistChain db rows
        above <- collectPersistedHeadersAbove db 10 h10
        map fst above `shouldBe` [ hh | (h, hh, _) <- rows, h >= 11 ]
        length above `shouldBe` 10

    it "stops at a hole in the height index" $
      withTestDB "hole" $ \db -> do
        let (_, rows) = chainUpTo 20
            kept = filter (\(h, _, _) -> h /= 15) rows
            Just (_, h10, _) = lookupRow 10 rows
        persistChain db kept
        above <- collectPersistedHeadersAbove db 10 h10
        -- 11..14 contiguous, 15 missing -> stop
        length above `shouldBe` 4
        let heights = [11, 12, 13, 14]
        map fst above `shouldBe` [ hh | (h, hh, _) <- rows, h `elem` heights ]

    it "stops at a prev-unlink (stale height-index pocket)" $
      withTestDB "unlink" $ \db -> do
        let (_, rows) = chainUpTo 20
            Just (_, h10, _) = lookupRow 10 rows
            -- Plant a header at 15 that does not link to 14.
            bogus = mkHdr (BlockHash (Hash256 (BS.replicate 32 0xab))) 9 99
            bogusH = computeBlockHash bogus
            patched =
              [ if h == 15 then (15, bogusH, bogus) else row
              | row@(h, _, _) <- rows
              ]
        persistChain db patched
        above <- collectPersistedHeadersAbove db 10 h10
        length above `shouldBe` 4  -- 11..14, stop before 15

    it "returns empty when nothing is persisted above the tip" $
      withTestDB "empty" $ \db -> do
        let (_, rows) = chainUpTo 10
            Just (_, h10, _) = lookupRow 10 rows
        persistChain db rows
        above <- collectPersistedHeadersAbove db 10 h10
        above `shouldBe` []

  describe "v2 first-byte stamp matches v1 command==block" $ do
    it "a max 2000-header batch is not a block-sized v2 packet" $ do
      -- 2000 * 81 = 162000 plus compact-size overhead, well under 200000
      v2PacketLooksLikeBlock 162000 `shouldBe` False
      v2PacketLooksLikeBlock (v2BlockFirstByteMinLen - 1) `shouldBe` False

    it "a 1 MB block length-prefix stamps first-byte (not mute at 16s)" $ do
      v2PacketLooksLikeBlock v2BlockFirstByteMinLen `shouldBe` True
      v2PacketLooksLikeBlock 1000000 `shouldBe` True
      blockFirstByteTimeout `shouldBe` 16

    it "a v2 peer with first-byte stamped is not mute at t=17" $ do
      let inf =
            [ PipelineInflight 0 910121 0 (Just 1)
            , PipelineInflight 0 910122 0 Nothing
            ]
          (peers, heights) = mutePipelineHeads 17 inf
      peers `shouldBe` []
      heights `shouldBe` []

    it "a v2 peer with no first-byte stamp IS mute at t=17 (the live stall)" $ do
      let inf = [ PipelineInflight 0 910121 0 Nothing ]
          (peers, heights) = mutePipelineHeads 17 inf
      peers `shouldBe` [0]
      heights `shouldBe` [910121]

lookupRow :: Word32 -> [(Word32, BlockHash, BlockHeader)] -> Maybe (Word32, BlockHash, BlockHeader)
lookupRow h rows = case [ r | r@(h', _, _) <- rows, h' == h ] of
  (x:_) -> Just x
  []    -> Nothing
