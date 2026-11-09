{-# LANGUAGE NumericUnderscores #-}

-- | secfix-haskoin-getblocktxn-index-wrap (finding C3).
--
-- A getblocktxn index list is differentially encoded: each varint is the gap
-- since the previous index plus one.  Core decodes the gaps into a uint64
-- running shift and throws "differential value overflow" the moment the shift
-- leaves uint16 (bitcoin-core/src/blockencodings.h DifferenceFormatter::Unser),
-- so decoded indexes are always strictly increasing and below 65536.
--
-- Pre-fix haskoin truncated each gap to Word16 before adding, so a gap of
-- 0xffff wrapped (prev + 0xffff + 1 == prev mod 2^16): a 60 KB request of
-- 20,000 such gaps decoded to the same index 20,000 times, and the serving
-- path built a blocktxn holding that many copies of one transaction.
module GetBlockTxnIndexWrapSpec (spec) where

import qualified Data.ByteString as BS
import Data.Serialize (runGet, runPut, put, putWord8, putWord16le, get)
import Data.Word (Word32)
import Test.Hspec

import Haskoin.Types
import Haskoin.Network hiding (computeWtxid)

mkTx :: Word32 -> Tx
mkTx n = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 7))) n
                        , txInScript     = BS.empty
                        , txInSequence   = 0xFFFFFFFD } ]
  , txOutputs  = [ TxOut { txOutValue = 1_000, txOutScript = BS.pack (0x00 : 0x14 : replicate 20 9) } ]
  , txWitness  = [[BS.replicate 71 0x30, BS.replicate 33 0x02]]
  , txLockTime = 0
  }

theBlock :: Block
theBlock = Block
  { blockHeader = BlockHeader 0x20000000 (BlockHash (Hash256 (BS.replicate 32 0)))
                    (Hash256 (BS.replicate 32 1)) 0 0x207fffff 0
  , blockTxns = [mkTx 1, mkTx 2, mkTx 3]
  }

bh :: BlockHash
bh = BlockHash (Hash256 (BS.replicate 32 0xbb))

-- | Raw getblocktxn payload: block hash, CompactSize count, CompactSize gaps.
rawRequest :: Int -> [Int] -> BS.ByteString
rawRequest count gaps = runPut $ do
  put bh
  compact count
  mapM_ compact gaps
  where
    compact n
      | n < 0xfd   = putWord8 (fromIntegral n)
      | n <= 0xffff = putWord8 0xfd >> putWord16le (fromIntegral n)
      | otherwise  = error "test helper: gap too large"

decodeGbt :: BS.ByteString -> Either String GetBlockTxn
decodeGbt = runGet get

isLeft' :: Either a b -> Bool
isLeft' = either (const True) (const False)

spec :: Spec
spec = describe "getblocktxn index decoding (C3)" $ do
  it "getblocktxn_wrapping_delta_rejected" $ do
    -- 0, then 999 gaps of 0xffff: every gap overflows the 16-bit index space.
    decodeGbt (rawRequest 1000 (0 : replicate 999 0xffff))
      `shouldSatisfy` isLeft'
    -- A request whose decoded indexes repeat must not be served: Core can
    -- never decode one, so serving it is a reply Core would not send.
    serveGetBlockTxn (Just 0) (GetBlockTxn bh [1, 1, 1]) (Just theBlock)
      `shouldSatisfy` isLeft'

  it "rejects the first gap that pushes the index past 0xffff" $ do
    -- 0xfffe then gap 0 -> 0xffff: still in range (Core accepts).
    fmap gbtIndexes (decodeGbt (rawRequest 2 [0xfffe, 0]))
      `shouldBe` Right [0xfffe, 0xffff]
    -- 0xffff then gap 0 -> 0x10000: Core "differential value overflow".
    decodeGbt (rawRequest 2 [0xffff, 0]) `shouldSatisfy` isLeft'

  it "rejects a non-increasing index list when serving" $
    serveGetBlockTxn (Just 0) (GetBlockTxn bh [2, 1]) (Just theBlock)
      `shouldSatisfy` isLeft'

  it "still decodes and serves a well-formed request" $ do
    let raw = rawRequest 2 [0, 1]   -- indexes 0, 2
    fmap gbtIndexes (decodeGbt raw) `shouldBe` Right [0, 2]
    case decodeGbt raw of
      Left e -> expectationFailure e
      Right g -> serveGetBlockTxn (Just 0) g (Just theBlock)
        `shouldBe` Right [MBlockTxn (BlockTxn bh [mkTx 1, mkTx 3])]

  it "round-trips the largest legal request (65536 indexes)" $ do
    let g = GetBlockTxn bh [0 .. 0xffff]
    fmap gbtIndexes (decodeGbt (runPut (put g))) `shouldBe` Right [0 .. 0xffff]
