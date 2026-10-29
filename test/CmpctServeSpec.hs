{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | BIP-152 serving: getdata(MSG_CMPCT_BLOCK) -> cmpctblock, getblocktxn ->
-- blocktxn (Core net_processing.cpp ProcessGetBlockData IsMsgCmpctBlk arm,
-- NetMsgType::GETBLOCKTXN / SendBlockTransactions).
--
-- Pre-fix haskoin answered MSG_CMPCT_BLOCK with the full block, so a Core
-- peer that asked for a compact block never got one and, having requested it,
-- stayed stuck one block behind (conformance-scenarios.py SERVE).
module CmpctServeSpec (spec) where

import qualified Data.ByteString as BS
import Data.Word (Word32)
import Test.Hspec

import Haskoin.Types
import Haskoin.Crypto (computeTxId)
import Haskoin.Network hiding (computeWtxid)
import qualified Haskoin.Network as N

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

hashA :: Hash256
hashA = Hash256 (BS.replicate 32 0xbb)

kind :: Message -> String
kind (MCmpctBlock _) = "cmpctblock"
kind (MBlock _)      = "block"
kind (MBlockTxn _)   = "blocktxn"
kind _               = "other"

serveAt :: Maybe Int -> InvType -> IO [Message]
serveAt depth t = serveGetDataCompact
  (const (pure depth)) (const (pure Nothing)) (const (pure Nothing))
  (\h -> pure (if h == BlockHash hashA then Just theBlock else Nothing))
  [InvVector t hashA]

spec :: Spec
spec = describe "BIP-152 serving (cmpctblock / blocktxn)" $ do
  it "getdata MSG_CMPCT_BLOCK at the tip is answered with a cmpctblock" $ do
    r <- serveAt (Just 0) InvCompactBlock
    case r of
      [MCmpctBlock cb] -> do
        cbHeader cb `shouldBe` blockHeader theBlock
        -- coinbase (tx 0) prefilled at index 0, the rest as 48-bit short ids
        map ptIndex (cbPrefilled cb) `shouldBe` [0]
        map ptTx (cbPrefilled cb) `shouldBe` [mkTx 1]
        let key = computeShortIdKey (cbHeader cb) (cbNonce cb)
        cbShortIds cb `shouldBe`
          [ computeShortId key (getHash256 (N.computeWtxid t)) | t <- [mkTx 2, mkTx 3] ]
        all (< 2 ^ (48 :: Int)) (cbShortIds cb) `shouldBe` True
      other -> expectationFailure ("expected one cmpctblock, got " ++ show (map kind other))

  it "getdata MSG_CMPCT_BLOCK exactly MAX_CMPCTBLOCK_DEPTH deep is still compact" $ do
    r <- serveAt (Just maxCmpctBlockDepth) InvCompactBlock
    map kind r `shouldBe` ["cmpctblock"]

  it "getdata MSG_CMPCT_BLOCK beyond MAX_CMPCTBLOCK_DEPTH falls back to the full block" $ do
    r <- serveAt (Just (maxCmpctBlockDepth + 1)) InvCompactBlock
    r `shouldBe` [MBlock theBlock]

  it "getdata MSG_CMPCT_BLOCK for a block off the active chain falls back to the full block" $ do
    r <- serveAt Nothing InvCompactBlock
    r `shouldBe` [MBlock theBlock]

  it "getdata MSG_CMPCT_BLOCK for an unknown block is notfound" $ do
    r <- serveGetDataCompact (const (pure (Just 0))) (const (pure Nothing))
           (const (pure Nothing)) (const (pure Nothing))
           [InvVector InvCompactBlock hashA]
    r `shouldBe` [MNotFound (NotFound [InvVector InvCompactBlock hashA])]

  it "plain serveGetData (no depth source) still answers MSG_CMPCT_BLOCK with the full block" $ do
    r <- serveGetData (const (pure Nothing)) (const (pure Nothing))
           (\_ -> pure (Just theBlock)) [InvVector InvCompactBlock hashA]
    r `shouldBe` [MBlock theBlock]

  describe "getblocktxn" $ do
    let bh  = BlockHash hashA
        req = GetBlockTxn bh
    it "serves the requested transactions in request order" $
      serveGetBlockTxn (Just 0) (req [2, 1]) (Just theBlock)
        `shouldBe` Right [MBlockTxn (BlockTxn bh [mkTx 3, mkTx 2])]
    it "serves blocktxn exactly MAX_BLOCKTXN_DEPTH deep" $
      serveGetBlockTxn (Just maxBlocktxnDepth) (req [1]) (Just theBlock)
        `shouldBe` Right [MBlockTxn (BlockTxn bh [mkTx 2])]
    it "sends the full block (not blocktxn, not a getdata) beyond MAX_BLOCKTXN_DEPTH" $
      serveGetBlockTxn (Just (maxBlocktxnDepth + 1)) (req [1]) (Just theBlock)
        `shouldBe` Right [MBlock theBlock]
    it "rejects an out-of-bound index (Core: Misbehaving)" $
      serveGetBlockTxn (Just 0) (req [1, 3]) (Just theBlock)
        `shouldSatisfy` either (const True) (const False)
    it "sends nothing when the block is not available" $
      serveGetBlockTxn (Just 0) (req [0]) Nothing `shouldBe` Right []
