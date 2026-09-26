{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W204 getdata / tx-fetch Core parity (BIP-339 wtxid relay, BIP-144).
--
-- Reference: bitcoin-core/src/net_processing.cpp
--   * ProcessGetData: @maybe_with_witness = inv.IsMsgTx() ? TX_NO_WITNESS
--     : TX_WITH_WITNESS@ — MSG_TX is served stripped, MSG_WTX and
--     MSG_WITNESS_TX with witness; FindTxForGetData resolves a MSG_WTX hash
--     as a WTXID.  Unserveable items are batched into one notfound.
--   * ProcessGetBlockData: MSG_BLOCK -> TX_NO_WITNESS(*pblock),
--     MSG_WITNESS_BLOCK -> TX_WITH_WITNESS(*pblock).
--   * SendMessages tx fetch: @gtxid.IsWtxid() ? MSG_WTX : (MSG_TX |
--     GetFetchFlags(peer))@.
--
-- Pre-fix haskoin (a) answered MSG_WTX with notfound (only MSG_TX /
-- MSG_WITNESS_TX were handled, both by txid), so Core — which always fetches
-- a wtxidrelay peer's announcements by wtxid — never received a segwit tx
-- from haskoin; (b) fetched a peer's MSG_WTX announcement as
-- MSG_WITNESS_TX with the WTXID in the txid slot, so Core replied notfound
-- and haskoin never received a segwit tx from Core; (c) served MSG_TX and
-- MSG_BLOCK with witness data.
module W204GetDataWtxSpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Serialize (encode)
import Data.Word (Word32)
import Test.Hspec

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeWtxid)
import Haskoin.Network hiding (computeWtxid)

segwitTx :: Word32 -> Tx
segwitTx n = Tx
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
  , blockTxns = [segwitTx 1, segwitTx 2]
  }

-- | Serve against a one-tx mempool and a one-block store.
serve :: [InvVector] -> IO [Message]
serve = serveGetData byTxid byWtxid byBlock
  where
    tx = segwitTx 0
    byTxid t   = pure (Map.lookup t (Map.fromList [(computeTxId tx, tx)]))
    byWtxid w  = pure (Map.lookup w (Map.fromList [(computeWtxid tx, tx)]))
    byBlock h  = pure (if h == BlockHash (Hash256 (BS.replicate 32 0xbb)) then Just theBlock else Nothing)

txidH, wtxidH, blockH, missH :: Hash256
txidH  = getTxIdHash  (computeTxId  (segwitTx 0))
wtxidH = getWtxidHash (computeWtxid (segwitTx 0))
blockH = Hash256 (BS.replicate 32 0xbb)
missH  = Hash256 (BS.replicate 32 0xee)

-- | Does a serialized tx carry the BIP-144 marker/flag after nVersion?
hasWitnessMarker :: BS.ByteString -> Bool
hasWitnessMarker bs = BS.take 2 (BS.drop 4 bs) == BS.pack [0x00, 0x01]

spec :: Spec
spec = describe "W204 getdata / tx-fetch Core parity" $ do
  it "fixture sanity: the segwit tx has txid /= wtxid" $
    txidH `shouldNotBe` wtxidH

  it "MSG_WTX + wtxid is served (not notfound), with witness" $ do
    r <- serve [InvVector InvWtx wtxidH]
    case r of
      [MTx t] -> do
        encode t `shouldBe` encode (segwitTx 0)
        hasWitnessMarker (encode t) `shouldBe` True
      other -> expectationFailure ("expected [MTx], got " ++ show (map commandName other))

  it "MSG_WTX carrying a txid is notfound (the hash is a wtxid)" $ do
    r <- serve [InvVector InvWtx txidH]
    r `shouldBe` [MNotFound (NotFound [InvVector InvWtx txidH])]

  it "MSG_TX + txid is served WITHOUT witness (TX_NO_WITNESS)" $ do
    r <- serve [InvVector InvTx txidH]
    case r of
      [MTx t] -> do
        hasWitnessMarker (encode t) `shouldBe` False
        computeTxId t `shouldBe` TxId txidH
        -- stripped serialization == the bytes the txid commits to
        getWtxidHash (computeWtxid t) `shouldBe` txidH
      other -> expectationFailure ("expected [MTx], got " ++ show (map commandName other))

  it "MSG_WITNESS_TX + txid is served WITH witness" $ do
    r <- serve [InvVector InvWitnessTx txidH]
    map (fmap encode . asTx) r `shouldBe` [Just (encode (segwitTx 0))]

  it "MSG_BLOCK is served WITHOUT witness (TX_NO_WITNESS(*pblock))" $ do
    r <- serve [InvVector InvBlock blockH]
    case r of
      [MBlock b] -> do
        map (hasWitnessMarker . encode) (blockTxns b) `shouldBe` [False, False]
        blockHeader b `shouldBe` blockHeader theBlock
      other -> expectationFailure ("expected [MBlock], got " ++ show (map commandName other))

  it "MSG_WITNESS_BLOCK is served WITH witness" $ do
    r <- serve [InvVector InvWitnessBlock blockH]
    case r of
      [MBlock b] -> encode b `shouldBe` encode theBlock
      other -> expectationFailure ("expected [MBlock], got " ++ show (map commandName other))

  it "unserveable items are batched into ONE notfound after the served replies" $ do
    let ivs = [ InvVector InvTx missH, InvVector InvWtx wtxidH
              , InvVector InvWtx missH, InvVector InvBlock missH
              , InvVector InvCompactBlock blockH ]
    r <- serve ivs
    map commandName r `shouldBe` ["tx", "notfound"]
    last r `shouldBe` MNotFound (NotFound [ InvVector InvTx missH, InvVector InvWtx missH
                                          , InvVector InvBlock missH, InvVector InvCompactBlock blockH ])

  it "no notfound when everything is served" $ do
    r <- serve [InvVector InvWtx wtxidH, InvVector InvTx txidH]
    map commandName r `shouldBe` ["tx", "tx"]

  describe "txFetchInv (requesting an announced tx)" $ do
    it "a MSG_WTX announcement is fetched as MSG_WTX with the same hash" $
      txFetchInv (InvVector InvWtx wtxidH) `shouldBe` InvVector InvWtx wtxidH
    it "a MSG_TX announcement is fetched as MSG_WITNESS_TX" $
      txFetchInv (InvVector InvTx txidH) `shouldBe` InvVector InvWitnessTx txidH
  where
    asTx (MTx t) = Just t
    asTx _       = Nothing
