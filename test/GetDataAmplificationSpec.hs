{-# LANGUAGE CPP #-}
-- | secfix-haskoin-getdata-amplification (C2).
--
-- One @getdata@ naming the same witness block 50,000 times used to make
-- 'serveGetDataCompact' load and keep all 50,000 replies (a @forM@ over the
-- whole request) before the first one went to the socket: a 1.8 MB message
-- grew the node to 9.6 GB RSS.
--
-- Core (net_processing.cpp ProcessGetData) works through the request one
-- item at a time and stops while the peer's send buffer is full
-- (@fPauseSend@), so at most one reply is ever held.  The fix serves the
-- request through 'serveGetDataStream': each reply is handed to the peer's
-- socket before the next item is looked up, a failed send stops the loop,
-- and an item that repeats one already served in the same request is
-- skipped.
--
-- The streaming tests call 'serveGetDataStream', which the fix adds.  They
-- sit behind @HASKOIN_GETDATA_STREAM@, which the fix commit sets in this
-- suite's cabal stanza (the Haskell stand-in for a @when declared@ guard:
-- Template Haskell cannot load the haskoin library here because of the
-- libzmq shared object).  Without it this file still compiles and each
-- streaming test fails on its assertion.
module GetDataAmplificationSpec (spec) where

import Data.IORef
import qualified Data.ByteString as BS
import Data.Word (Word32)
import Test.Hspec

import Haskoin.Types
import Haskoin.Network

-- | A small, real block (one coinbase) so the replies are genuine 'MBlock's.
mkBlock :: Word32 -> Block
mkBlock n = Block
  { blockHeader = BlockHeader
      { bhVersion    = 0x20000000
      , bhPrevBlock  = BlockHash (Hash256 (BS.replicate 32 0))
      , bhMerkleRoot = Hash256 (BS.replicate 32 1)
      , bhTimestamp  = 1700000000
      , bhBits       = 0x207fffff
      , bhNonce      = n
      }
  , blockTxns = [coinbase]
  }
  where
    coinbase = Tx
      { txVersion  = 2
      , txInputs   = [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff)
                           (BS.pack [0x01, fromIntegral n]) 0xffffffff]
      , txOutputs  = [TxOut 5000000000 (BS.pack [0x51])]
      , txWitness  = [[BS.replicate 32 0]]
      , txLockTime = 0
      }

hashN :: Int -> Hash256
hashN i = Hash256 (BS.pack [fromIntegral (i `div` 256), fromIntegral (i `mod` 256)]
                   <> BS.replicate 30 7)

witnessBlockInv :: Hash256 -> InvVector
witnessBlockInv = InvVector InvWitnessBlock

-- | A block store that serves every hash and counts lookups.
countingStore :: IO (IORef Int, BlockHash -> IO (Maybe Block))
countingStore = do
  calls <- newIORef (0 :: Int)
  let getBlk _ = do
        modifyIORef' calls (+ 1)
        n <- readIORef calls
        return (Just (mkBlock (fromIntegral n)))
  return (calls, getBlk)

noTx :: a -> IO (Maybe Tx)
noTx _ = return Nothing

noDepth :: BlockHash -> IO (Maybe Int)
noDepth _ = return Nothing

-- | @Just stream@ when this commit has 'serveGetDataStream'.
streamImpl
  :: Maybe ((BlockHash -> IO (Maybe Int))
            -> (TxId -> IO (Maybe Tx))
            -> (Wtxid -> IO (Maybe Tx))
            -> (BlockHash -> IO (Maybe Block))
            -> (Message -> IO Bool)
            -> [InvVector]
            -> IO ())
#ifdef HASKOIN_GETDATA_STREAM
streamImpl = Just serveGetDataStream
#else
streamImpl = Nothing
#endif

withStream
  :: (((BlockHash -> IO (Maybe Int))
       -> (TxId -> IO (Maybe Tx))
       -> (Wtxid -> IO (Maybe Tx))
       -> (BlockHash -> IO (Maybe Block))
       -> (Message -> IO Bool)
       -> [InvVector]
       -> IO ()) -> Expectation)
  -> Expectation
withStream k = case streamImpl of
  Nothing -> expectationFailure
    ("no serveGetDataStream on this commit: getdata replies are built "
     ++ "as one list before any is sent")
  Just s  -> k s

spec :: Spec
spec = describe "getdata amplification (C2)" $ do

  it "getdata_dupes_bounded_memory" $ do
    -- 50,000 identical witness-block items (the wire maximum, MAX_INV_SZ).
    (calls, getBlk) <- countingStore
    let ivs = replicate 50000 (witnessBlockInv (hashN 1))
    replies <- serveGetDataCompact noDepth noTx noTx getBlk ivs
    n <- readIORef calls
    -- The repeated item is served once: one store read, one reply.
    n `shouldBe` 1
    length replies `shouldBe` 1
    case replies of
      [MBlock _] -> return ()
      other      -> expectationFailure ("expected one block, got "
                                        ++ show (length other) ++ " replies")

  it "getdata_dupes_bounded_memory_stream" $ withStream $ \stream -> do
    -- The same request through the path the node uses: one block out, the
    -- other 49,999 copies never loaded.
    (calls, getBlk) <- countingStore
    sent <- newIORef (0 :: Int)
    stream noDepth noTx noTx getBlk (\_ -> modifyIORef' sent (+ 1) >> return True)
           (replicate 50000 (witnessBlockInv (hashN 1)))
    readIORef calls `shouldReturn` 1
    readIORef sent  `shouldReturn` 1

  it "getdata_serves_one_item_at_a_time" $ withStream $ \stream -> do
    -- 2,000 DISTINCT blocks: dedupe does not help, so the bound has to come
    -- from serving lazily.  At every send at most one looked-up reply may be
    -- waiting (the one being sent).
    (calls, getBlk) <- countingStore
    sent <- newIORef (0 :: Int)
    maxAhead <- newIORef (0 :: Int)
    let send _ = do
          c <- readIORef calls
          s <- readIORef sent
          modifyIORef' maxAhead (max (c - s))
          writeIORef sent (s + 1)
          return True
    stream noDepth noTx noTx getBlk send (map (witnessBlockInv . hashN) [1 .. 2000])
    readIORef sent     `shouldReturn` 2000
    readIORef maxAhead `shouldReturn` 1

  it "getdata_stops_when_send_fails" $ withStream $ \stream -> do
    -- Core stops serving while fPauseSend / once the peer disconnects; a
    -- send that fails (peer gone or stalled past the send timeout) must not
    -- cost a store read for every remaining item.
    (calls, getBlk) <- countingStore
    sent <- newIORef (0 :: Int)
    let send _ = do
          modifyIORef' sent (+ 1)
          s <- readIORef sent
          return (s < 3)
    stream noDepth noTx noTx getBlk send (map (witnessBlockInv . hashN) [1 .. 1000])
    readIORef sent  `shouldReturn` 3
    readIORef calls `shouldReturn` 3

  it "getdata_keeps_order_and_batched_notfound" $ withStream $ \stream -> do
    -- Order is the request order; unserveable items (here: a tx we do not
    -- have, repeated) go into ONE trailing notfound, each listed once.
    (_, getBlk) <- countingStore
    out <- newIORef []
    let txIv = InvVector InvWitnessTx (hashN 9)
        ivs  = [witnessBlockInv (hashN 1), txIv, witnessBlockInv (hashN 2), txIv
               , witnessBlockInv (hashN 1)]
    stream noDepth noTx noTx getBlk (\m -> modifyIORef' out (m :) >> return True) ivs
    msgs <- reverse <$> readIORef out
    map tag msgs `shouldBe` ["block", "block", "notfound"]
    case last msgs of
      MNotFound (NotFound nf) -> nf `shouldBe` [txIv]
      _                       -> expectationFailure "no trailing notfound"

  it "distinct item types for one hash are both served" $ do
    -- MSG_BLOCK and MSG_WITNESS_BLOCK of one hash are different replies
    -- (with and without witness): dedupe is by (type, hash).
    (calls, getBlk) <- countingStore
    let h = hashN 5
    replies <- serveGetDataCompact noDepth noTx noTx getBlk
                 [InvVector InvBlock h, InvVector InvWitnessBlock h]
    length replies `shouldBe` 2
    readIORef calls `shouldReturn` 2
  where
    tag m = case m of
      MBlock _    -> "block"
      MNotFound _ -> "notfound"
      _           -> "other" :: String
