{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | gate-6, fix-only API (this module does not compile on the
-- "5668c1b + hooks" tree: the Internal outcome, the retry and the fatal
-- latch do not exist there).
--
--   G6-HK-3b an Internal script outcome is retried once on the serial path;
--            a one-off fault then validates OK (and proves the retry really
--            re-validates instead of re-reading a cached result).
--   G6-HK-3c a fault that persists latches the node (AbortNode): no
--            verdict, no mark, nothing validated afterwards, submitblock and
--            generate answer -25, the mempool refuses.
--   G6-HK-7  flushCache writes before it forgets; a failed write keeps the
--            dirty set, retries once, then latches.
--   misc     serial path three outcomes; catchSync rethrows every async
--            type; Internal strings are never verdicts.
module Gate6PostSpec (spec) where

import Control.Concurrent.STM (atomically, modifyTVar', readTVarIO)
import Control.Exception
import Control.Monad (when)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Bits (shiftR, (.&.))
import Data.IORef
import Data.List (isInfixOf)
import qualified Data.Map.Strict as Map
import Data.Word (Word8, Word32)
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)
import Test.Hspec

import Haskoin.Types
import Haskoin.Crypto (computeBlockHash, computeTxId)
import Haskoin.Consensus
import Haskoin.Fatal
import Haskoin.Script (emptyFlags)
import Haskoin.Storage
  ( defaultDBConfig, withDB, Coin (..), getBlockStatus, HaskoinDB
  , newUTXOCache, addUTXO, flushCache, flushWriteHookRef, UTXOCache (..)
  , UTXOEntry (..), getUTXOCoin )
import Haskoin.Mempool (newMempool, defaultMempoolConfig, addTransaction, MempoolError (..))
import Haskoin.Rpc (submitBlockLeftResponse, generateErrorCode)

import Gate6Adapter (mblockValidate)

opTrue, opFalse :: ByteString
opTrue = BS.singleton 0x51
opFalse = BS.singleton 0x00

txidBytes :: Int -> ByteString
txidBytes i =
  let b k = fromIntegral ((i `shiftR` (8 * k)) .&. 0xff) :: Word8
  in BS.pack ([b 0, b 1, b 2, b 3] ++ replicate 28 0)

itemsOf :: [ByteString] -> [ScriptCheckItem]
itemsOf spks =
  let n = length spks
      tx = Tx 2
             [ TxIn (OutPoint (TxId (Hash256 (txidBytes (i + 1)))) 0) BS.empty 0xffffffff
             | i <- [0 .. n - 1] ]
             [TxOut 900 opTrue] (replicate n []) 7
  in [ ScriptCheckItem
         { sciTx = tx, sciInputIdx = i, sciPrevScript = spk, sciPrevValue = 100_000
         , sciSpentAmounts = replicate n 100_000, sciSpentScripts = spks }
     | (i, spk) <- zip [0 ..] spks ]

resetAll :: IO ()
resetAll = do
  writeIORef scriptItemHookRef (\_ _ _ -> return ())
  writeIORef masterStartHookRef (\_ -> return ())
  writeIORef masterWaitHookRef (return ())
  writeIORef flushWriteHookRef (return ())
  resetFatalLatchForTest

clean :: IO a -> IO a
clean act = (resetAll >> act) `finally` resetAll

nullOutPoint :: OutPoint
nullOutPoint = OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff

fundingOutPoint :: Int -> OutPoint
fundingOutPoint i = OutPoint (TxId (Hash256 (BS.replicate 31 0x5a `BS.snoc` fromIntegral i))) 0

mkSpendBlock :: BlockHash -> Word32 -> Int -> (Block, Map.Map OutPoint Coin)
mkSpendBlock prevHash ts nIn =
  let spend = Tx 1 [ TxIn (fundingOutPoint i) BS.empty 0xffffffff | i <- [0 .. nIn - 1] ]
                   [TxOut (fromIntegral nIn * 10_000 - 1_000) opTrue] (replicate nIn []) 0
      cb = Tx 1 [TxIn nullOutPoint (encodeBip34Height 1 `BS.snoc` 0x01) 0xffffffff]
              [TxOut 5_000_000_000 opTrue] [[]] 0
      txns = [cb, spend]
      hdr = BlockHeader 0x20000000 prevHash (computeMerkleRoot (map computeTxId txns))
                        ts 0x207fffff 0
      coins = Map.fromList [ (fundingOutPoint i, Coin (TxOut 10_000 opTrue) 0 False)
                           | i <- [0 .. nIn - 1] ]
  in (Block hdr txns, coins)

data Fx = Fx
  { fxDb :: HaskoinDB, fxHc :: HeaderChain, fxCs :: ChainState
  , fxMtp :: Word32 -> Word32, fxBlk :: Block, fxBh :: BlockHash
  , fxCoins :: Map.Map OutPoint Coin }

-- | Regtest genesis connected; block 1 (8 OP_TRUE spends) known as a header.
-- The global script queue runs with @par@ (extra = par-1 workers).
withFixture :: Int -> (Fx -> IO a) -> IO a
withFixture par body =
  withSystemTempDirectory "haskoin-gate6-post" $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      let net = regtest
          genesis = netGenesisBlock net
          gHash = computeBlockHash (blockHeader genesis)
          (blk, coins) = mkSpendBlock gHash (bhTimestamp (blockHeader genesis) + 600) 8
          bh = computeBlockHash (blockHeader blk)
      rG <- connectBlockAt db net genesis 0 Map.empty
      rG `shouldBe` Right ()
      hc <- initHeaderChain net
      let ce = ChainEntry { ceHeader = blockHeader blk, ceHash = bh, ceHeight = 1
                          , ceChainWork = 2 * headerWork (blockHeader blk)
                          , cePrev = Just gHash, ceStatus = StatusHeaderValid
                          , ceMedianTime = bhTimestamp (blockHeader blk), ceSequenceId = 5 }
      atomically $ modifyTVar' (hcEntries hc) (Map.insert bh ce)
      let cs = ChainState 0 gHash (headerWork (blockHeader genesis))
                          (bhTimestamp (blockHeader genesis)) (consensusFlagsAtHeight net 1)
          getMtp = const (bhTimestamp (blockHeader genesis))
      setConfiguredPar par
      _ <- startGlobalScriptCheckQueue
      body (Fx db hc cs getMtp blk bh coins) `finally` stopGlobalScriptCheckQueue

statusMem :: Fx -> IO (Maybe BlockStatus)
statusMem fx = fmap ceStatus . Map.lookup (fxBh fx) <$> readTVarIO (hcEntries (fxHc fx))

data MyAsync = MyAsync deriving Show
instance Exception MyAsync where
  toException = asyncExceptionToException
  fromException = asyncExceptionFromException

spec :: Spec
spec = describe "gate-6 (fix-only API)" $ do

  describe "G6-HK-3b Internal -> retry once on the serial path" $ do
    it "a one-off fault in the pool: the serial retry validates the block OK, no latch" $ clean $
      withFixture 4 $ \fx -> do
        calls <- newIORef (0 :: Int)
        modeRef <- newIORef ([] :: [Int])
        writeIORef scriptItemHookRef $ \jobSeq _ _ -> do
          n <- atomicModifyIORef' calls (\c -> (c + 1, c + 1))
          atomicModifyIORef' modeRef (\m -> (jobSeq : m, ()))
          when (n == 1) $ throwIO (ErrorCall "one-off fault")
        r <- mblockValidate (fxDb fx) regtest (fxHc fx) (fxCs fx) (fxMtp fx) (fxBlk fx) (fxBh fx) (fxCoins fx)
        r `shouldBe` Right ()
        isFatalLatched `shouldReturn` False
        statusMem fx `shouldReturn` Just StatusHeaderValid
        -- the retry really ran, and on the serial path (job sequence -1)
        seqs <- readIORef modeRef
        seqs `shouldSatisfy` elem (-1)
        n <- readIORef calls
        n `shouldSatisfy` (> 8)

    it "reorg-path wrapper (validateFullBlockFresh) re-validates on retry too" $ clean $
      withFixture 4 $ \fx -> do
        calls <- newIORef (0 :: Int)
        writeIORef scriptItemHookRef $ \_ _ _ -> do
          n <- atomicModifyIORef' calls (\c -> (c + 1, c + 1))
          when (n == 1) $ throwIO (ErrorCall "one-off fault")
        r <- validateBlockGuarded "reorg test"
               (validateFullBlockFresh regtest (fxCs fx) (fxMtp fx) False False (fxBlk fx) (fxCoins fx))
        r `shouldBe` Right ()
        isFatalLatched `shouldReturn` False

    it "a fault plus a genuinely invalid script: still a VERDICT (control)" $ clean $
      withFixture 4 $ \fx -> do
        let coinsBad = Map.adjust (\c -> c { coinTxOut = TxOut 10_000 opFalse })
                                  (fundingOutPoint 3) (fxCoins fx)
        calls <- newIORef (0 :: Int)
        writeIORef scriptItemHookRef $ \_ _ _ -> do
          n <- atomicModifyIORef' calls (\c -> (c + 1, c + 1))
          when (n == 1) $ throwIO (ErrorCall "one-off fault")
        r <- mblockValidate (fxDb fx) regtest (fxHc fx) (fxCs fx) (fxMtp fx) (fxBlk fx) (fxBh fx) coinsBad
        case r of
          Left err -> do
            err `shouldSatisfy` ("script verify failed" `isInfixOf`)
            classifyBlockReject err `shouldBe` BlockRejectVerdict
          Right () -> expectationFailure "invalid script accepted"
        isFatalLatched `shouldReturn` False
        statusMem fx `shouldReturn` Just StatusFailedValid

    it "control without any fault: an invalid script is a verdict and marks the block" $ clean $
      withFixture 4 $ \fx -> do
        let coinsBad = Map.adjust (\c -> c { coinTxOut = TxOut 10_000 opFalse })
                                  (fundingOutPoint 5) (fxCoins fx)
        r <- mblockValidate (fxDb fx) regtest (fxHc fx) (fxCs fx) (fxMtp fx) (fxBlk fx) (fxBh fx) coinsBad
        fmap (const ()) r `shouldSatisfy` either ("script verify failed (input 5)" `isInfixOf`) (const False)
        statusMem fx `shouldReturn` Just StatusFailedValid
        getBlockStatus (fxDb fx) (fxBh fx) `shouldReturn` Just StatusFailedValid

  describe "G6-HK-3c a persistent fault latches the node (AbortNode)" $
    it "no verdict, no mark, nothing validated after, -25 answers, mempool refuses" $ clean $
      withFixture 4 $ \fx -> do
        calls <- newIORef (0 :: Int)
        writeIORef scriptItemHookRef $ \_ _ i -> do
          atomicModifyIORef' calls (\c -> (c + 1, ()))
          when (i == 2) $ throwIO (ErrorCall "persistent fault")
        r <- mblockValidate (fxDb fx) regtest (fxHc fx) (fxCs fx) (fxMtp fx) (fxBlk fx) (fxBh fx) (fxCoins fx)
        err <- either return (const (fail "accepted under a persistent fault")) r
        err `shouldSatisfy` isInternalReject
        err `shouldNotSatisfy` ("script verify failed" `isInfixOf`)
        classifyBlockReject err `shouldBe` BlockRejectNonVerdict
        isFatalLatched `shouldReturn` True
        statusMem fx `shouldReturn` Just StatusHeaderValid
        getBlockStatus (fxDb fx) (fxBh fx) `shouldReturn` Nothing
        -- every connect entry checks the latch first: nothing is validated
        callsBefore <- readIORef calls
        r2 <- validateBlockGuarded "after latch"
                (validateFullBlockIO (fxDb fx) regtest (fxCs fx) (fxMtp fx) False (fxBlk fx) (fxCoins fx))
        callsAfter <- readIORef calls
        callsAfter `shouldBe` callsBefore
        r2 `shouldSatisfy` either isInternalReject (const False)
        -- submitblock / generate*: RPC_VERIFY_ERROR (-25), not a BIP22 reason
        fmap fst (either Just (const Nothing) (submitBlockLeftResponse err)) `shouldBe` Just (-25)
        fmap fst (either Just (const Nothing) (submitBlockLeftResponse (either id (const "") r2)))
          `shouldBe` Just (-25)
        generateErrorCode err `shouldBe` (-25)
        -- control: a real rejection keeps its BIP22 string
        submitBlockLeftResponse "Block validation failed: bad-cb-amount" `shouldSatisfy` either (const False) (const True)
        -- mempool refuses after the latch
        cache <- newUTXOCache (fxDb fx) 1000
        mp <- newMempool regtest cache defaultMempoolConfig 1 0 (\_ -> return 0)
        let tx = head (drop 1 (blockTxns (fxBlk fx)))
        mr <- addTransaction mp tx
        case mr of
          Left (ErrValidationFailed m) -> m `shouldSatisfy` isInternalReject
          other -> expectationFailure ("mempool accepted / wrong refusal after the latch: " ++ show other)

  describe "serial path: three outcomes" $ do
    it "a fault is Internal; a later real failure still wins (Fail over Internal)" $ clean $ do
      writeIORef scriptItemHookRef $ \_ _ i -> when (i == 1) $ throwIO (ErrorCall "boom")
      r1 <- evalChecksSerialIO emptyFlags (itemsOf (replicate 4 opTrue))
      r1 `shouldSatisfy` (\x -> case x of ScriptCheckInternal 1 _ -> True; _ -> False)
      r2 <- evalChecksSerialIO emptyFlags (itemsOf [opTrue, opTrue, opTrue, opFalse])
      r2 `shouldSatisfy` (\x -> case x of ScriptCheckFail 3 _ -> True; _ -> False)
    it "the pool combines the same way (Fail at 40 beats a fault at 7)" $ clean $ do
      writeIORef scriptItemHookRef $ \_ _ i -> when (i == 7) $ throwIO (ErrorCall "boom")
      q <- newScriptCheckQueue 3
      r <- runScriptCheckQueue q emptyFlags (itemsOf (replicate 40 opTrue ++ [opFalse] ++ replicate 20 opTrue))
      shutdownScriptCheckQueue q
      r `shouldSatisfy` (\x -> case x of ScriptCheckFail 40 _ -> True; _ -> False)
    it "an Internal result string is never a verdict" $ do
      let s = either id (const "") (scriptCheckResultToEither (ScriptCheckInternal 3 "input 3: boom"))
      s `shouldSatisfy` isInternalReject
      s `shouldNotSatisfy` ("script verify failed" `isInfixOf`)
      classifyBlockReject ("Core full-block validation: " ++ s) `shouldBe` BlockRejectNonVerdict

  describe "catchSync / trySync rethrow EVERY async type" $ do
    it "a non-AsyncException async (SomeAsyncException) is rethrown" $ do
      r <- try (catchSync (throwIO MyAsync) (\_ -> return ("swallowed" :: String)))
      fmap (const ()) r `shouldSatisfy` either (\e -> show (e :: SomeException) == "MyAsync") (const False)
    it "ThreadKilled is rethrown; a sync exception is handled" $ do
      r <- try (catchSync (throwIO ThreadKilled) (\_ -> return ("swallowed" :: String)))
      either (\e -> fromException e == Just ThreadKilled) (const False) (r :: Either SomeException String)
        `shouldBe` True
      r2 <- catchSync (throwIO (ErrorCall "x")) (\_ -> return ("handled" :: String))
      r2 `shouldBe` "handled"

  describe "G6-HK-7 flushCache: write before forget" $ do
    it "a failed write keeps the dirty set; retry once; second failure latches" $ clean $
      withSystemTempDirectory "haskoin-gate6-flush" $ \dir ->
        withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
          cache <- newUTXOCache db 1000
          let op = fundingOutPoint 9
          atomically $ addUTXO cache op (UTXOEntry (TxOut 777 opTrue) 5 False False)
          -- one failure: the retry writes it
          n <- newIORef (0 :: Int)
          writeIORef flushWriteHookRef $ do
            k <- atomicModifyIORef' n (\c -> (c + 1, c + 1))
            when (k == 1) $ throwIO (userError "disk full (injected)")
          flushCache cache
          isFatalLatched `shouldReturn` False
          fmap (fmap (txOutValue . coinTxOut)) (getUTXOCoin db op) `shouldReturn` Just 777
          Map.size <$> readTVarIO (ucDirty cache) `shouldReturn` 0
          -- persistent failure: exception, latch, dirty set KEPT
          let op2 = fundingOutPoint 10
          atomically $ addUTXO cache op2 (UTXOEntry (TxOut 888 opTrue) 6 False False)
          writeIORef flushWriteHookRef (throwIO (userError "disk full (injected)"))
          r <- try (flushCache cache)
          either (\(_ :: SomeException) -> True) (const False) r `shouldBe` True
          isFatalLatched `shouldReturn` True
          Map.member op2 <$> readTVarIO (ucDirty cache) `shouldReturn` True
          getUTXOCoin db op2 `shouldReturn` Nothing
          -- once the disk is back, a flush writes what was kept
          writeIORef flushWriteHookRef (return ())
          flushCache cache
          fmap (fmap (txOutValue . coinTxOut)) (getUTXOCoin db op2) `shouldReturn` Just 888

  describe "fixture sanity" $
    it "the fixture block validates with no hooks (control)" $ clean $
      withFixture 1 $ \fx -> do
        r <- mblockValidate (fxDb fx) regtest (fxHc fx) (fxCs fx) (fxMtp fx) (fxBlk fx) (fxBh fx) (fxCoins fx)
        r `shouldBe` Right ()
