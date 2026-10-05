{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | gate-6: a system fault during block validation is never a verdict.
-- Design: receipts/haskoin-gate6-design-2026-10-04.md (meta-repo).
--
-- This module is SHARED verbatim between the fix tree and a
-- "5668c1b + test hooks only" tree, so every example here must compile on
-- both. It uses only the hook API (scriptItemHookRef / masterStartHookRef /
-- masterWaitHookRef, HardStallView / hardStallFires) and 'Gate6Adapter',
-- which transcribes the MBlock handler's validate-then-mark step of the
-- tree it is built in (app/Main.hs is not importable from tests).
--
--   G6-HK-1  ThreadKilled inside the script queue must PROPAGATE, not become
--            "script verify failed (input i): thread killed" (a verdict).
--   G6-HK-2  end to end: a recv thread killed mid-validateFullBlock leaves no
--            failed mark (memory or disk) and the block still validates.
--   G6-HK-3a a synchronous throw inside a check is not a verdict.
--   G6-HK-4  F6: a killed master's stale workers must not let the NEXT job
--            return OK while one of its items is still unchecked (fail-open).
--   G6-HK-4b a worker that dies inside its batch (async) yields no verdict
--            and never OK.
--   G6-HK-5  HARD STALL predicate: never while the sole peer owes nothing
--            or is processing; still fires on a real owed-and-silent block.
--   G6-HK-6  BIP30 lookup: a present-but-undecodable coin row must not read
--            as "absent" = "no conflict" (fail-open). RUNS LAST: on the fix
--            tree it sets the process-wide fatal latch.
--
-- Control: cabal test gate6 --enable-tests (separate --builddir).
module Gate6Spec (spec) where

import Control.Concurrent
import Control.Exception
import Control.Monad (forM_, void, when, forever)
import Data.Bits (shiftR, (.&.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.IORef
import Data.List (isInfixOf, isPrefixOf)
import qualified Data.Map.Strict as Map
import Data.Word (Word8, Word32, Word64)
import Control.Concurrent.STM (atomically, modifyTVar', readTVarIO)
import System.Timeout (timeout)
import Test.Hspec

import Haskoin.Types
import Haskoin.Crypto (computeBlockHash, computeTxId)
import Haskoin.Consensus
import Haskoin.Script (emptyFlags)
import Haskoin.Network (HardStallView (..), hardStallFires)
import Haskoin.Storage (defaultDBConfig, withDB, Coin (..), getBlockStatus,
                        KeyPrefix (..), makeKey, WriteBatch (..), BatchOp (..), writeBatch)
import Data.Serialize (encode)
import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

import Gate6Adapter (mblockValidate)

--------------------------------------------------------------------------------
-- fixtures
--------------------------------------------------------------------------------

opTrue, opFalse :: ByteString
opTrue = BS.singleton 0x51
opFalse = BS.singleton 0x00

-- | <32-byte push> OP_HASH256{rounds} OP_DROP OP_TRUE (ParallelScriptSpec).
hashHeavyScript :: Int -> ByteString
hashHeavyScript rounds =
  BS.pack $ [0x20] ++ replicate 32 0x11 ++ replicate rounds 0xaa ++ [0x75, 0x51]

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

resetHooks :: IO ()
resetHooks = do
  writeIORef scriptItemHookRef (\_ _ _ -> return ())
  writeIORef masterStartHookRef (\_ -> return ())
  writeIORef masterWaitHookRef (return ())

withHooks :: IO a -> IO a
withHooks act = (resetHooks >> act) `finally` resetHooks

blockForever :: IO ()
blockForever = forever (threadDelay 1_000_000)

isThreadKilled :: SomeException -> Bool
isThreadKilled e = fromException e == Just ThreadKilled

-- | Run @act@ on a fresh thread; return its tid and an MVar with the outcome.
spawn :: IO a -> IO (ThreadId, MVar (Either SomeException a))
spawn act = do
  done <- newEmptyMVar
  tid <- forkIO (try act >>= putMVar done)
  return (tid, done)

await :: Int -> MVar a -> IO (Maybe a)
await secs v = timeout (secs * 1_000_000) (takeMVar v)

describeOutcome :: Show a => Maybe (Either SomeException a) -> String
describeOutcome Nothing = "timeout"
describeOutcome (Just (Left e)) = "exception: " ++ show e
describeOutcome (Just (Right r)) = "returned: " ++ show r

--------------------------------------------------------------------------------
-- G6-HK-2 fixture: one block on a connected regtest prefix
--------------------------------------------------------------------------------

nullOutPoint :: OutPoint
nullOutPoint = OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff

fundingOutPoint :: Int -> OutPoint
fundingOutPoint i = OutPoint (TxId (Hash256 (BS.replicate 31 0x5a `BS.snoc` fromIntegral i))) 0

coinbaseAt :: Word32 -> Word64 -> Tx
coinbaseAt h v = Tx 1 [TxIn nullOutPoint (encodeBip34Height h `BS.snoc` 0x01) 0xffffffff]
                     [TxOut v opTrue] [[]] 0

-- | Block at height 1 on regtest genesis: coinbase + one tx spending
-- @nIn@ fabricated OP_TRUE coins (non-coinbase, so no maturity rule).
mkSpendBlock :: BlockHash -> Word32 -> Int -> (Block, Map.Map OutPoint Coin)
mkSpendBlock prevHash ts nIn =
  let spend = Tx 1 [ TxIn (fundingOutPoint i) BS.empty 0xffffffff | i <- [0 .. nIn - 1] ]
                   [TxOut (fromIntegral nIn * 10_000 - 1_000) opTrue] (replicate nIn []) 0
      txns = [coinbaseAt 1 5_000_000_000, spend]
      hdr = BlockHeader 0x20000000 prevHash (computeMerkleRoot (map computeTxId txns))
                        ts 0x207fffff 0
      coins = Map.fromList [ (fundingOutPoint i, Coin (TxOut 10_000 opTrue) 0 False)
                           | i <- [0 .. nIn - 1] ]
  in (Block hdr txns, coins)

--------------------------------------------------------------------------------

spec :: Spec
spec = describe "gate-6: a fault during validation is never a verdict" $ do

  ------------------------------------------------------------------ G6-HK-1
  describe "G6-HK-1 ThreadKilled in the script queue propagates" $ do
    forM_ [0, 3] $ \extra ->
      it ("master killed inside an item check (extra=" ++ show extra
          ++ ") dies with ThreadKilled; no 'thread killed' verdict") $ withHooks $ do
        entered <- newEmptyMVar
        once <- newIORef True
        writeIORef scriptItemHookRef $ \_ isMaster _ ->
          if isMaster
            then do first <- atomicModifyIORef' once (\b -> (False, b))
                    when first $ void (tryPutMVar entered ()) >> blockForever
            else threadDelay 20_000          -- workers slow: master claims
        q <- newScriptCheckQueue extra
        (tid, done) <- spawn (runScriptCheckQueue q emptyFlags (itemsOf (replicate 64 opTrue)))
        Just () <- await 10 entered
        throwTo tid ThreadKilled
        r <- await 10 done
        resetHooks
        -- queue still usable: an invalid item is still a verdict (control)
        r2 <- timeout 10_000_000 $
                runScriptCheckQueue q emptyFlags (itemsOf (replicate 20 opTrue ++ [opFalse]))
        shutdownScriptCheckQueue q
        case r of
          Just (Left e) | isThreadKilled e -> return ()
          other -> expectationFailure ("expected the runner to die with ThreadKilled, got "
                                       ++ describeOutcome other)
        fmap show r2 `shouldSatisfy` maybe False ("ScriptCheckFail" `isPrefixOf`)

    it "hook-free: heavy items, kill after 200 ms -> ThreadKilled (negative control for the hook)" $ withHooks $ do
      q <- newScriptCheckQueue 0
      (tid, done) <- spawn (runScriptCheckQueue q emptyFlags (itemsOf (replicate 12_000 (hashHeavyScript 180))))
      threadDelay 200_000
      throwTo tid ThreadKilled
      r <- await 30 done
      shutdownScriptCheckQueue q
      case r of
        Just (Left e) | isThreadKilled e -> return ()
        other -> expectationFailure ("expected ThreadKilled, got " ++ describeOutcome other)

    it "chain proof (documents the pre-fix path): a 'thread killed' script string IS classified a verdict" $
      classifyBlockReject "Core full-block validation: script verify failed (input 0): thread killed"
        `shouldBe` BlockRejectVerdict

  ------------------------------------------------------------------ G6-HK-3a
  describe "G6-HK-3a a synchronous throw inside a check is not a verdict" $
    forM_ [0, 3] $ \extra ->
      it ("ErrorCall at idx 7 (extra=" ++ show extra ++ ") -> Internal, not Fail") $ withHooks $ do
        writeIORef scriptItemHookRef $ \_ _ i ->
          when (i == 7) $ throwIO (ErrorCall "injected fault")
        q <- newScriptCheckQueue extra
        r <- runScriptCheckQueue q emptyFlags (itemsOf (replicate 64 opTrue))
        shutdownScriptCheckQueue q
        show r `shouldSatisfy` ("ScriptCheckInternal" `isPrefixOf`)
        show r `shouldSatisfy` ("injected fault" `isInfixOf`)

  ------------------------------------------------------------------ G6-HK-4
  describe "G6-HK-4 F6: a killed master's stale workers cannot make the next job fail open" $ do
    it "job B does not return before its claimed invalid item is checked, and rejects it" $ withHooks $ do
      gA <- newEmptyMVar :: IO (MVar ())
      gB <- newEmptyMVar :: IO (MVar ())
      workerInA <- newEmptyMVar
      masterAtWait <- newEmptyMVar
      workerHasB0 <- newEmptyMVar
      seqRef <- newIORef (-1 :: Int)
      -- Job A (first job on a fresh queue) = sequence 1, B = 2.
      writeIORef scriptItemHookRef $ \jobSeq isMaster i -> do
        if not isMaster && jobSeq == 1
          then void (tryPutMVar workerInA ()) >> readMVar gA
          else if not isMaster && jobSeq == 2 && i == 0
            then void (tryPutMVar workerHasB0 ()) >> readMVar gB
            else if isMaster && jobSeq == 1
              then threadDelay 2_000        -- let both workers claim in A
              else return ()
      writeIORef masterWaitHookRef $ do
        s <- readIORef seqRef
        when (s == 1) $ void (tryPutMVar masterAtWait ()) >> blockForever
      writeIORef masterStartHookRef $ \jobSeq -> do
        writeIORef seqRef jobSeq
        -- B's master claims only after a worker holds B's first batch.
        when (jobSeq == 2) $ void (timeout 5_000_000 (readMVar workerHasB0))
      q <- newScriptCheckQueue 2
      (tidA, doneA) <- spawn (runScriptCheckQueue q emptyFlags (itemsOf (replicate 64 opTrue)))
      Just () <- await 10 workerInA
      Just () <- await 10 masterAtWait
      threadDelay 50_000
      throwTo tidA ThreadKilled
      rA <- await 10 doneA
      fmap (either isThreadKilled (const False)) rA `shouldBe` Just True
      -- Job B: item 0 invalid; it sits in a worker's batch, held on gB.
      (_, doneB) <- spawn (runScriptCheckQueue q emptyFlags
                             (itemsOf (opFalse : replicate 63 opTrue)))
      putMVar gA ()                          -- stale workers finish job A
      early <- timeout 3_000_000 (readMVar doneB)
      putMVar gB ()
      rB <- await 10 doneB
      resetHooks
      shutdownScriptCheckQueue q
      case early of
        Nothing -> return ()
        Just o -> expectationFailure
                    ("job B returned while its item 0 was still unchecked: "
                     ++ describeOutcome (Just o))
      fmap (fmap show) rB `shouldSatisfy`
        maybe False (either (const False) ("ScriptCheckFail {scfIndex = 0" `isPrefixOf`))

    it "G6-HK-4b a worker dying inside its batch (async) -> neither OK nor a verdict" $ withHooks $ do
      writeIORef scriptItemHookRef $ \_ isMaster i ->
        if not isMaster && i >= 0
          then throwIO StackOverflow
          else threadDelay 2_000             -- master slow: workers claim
      q <- newScriptCheckQueue 2
      r <- timeout 20_000_000 (runScriptCheckQueue q emptyFlags (itemsOf (replicate 64 opTrue)))
      resetHooks
      shutdownScriptCheckQueue q
      fmap show r `shouldSatisfy` maybe False ("ScriptCheckInternal" `isPrefixOf`)

  ------------------------------------------------------------------ G6-HK-2
  describe "G6-HK-2 end to end: recv thread killed mid-validateFullBlock" $
    it "the thread dies, the block is NOT marked failed (memory or disk), and it still validates" $
      withSystemTempDirectory "haskoin-gate6-e2e" $ \dir ->
        withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> withHooks $ do
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
          setConfiguredPar 1                       -- global queue, master only
          _ <- startGlobalScriptCheckQueue
          (do
            entered <- newEmptyMVar
            once <- newIORef True
            writeIORef scriptItemHookRef $ \_ _ _ -> do
              first <- atomicModifyIORef' once (\b -> (False, b))
              when first $ void (tryPutMVar entered ()) >> blockForever
            (tid, done) <- spawn (mblockValidate db net hc cs getMtp blk bh coins)
            Just () <- await 10 entered
            throwTo tid ThreadKilled
            r <- await 10 done
            resetHooks
            memSt <- fmap ceStatus . Map.lookup bh <$> readTVarIO (hcEntries hc)
            diskSt <- getBlockStatus db bh
            again <- validateFullBlockIO db net cs getMtp False blk coins >>= evaluate
            -- the persisted verdict is the damage: check it first
            (memSt, diskSt) `shouldBe` (Just StatusHeaderValid, Nothing)
            again `shouldBe` Right ()
            case r of
              Just (Left e) | isThreadKilled e -> return ()
              other -> expectationFailure ("expected the validating thread to die with ThreadKilled, got "
                                           ++ describeOutcome other))
            `finally` stopGlobalScriptCheckQueue

  ------------------------------------------------------------------ G6-HK-5
  describe "G6-HK-5 HARD STALL predicate" $ do
    let thr = 120
        base = HardStallView
          { hsvNow = 10_000, hsvPeers = 1, hsvActive = True, hsvIsFork = False
          , hsvProgressed = False, hsvLastProgAt = 10_000 - 300
          , hsvNextInflight = Nothing, hsvPeerLastDoneAt = Nothing
          , hsvNextArrived = False, hsvPeerBusy = False, hsvConnectLockHeld = False }
    it "(a) header T+1 just arrived, last connect 300 s ago, block not yet requested -> no fire" $
      hardStallFires thr base `shouldBe` False
    it "(a') requested 0.2 s ago -> no fire" $
      hardStallFires thr base { hsvNextInflight = Just (10_000, Nothing) } `shouldBe` False
    it "(b) next-needed being processed / peer busy validating for 150 s -> no fire" $ do
      hardStallFires thr base { hsvNextInflight = Just (10_000 - 150, Nothing)
                              , hsvNextArrived = True, hsvPeerBusy = True } `shouldBe` False
      hardStallFires thr base { hsvNextInflight = Just (10_000 - 150, Nothing)
                              , hsvPeerBusy = True } `shouldBe` False
      hardStallFires thr base { hsvNextInflight = Just (10_000 - 150, Nothing)
                              , hsvConnectLockHeld = True } `shouldBe` False
    it "(b') requested 200 s ago but the peer finished a 190 s validate 10 s ago -> no fire" $
      hardStallFires thr base { hsvNextInflight = Just (10_000 - 200, Nothing)
                              , hsvPeerLastDoneAt = Just (10_000 - 10) } `shouldBe` False
    it "(c) control: requested 130 s ago, no first byte, peer idle -> FIRES" $
      hardStallFires thr base { hsvNextInflight = Just (10_000 - 130, Nothing) } `shouldBe` True
    it "(d) control: two peers -> never" $
      hardStallFires thr base { hsvPeers = 2, hsvNextInflight = Just (10_000 - 130, Nothing) }
        `shouldBe` False

  ------------------------------------------------------------------ G6-HK-6
  describe "G6-HK-6 BIP30 lookup of a corrupt coin row is not 'no conflict'" $
    it "validation of a block whose coinbase output row is corrupt does not pass" $
      withSystemTempDirectory "haskoin-gate6-bip30" $ \dir ->
        withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> withHooks $ do
          let net = regtest
              genesis = netGenesisBlock net
              gHash = computeBlockHash (blockHeader genesis)
              (blk, coins) = mkSpendBlock gHash (bhTimestamp (blockHeader genesis) + 600) 2
              cbTxid = computeTxId (head (blockTxns blk))
              cs = ChainState 0 gHash (headerWork (blockHeader genesis))
                              (bhTimestamp (blockHeader genesis)) (consensusFlagsAtHeight net 1)
              getMtp = const (bhTimestamp (blockHeader genesis))
          rG <- connectBlockAt db net genesis 0 Map.empty
          rG `shouldBe` Right ()
          -- control: clean DB -> the block validates
          ok <- validateFullBlockIO db net cs getMtp False blk coins >>= evaluate
          ok `shouldBe` Right ()
          -- a row exists at the coinbase's outpoint but cannot be decoded
          writeBatch db (WriteBatch [BatchPut (makeKey PrefixUTXO (encode (OutPoint cbTxid 0)))
                                               (BS.pack [0xff, 0xff, 0xff])])
          hc <- initHeaderChain net
          r <- try (mblockValidate db net hc cs getMtp blk (computeBlockHash (blockHeader blk)) coins)
          case r of
            Left (e :: SomeException) ->
              expectationFailure ("unexpected exception: " ++ show e)
            Right (Right ()) ->
              expectationFailure "FAIL-OPEN: a corrupt row at the block's own output read as no conflict"
            Right (Left err) -> do
              err `shouldSatisfy` ("internal-error" `isInfixOf`)
              classifyBlockReject err `shouldBe` BlockRejectNonVerdict
