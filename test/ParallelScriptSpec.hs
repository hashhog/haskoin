{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Parallel script verification — QUEUES.md 2026-09-19 control.
--
-- Bitcoin Core: -par (init.cpp:513), CCheckQueue (src/checkqueue.h),
-- CScriptCheck batched per-input in ConnectBlock (validation.cpp). Extra
-- worker threads drain a bounded job vector; the connecting thread joins as
-- the master; the block is accepted only if every check returns true; the
-- reported failure is the lowest-index one so worker count cannot change
-- the decision.
--
-- REQUIRED:
--   (1) decision identity — accept/reject AND reject reason identical at
--       1 worker and at N
--   (2) failure propagation — one failing check rejects the whole batch
--       with the same reason as the serial path
--   (3) measured scaling — blk/h at 1, 2, 4, 8 workers, printed
--   (4) bounded RSS — more workers must not mean unbounded buffers
--
-- CONTROL: cabal run parallel-script --enable-tests
module Main (main) where

import Control.Monad (when)
import Data.Bits (shiftR, (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List (isInfixOf)
import Data.IORef (IORef, newIORef, atomicModifyIORef')
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Word (Word8, Word32)
import GHC.Conc (getNumCapabilities, setNumCapabilities)
import System.IO (hPutStrLn, stderr)
import Test.Hspec

import Haskoin.Consensus
import Haskoin.Script (emptyFlags)
import Haskoin.Types

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

opTrue, opFalse, opReturn, opCat, opIfUnbalanced :: ByteString
opTrue = BS.singleton 0x51
opFalse = BS.singleton 0x00
opReturn = BS.singleton 0x6a
opCat = BS.singleton 0x7e
opIfUnbalanced = BS.singleton 0x63

-- | <32-byte push> OP_HASH256{rounds} OP_DROP OP_TRUE.
-- Opcode count is rounds+3, so rounds<=180 stays under MAX_OPS_PER_SCRIPT (201).
hashHeavyScript :: Int -> ByteString
hashHeavyScript rounds =
  BS.pack $ [0x20] ++ replicate 32 0x11 ++ replicate rounds 0xaa ++ [0x75, 0x51]

txidBytes :: Int -> ByteString
txidBytes i =
  let b0 = fromIntegral (i .&. 0xff) :: Word8
      b1 = fromIntegral ((i `shiftR` 8) .&. 0xff)
      b2 = fromIntegral ((i `shiftR` 16) .&. 0xff)
      b3 = fromIntegral ((i `shiftR` 24) .&. 0xff)
  in BS.pack ([b0, b1, b2, b3] ++ replicate 28 0)

uidRef :: IO (IORef Word32)
uidRef = newIORef 1

nextUid :: IORef Word32 -> IO Word32
nextUid r = atomicModifyIORef' r $ \n -> (n + 1, n)

-- | One tx with N inputs, one ScriptCheckItem per input. sciInputIdx matches
-- the job index so reject reasons carry the same input number at 1 worker
-- and at N.
jobsOfSpks :: IORef Word32 -> [ByteString] -> IO [ScriptCheckItem]
jobsOfSpks uid spks = do
  locktime <- nextUid uid
  let n = length spks
      inputs =
        [ TxIn
            (OutPoint (TxId (Hash256 (txidBytes (i + 1)))) 0)
            BS.empty
            0xffffffff
        | i <- [0 .. n - 1]
        ]
      tx =
        Tx
          2
          inputs
          [TxOut 900 opTrue]
          (replicate n [])
          locktime
      amounts = replicate n 100_000
  return
    [ ScriptCheckItem
        { sciTx = tx
        , sciInputIdx = i
        , sciPrevScript = spk
        , sciPrevValue = 100_000
        , sciSpentAmounts = amounts
        , sciSpentScripts = spks
        }
    | (i, spk) <- zip [0 ..] spks
    ]

runN :: Int -> [ScriptCheckItem] -> IO ScriptCheckResult
runN n items = do
  let extra = max 0 (n - 1)
  q <- newScriptCheckQueue extra
  r <- runScriptCheckQueue q emptyFlags items
  shutdownScriptCheckQueue q
  return r

ppRes :: ScriptCheckResult -> String
ppRes ScriptCheckOK = "OK"
ppRes (ScriptCheckFail i reason) =
  "FAIL idx=" ++ show i ++ " reason=" ++ show reason

rssKb :: IO Int
rssKb = do
  txt <- readFile "/proc/self/status"
  let loop [] = 0
      loop (ln:rest)
        | take 6 ln == "VmRSS:" =
            case reads (drop 6 ln) of
              [(n, _)] -> n
              _ -> 0
        | otherwise = loop rest
  return (loop (lines txt))

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

main :: IO ()
main = do
  caps <- getNumCapabilities
  when (caps < 8) $ setNumCapabilities 8
  uid <- uidRef
  hspec (spec uid)

spec :: IORef Word32 -> Spec
spec uid = describe "ParallelScript" $ do
  describe "par mapping (Core chainstatemanager_args.cpp:53-60)" $ do
    it "par=1 is serial (0 extra workers)" $
      resolveScriptCheckWorkers 1 `shouldBe` 0

    it "par=2 is one extra worker" $
      resolveScriptCheckWorkers 2 `shouldBe` 1

    it "par=0 is every core (extra = CPU-1)" $ do
      let extra = resolveScriptCheckWorkers 0
      extra `shouldBe` max 0 (cpuCount - 1)
      defaultScriptCheckThreads `shouldBe` 0
      scriptCheckBatchSize `shouldBe` 128

    it "par=-1 leaves one core free (auto-1, floored at 0)" $ do
      let auto = resolveScriptCheckWorkers 0
          leave = resolveScriptCheckWorkers (-1)
      leave `shouldBe` max 0 (auto - 1)
      leave <= auto `shouldBe` True

    it "init extra=0 spawns no threads" $ do
      q <- newScriptCheckQueue 0
      extraWorkers q `shouldBe` 0
      hasThreads q `shouldBe` False
      shutdownScriptCheckQueue q

    it "init extra=4 spawns a persistent pool" $ do
      q <- newScriptCheckQueue 4
      extraWorkers q `shouldBe` 4
      hasThreads q `shouldBe` True
      shutdownScriptCheckQueue q

  describe "(1) decision identity — 1 worker vs N" $ do
    it "accepts 64 OP_TRUE at 1 and at 8 with identical result" $ do
      items <- jobsOfSpks uid (replicate 64 opTrue)
      one <- runN 1 items
      eight <- runN 8 items
      one `shouldBe` ScriptCheckOK
      ppRes one `shouldBe` ppRes eight

    it "mixed corpus reject reason is identical at 1 and at 8" $ do
      let corpus =
            [ opTrue, opTrue, opFalse, opTrue
            , opReturn, opTrue, opCat, opTrue
            , opIfUnbalanced, opTrue, opFalse, opReturn
            , opTrue, opCat, opTrue, opIfUnbalanced
            , opTrue, opFalse, opTrue, opReturn
            , opTrue, opCat, opTrue, opTrue
            ]
      serial <- jobsOfSpks uid corpus >>= runN 1
      parallel <- jobsOfSpks uid corpus >>= runN 8
      serial `shouldSatisfy` (/= ScriptCheckOK)
      ppRes serial `shouldBe` ppRes parallel

  describe "(2) failure propagation" $ do
    it "one OP_CAT in 64 OP_TRUE rejects the whole batch at the same index/reason" $ do
      let failAt = 17
          spks = [ if i == failAt then opCat else opTrue | i <- [0 .. 63] ]
      serial <- jobsOfSpks uid spks >>= runN 1
      parallel <- jobsOfSpks uid spks >>= runN 8
      serial `shouldSatisfy` (/= ScriptCheckOK)
      parallel `shouldSatisfy` (/= ScriptCheckOK)
      case (serial, parallel) of
        (ScriptCheckFail si sr, ScriptCheckFail pidx pr) -> do
          si `shouldBe` failAt
          pidx `shouldBe` failAt
          sr `shouldBe` pr
          sr `shouldSatisfy` (not . null)
        _ -> expectationFailure "expected both to fail"

    it "all-pass identity at 1 and 8" $ do
      items <- jobsOfSpks uid (replicate 32 opTrue)
      serial <- runN 1 items
      parallel <- runN 8 items
      serial `shouldBe` ScriptCheckOK
      parallel `shouldBe` ScriptCheckOK

    it "lowest-index failure wins, never the race-winner" $ do
      -- Three distinct failures. Reported reason MUST be job 5 (OP_CAT),
      -- never 20 (unbalanced IF) or 40 (OP_FALSE).
      let spk i
            | i == 5 = opCat
            | i == 20 = opIfUnbalanced
            | i == 40 = opFalse
            | otherwise = opTrue
      serial <- jobsOfSpks uid (map spk [0 .. 47]) >>= runN 1
      parallel <- jobsOfSpks uid (map spk [0 .. 47]) >>= runN 8
      case (serial, parallel) of
        (ScriptCheckFail si sr, ScriptCheckFail pidx pr) -> do
          si `shouldBe` 5
          pidx `shouldBe` 5
          sr `shouldBe` pr
          sr `shouldSatisfy` ("OP_CAT" `isInfixOf`)
        _ -> expectationFailure "expected both to fail at index 5"

    it "a 1-job fail is not skipped (off-by-one on the claim counter)" $ do
      r <- jobsOfSpks uid [opCat] >>= runN 5
      case r of
        ScriptCheckFail 0 reason ->
          reason `shouldSatisfy` (not . null)
        other -> expectationFailure ("expected FAIL idx=0, got " ++ ppRes other)

  describe "(3) measured scaling — 1, 2, 4, 8 total workers" $ do
    it "8 workers beat 1 worker on a 2048-input HASH256 block (>= 1.3x)" $ do
      let inputs = 2048
          goWarm :: Int -> IO Int
          goWarm rounds = do
            items <- jobsOfSpks uid (replicate inputs (hashHeavyScript rounds))
            t0 <- getPOSIXTime
            r <- runN 1 items
            t1 <- getPOSIXTime
            let ms = realToFrac (t1 - t0) * 1000.0 :: Double
            case r of
              ScriptCheckFail _ reason ->
                error ("hash-heavy OP_TRUE rejected: " ++ reason)
              ScriptCheckOK -> do
                hPutStrLn stderr $
                  "scaling warmup: 1 worker " ++ show (round ms :: Int)
                    ++ " ms at " ++ show rounds ++ " HASH256 rounds, "
                    ++ show inputs ++ " inputs"
                if ms >= 150.0 || rounds >= 180
                  then return rounds
                  else goWarm (min 180 (rounds * 2))
          measure :: Int -> Int -> IO (Int, Double, Double)
          measure rounds n = do
            items <- jobsOfSpks uid (replicate inputs (hashHeavyScript rounds))
            q <- newScriptCheckQueue (max 0 (n - 1))
            t0 <- getPOSIXTime
            r <- runScriptCheckQueue q emptyFlags items
            t1 <- getPOSIXTime
            shutdownScriptCheckQueue q
            case r of
              ScriptCheckFail _ reason ->
                error ("workers=" ++ show n ++ " rejected: " ++ reason)
              ScriptCheckOK -> do
                let wall = max 1e-9 (realToFrac (t1 - t0) :: Double)
                    blkH = 3600.0 / wall
                hPutStrLn stderr $
                  "scaling workers=" ++ show n
                    ++ " wall_s=" ++ show wall
                    ++ " blk_h=" ++ show blkH
                    ++ " (n_jobs=" ++ show inputs
                    ++ " HASH256_rounds=" ++ show rounds ++ ")"
                return (n, wall, blkH)
      rounds <- goWarm 64
      times <- mapM (measure rounds) [1, 2, 4, 8]
      let wall1 = head [ w | (1, w, _) <- times ]
          wall8 = head [ w | (8, w, _) <- times ]
          speedup = wall1 / wall8
      hPutStrLn stderr $ "scaling speedup 1→8 workers: " ++ show speedup ++ "x"
      wall8 < wall1 `shouldBe` True
      speedup >= 1.3 `shouldBe` True

  describe "(4) bounded RSS — more workers must not mean unbounded buffers" $ do
    it "maxInFlight is bounded by batch*(extra+1); extra RSS is O(workers)" $ do
      items <- jobsOfSpks uid (replicate 256 opTrue)
      q1 <- newScriptCheckQueue 1
      q8 <- newScriptCheckQueue 8
      rssBefore <- rssKb
      r1 <- runScriptCheckQueue q1 emptyFlags items
      r8 <- runScriptCheckQueue q8 emptyFlags items
      m1 <- maxInFlight q1
      m8 <- maxInFlight q8
      rssAfter <- rssKb
      shutdownScriptCheckQueue q1
      shutdownScriptCheckQueue q8
      r1 `shouldBe` ScriptCheckOK
      r8 `shouldBe` ScriptCheckOK
      let cap1 = scriptCheckBatchSize * (extraWorkers q1 + 1)
          cap8 = scriptCheckBatchSize * (extraWorkers q8 + 1)
          extraKb = rssAfter - rssBefore
      m1 <= cap1 `shouldBe` True
      m8 <= cap8 `shouldBe` True
      cap8 > cap1 `shouldBe` True
      hPutStrLn stderr $
        "bounded RSS: VmRSS before=" ++ show rssBefore
          ++ " kB after=" ++ show rssAfter
          ++ " kB extra=" ++ show extraKb
          ++ " kB; maxInFlight 1w=" ++ show m1
          ++ " 8w=" ++ show m8
          ++ " (caps " ++ show cap1 ++ "/" ++ show cap8 ++ ")"
      -- Worker stacks are O(workers), not O(workers × jobs). 512 MiB is
      -- well above 8 × a Haskell thread and well below an unbounded copy
      -- of the job list per worker.
      extraKb < 512 * 1024 `shouldBe` True

  describe "persistent pool (not per-block spawn)" $ do
    it "two batches on one queue do not respawn workers" $ do
      q <- newScriptCheckQueue 4
      let extra = extraWorkers q
      passItems <- jobsOfSpks uid (replicate 16 opTrue)
      pass <- runScriptCheckQueue q emptyFlags passItems
      pass `shouldBe` ScriptCheckOK
      failItems <-
        jobsOfSpks uid [ if i == 1 then opFalse else opTrue | i <- [0 .. 15] ]
      failed <- runScriptCheckQueue q emptyFlags failItems
      case failed of
        ScriptCheckFail 1 _ -> return ()
        other -> expectationFailure ("expected FAIL idx=1, got " ++ ppRes other)
      extraWorkers q `shouldBe` extra
      shutdownScriptCheckQueue q
