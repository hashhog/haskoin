{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | EXECUTED before/after proof for the restart-path header re-validation
-- fix in app/Main.hs :: initHeaderChainFromDB (uncommitted, 2026-08-10).
--
-- What this proves, on a REAL on-disk RocksDB seeded exactly the way
-- connectBlock writes rows (putBlockHeader / putBlockHeight / putBestBlockHash):
--
--   * NEG fixture = the camlcoin exploit shape: a MIN-difficulty header
--     (bits = powLimit compact) planted at the tip, forking off a
--     REAL-difficulty parent.  Because the custom net has
--     netPowNoRetargeting = True, difficultyAdjustment returns the parent's
--     (harder) bits, so the planted header is strictly EASIER than consensus
--     requires -> bad-diffbits.
--   * POS fixture = an all-valid chain at the real difficulty.
--
-- The reload loop below is a faithful transcription of Main.hs's `go` loop.
-- The four gate checks (bhPrevBlock/ceHash linkage, computeBlockHash identity,
-- checkProofOfWork, and bhBits vs difficultyAdjustment) are copied VERBATIM and
-- call the REAL library functions -- they are NOT reimplemented here.  A `gate`
-- flag toggles them:
--   gate = True   -> POST-FIX behaviour (the four checks present)
--   gate = False  -> PRE-FIX behaviour  (HEAD: no checks, admit everything)
--
-- Expected:
--   POST-FIX NEG -> finalHeight 1  (planted row REFUSED, chain truncated at h1)
--   POST-FIX POS -> finalHeight 2  (loads fully, no over-truncation)
--   PRE-FIX  NEG -> finalHeight 2  (planted row ADMITTED -> the dead-code proof)
--   PRE-FIX  POS -> finalHeight 2

module Main (main) where

import Haskoin.Types
import Haskoin.Consensus
import Haskoin.Storage
import Haskoin.Crypto (computeBlockHash)
import Data.Word (Word32)
import qualified Data.Map.Strict as Map
import Numeric (showHex)
import System.Directory (doesDirectoryExist, removeDirectoryRecursive,
                         createDirectoryIfMissing)
import System.IO (hSetBuffering, stdout, BufferMode(..))
import Control.Monad (when)
import Control.Exception (catch, SomeException)

--------------------------------------------------------------------------------
-- Custom regtest-shaped net: genesis runs at a "real" (hard) difficulty.
--------------------------------------------------------------------------------

-- Hard target 2^252 (well below regtest powLimit 2^255), so a min-difficulty
-- header is strictly EASIER = the exploit direction.  ~1/16 grind per block.
hardTarget :: Integer
hardTarget = 2 ^ (252 :: Int)

hardBits :: Word32
hardBits = targetToBits hardTarget

-- Easiest allowed on this net (== powLimit compact); what the exploit claims.
minDiffBits :: Word32
minDiffBits = targetToBits (netPowLimit regtest)

-- regtest with a genesis that runs at hard difficulty.  netPowNoRetargeting =
-- True on regtest, so difficultyAdjustment returns the PARENT's bits verbatim;
-- every child's expected bits therefore = hardBits, and a planted min-diff
-- header mismatches on bad-diffbits.
customNet :: Network
customNet =
  let g0  = netGenesisBlock regtest
      hdr = (blockHeader g0) { bhBits = hardBits }
  in regtest { netName = "regtest-hardgen"
             , netGenesisBlock = g0 { blockHeader = hdr } }

genesisHdr :: BlockHeader
genesisHdr = blockHeader (netGenesisBlock customNet)

genesisHash :: BlockHash
genesisHash = computeBlockHash genesisHdr

merkle0 :: Hash256
merkle0 = bhMerkleRoot genesisHdr

-- Grind a nonce so checkProofOfWork passes for the given bits under customNet.
grindHeader :: BlockHash -> Word32 -> Word32 -> BlockHeader
grindHeader prev bits ts = go 0
  where
    mk n = BlockHeader
      { bhVersion    = 1
      , bhPrevBlock  = prev
      , bhMerkleRoot = merkle0
      , bhTimestamp  = ts
      , bhBits       = bits
      , bhNonce      = n
      }
    go n = let h = mk n
           in if checkProofOfWork h (netPowLimit customNet) then h else go (n + 1)

validH1 :: BlockHeader
validH1 = grindHeader genesisHash hardBits 1300000000

validH2 :: BlockHeader
validH2 = grindHeader (computeBlockHash validH1) hardBits 1300000600

-- The planted exploit header: min-difficulty, off the real-difficulty parent.
plantedBad :: BlockHeader
plantedBad = grindHeader (computeBlockHash validH1) minDiffBits 1300000600

negChain :: [BlockHeader]
negChain = [validH1, plantedBad]   -- POST-FIX: truncate at h1; PRE-FIX: admit to h2

posChain :: [BlockHeader]
posChain = [validH1, validH2]      -- both: load to h2

--------------------------------------------------------------------------------
-- Seed a RocksDB exactly the way connectBlock persists the active chain.
--------------------------------------------------------------------------------

seedDB :: HaskoinDB -> [BlockHeader] -> IO ()
seedDB db headers = do
  putBlockHeader db genesisHash genesisHdr
  putBlockHeight db 0 genesisHash
  let go _ []       lastH = putBestBlockHash db lastH
      go h (x:xs)   _     = do
        let bh = computeBlockHash x
        putBlockHeader db bh x
        putBlockHeight db h bh
        go (h + 1) xs bh
  go 1 headers genesisHash

--------------------------------------------------------------------------------
-- Faithful transcription of Main.hs :: initHeaderChainFromDB `go` loop.
-- The four gate checks are VERBATIM from the fix and call the real functions.
--------------------------------------------------------------------------------

reloadLoop :: Bool -> HaskoinDB -> Network -> IO Word32
reloadLoop gate db net = do
  let genesisEntry = ChainEntry
        { ceHeader     = genesisHdr
        , ceHash       = genesisHash
        , ceHeight     = 0
        , ceChainWork  = headerWork genesisHdr
        , cePrev       = Nothing
        , ceStatus     = StatusValid
        , ceMedianTime = bhTimestamp genesisHdr
        , ceSequenceId = seqIdBestChainFromDisk
        }
  mBest <- getBestBlockHash db
  case mBest of
    Nothing -> return 0
    Just _  -> go (Map.singleton genesisHash genesisEntry) 1 genesisEntry
  where
    go entriesSoFar height prevEntry = do
      mHash <- getBlockHeight db height
      case mHash of
        Nothing -> return (ceHeight prevEntry)
        Just bh -> do
          mHeader <- getBlockHeader db bh
          case mHeader of
            Nothing     -> return (ceHeight prevEntry)
            Just header -> do
              let refuse reason = do
                    putStrLn $ "WARNING: header reload REFUSED at height "
                             ++ show height ++ " (" ++ reason ++ "); "
                             ++ "truncating in-memory chain at height "
                             ++ show (ceHeight prevEntry)
                    return (ceHeight prevEntry)
                  admit = do
                    let work  = ceChainWork prevEntry + headerWork header
                        entry = ChainEntry
                          { ceHeader     = header
                          , ceHash       = bh
                          , ceHeight     = height
                          , ceChainWork  = work
                          , cePrev       = Just (ceHash prevEntry)
                          , ceStatus     = StatusValid
                          , ceMedianTime = bhTimestamp header
                          , ceSequenceId = seqIdBestChainFromDisk
                          }
                    go (Map.insert bh entry entriesSoFar) (height + 1) entry
              if not gate
                then admit    -- PRE-FIX (HEAD): loop admitted with NO checks
                else
                  -- ==== VERBATIM from app/Main.hs initHeaderChainFromDB fix ====
                  if bhPrevBlock header /= ceHash prevEntry
                    then refuse "prev-hash does not link to loaded parent"
                  else if computeBlockHash header /= bh
                    then refuse "stored hash does not match header hash"
                  else if not (checkProofOfWork header (netPowLimit net))
                    then refuse "proof of work check failed"
                  else if bhBits header
                          /= difficultyAdjustment net entriesSoFar prevEntry header
                    then refuse "bad-diffbits"
                  else admit

--------------------------------------------------------------------------------

runOne :: FilePath -> String -> Bool -> [BlockHeader] -> Word32 -> IO Bool
runOne baseDir label gate chain expected = do
  let path = baseDir ++ "/db-" ++ filter (`elem` ("0123456789" :: String)) label
                             ++ (if gate then "-on" else "-off") ++ show (length chain)
  ex <- doesDirectoryExist path
  when ex $ removeDirectoryRecursive path
  createDirectoryIfMissing True path
  db <- openDB (defaultDBConfig path)
  seedDB db chain
  putStrLn $ "\n----- " ++ label ++ " -----"
  finalH <- reloadLoop gate db customNet `catch` \(e :: SomeException) -> do
              putStrLn ("EXCEPTION: " ++ show e); return 999999
  closeDB db
  let ok = finalH == expected
  putStrLn $ label ++ ": finalHeight=" ++ show finalH
           ++ "  expected=" ++ show expected
           ++ (if ok then "   [PASS]" else "   [FAIL]")
  return ok

main :: IO ()
main = do
  hSetBuffering stdout NoBuffering
  let baseDir = "/tmp/claude-1000/-home-work-hashhog/"
             ++ "e811691d-ab9a-43b8-b32d-c8bfd3f2d03f/scratchpad/reloadtest"
  createDirectoryIfMissing True baseDir
  putStrLn $ "netPowNoRetargeting customNet = " ++ show (netPowNoRetargeting customNet)
  putStrLn $ "hardBits    = 0x" ++ showHex hardBits ""
           ++ "   (target 2^252, the 'real' difficulty)"
  putStrLn $ "minDiffBits = 0x" ++ showHex minDiffBits ""
           ++ "   (== powLimit compact, the planted exploit's claim)"
  putStrLn $ "difficultyAdjustment(child of h1) expects hardBits = 0x"
           ++ showHex hardBits "  ; planted header claims 0x" ++ showHex minDiffBits ""

  putStrLn "\n================ POST-FIX (gate = ON, the uncommitted fix) ================"
  p1 <- runOne baseDir "POSTFIX NEG (planted min-diff off real parent)" True  negChain 1
  p2 <- runOne baseDir "POSTFIX POS (all-valid chain)"                   True  posChain 2

  putStrLn "\n================ PRE-FIX  (gate = OFF, == HEAD, no checks) ================"
  q1 <- runOne baseDir "PREFIX NEG (planted min-diff off real parent)"   False negChain 2
  q2 <- runOne baseDir "PREFIX POS (all-valid chain)"                    False posChain 2

  putStrLn "\n==================================== SUMMARY ===================================="
  putStrLn $ "POST-FIX NEG truncates to h1 (planted REFUSED) : " ++ verdict p1
  putStrLn $ "POST-FIX POS loads fully to h2 (no over-trunc) : " ++ verdict p2
  putStrLn $ "PRE-FIX  NEG admits planted to h2 (dead-code!) : " ++ verdict q1
  putStrLn $ "PRE-FIX  POS loads fully to h2                 : " ++ verdict q2
  let allOk = p1 && p2 && q1 && q2
  putStrLn $ "\nBEFORE/AFTER (dead-code) PROOF: "
           ++ if p1 && q1
                then "CONFIRMED -- same seeded DB: gate ON refuses (h1), gate OFF admits (h2)."
                else "NOT CONFIRMED."
  putStrLn $ "OVERALL: " ++ if allOk then "ALL PASS -- gate is EFFECTIVE and dead-code-free."
                                     else "SOME FAIL -- see above."
  where
    verdict b = if b then "PASS" else "FAIL"
