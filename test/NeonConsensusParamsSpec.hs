-- | verify-neon-haskoin-findings, consensus (Neon audit findings 10, 12, 15, 16).
--
-- 10. Assume-valid condition 6. Core's ConnectBlock verifies scripts unless
--     GetBlockProofEquivalentTime(best_header, pindex, best_header) >
--     1209600: the WORK between the block and the best header, expressed in
--     seconds at the best header's difficulty (pow.cpp). haskoin compared
--     raw timestamps, in Word32 (a best header one second older than the
--     block wrapped to ~4.29e9 and skipped scripts), with >=.
-- 12. ContextualCheckBlockHeader rejects nVersion < 2 / < 3 / < 4 once
--     BIP34 / BIP66 / BIP65 are active (bad-version(0x%08x)). haskoin
--     checked the version only for block bodies, so a header-only chain
--     (P2P headers, submitheader) with an outdated version was indexed.
-- 15. Testnet4's genesis coinbase pays CScript() << 33 zero bytes <<
--     OP_CHECKSIG (kernel/chainparams.cpp); haskoin had 34 zero bytes, so
--     the genesis body did not hash to its own header's merkle root.
-- 16. Regtest: DifficultyAdjustmentInterval() is nPowTargetTimespan /
--     nPowTargetSpacing = 86400 / 600 = 144 (haskoin: 150), and the
--     getblocktemplate coinbase value uses GetBlockSubsidy with regtest's
--     150-block halving (haskoin: the mainnet 210000 schedule).
module Main (main) where

import Control.Concurrent.STM (readTVarIO)
import qualified Data.ByteString as BS
import Data.Int (Int32)
import Data.List (foldl')
import qualified Data.Map.Strict as Map
import Data.Word (Word32)
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)
import Test.Hspec

import Haskoin.BlockTemplate (BlockTemplate(..), createBlockTemplate)
import Haskoin.Consensus
import Haskoin.Crypto (computeBlockHash, computeTxId)
import Haskoin.Mempool (defaultMempoolConfig, newMempool)
import Haskoin.Storage (defaultDBConfig, newUTXOCache, withDB)
import Haskoin.Types

--------------------------------------------------------------------------------
-- 10. Assume-valid condition 6
--------------------------------------------------------------------------------

-- | A header chain above a fake genesis; @tss@ are the timestamps of
-- heights 0.. Every header has difficulty-1 bits, so each adds the same work.
mkChain :: [Word32] -> [ChainEntry]
mkChain tss = reverse (foldl' step [] (zip [0 ..] tss))
  where
    step acc (h, ts) =
      let prev = case acc of
                   (p:_) -> Just (ceHash p)
                   []    -> Nothing
          hdr = BlockHeader
            { bhVersion = 4
            , bhPrevBlock = maybe (BlockHash (Hash256 (BS.replicate 32 0))) id prev
            , bhMerkleRoot = Hash256 (BS.replicate 32 0)
            , bhTimestamp = ts
            , bhBits = 0x1d00ffff
            , bhNonce = h }
          work = maybe 0 ceChainWork (case acc of { (p:_) -> Just p; [] -> Nothing })
                 + headerWork hdr
          e = ChainEntry
            { ceHeader = hdr, ceHash = computeBlockHash hdr, ceHeight = h
            , ceChainWork = work, cePrev = prev, ceStatus = StatusHeaderValid
            , ceMedianTime = 0, ceSequenceId = 0 }
      in e : acc

-- | Would haskoin skip the scripts of the block at height @p@ when the best
-- header (and the assume-valid block) is the last entry of the chain?
skipAt :: [Word32] -> Word32 -> Bool
skipAt tss p =
  let chain = mkChain tss
      best  = last chain
      blk   = chain !! fromIntegral p
      idx   = Map.fromList [ (ceHash e, e) | e <- chain ]
      net   = mainnet { netAssumedValid = Just (ceHash best), netMinimumChainWork = 0 }
  in shouldSkipScripts (ceHash blk) (ceHeight blk) (bhTimestamp (ceHeader blk)) net idx best

-- | Timestamps 600 s apart from @t0@, @n@ of them.
spaced :: Int -> [Word32]
spaced n = take n [1000000, 1000600 ..]

--------------------------------------------------------------------------------
-- 12. Header version
--------------------------------------------------------------------------------

-- | A regtest header on the genesis block with @ver@, ground to valid PoW.
regtestChild :: Int32 -> BlockHeader
regtestChild ver =
  let g = blockHeader (netGenesisBlock regtest)
      base = BlockHeader
        { bhVersion = ver
        , bhPrevBlock = computeBlockHash g
        , bhMerkleRoot = Hash256 (BS.replicate 32 0x33)
        , bhTimestamp = bhTimestamp g + 600
        , bhBits = bhBits g
        , bhNonce = 0 }
  in head [ h | n <- [0 ..], let h = base { bhNonce = n }
              , checkProofOfWork h (netPowLimit regtest) ]

addOnGenesis :: Int32 -> IO (Either String Word32, Word32)
addOnGenesis ver = do
  hc <- initHeaderChain regtest
  r <- addHeaderAt regtest hc (regtestChild ver) True (Just 2000000000)
  tipH <- ceHeight <$> readTVarIO (hcTip hc)
  return (fmap ceHeight r, tipH)

contextualOnGenesis :: Int32 -> Either String ()
contextualOnGenesis ver =
  let g = blockHeader (netGenesisBlock regtest)
      ge = ChainEntry
        { ceHeader = g, ceHash = computeBlockHash g, ceHeight = 0
        , ceChainWork = headerWork g, cePrev = Nothing, ceStatus = StatusValid
        , ceMedianTime = bhTimestamp g, ceSequenceId = 0 }
  in contextualCheckBlockHeader regtest (Map.singleton (ceHash ge) ge) ge
       (regtestChild ver) 2000000000

-- | Activation boundaries: a regtest variant with BIP34 at 3, BIP66 at 4 and
-- BIP65 at 5. Build @prefix@ (versions of heights 1..) and then add one more
-- header at the next height with @ver@; return addHeaderAt's answer for it.
-- Core: DeploymentActiveAfter(pindexPrev) is pindexPrev->nHeight + 1 >= the
-- activation height, so the gate applies from the activation height itself.
boundaryNet :: Network
boundaryNet = regtest { netBIP34Height = 3, netBIP66Height = 4, netBIP65Height = 5 }

atHeight :: [Int32] -> Int32 -> IO (Either String Word32)
atHeight prefix ver = do
  hc <- initHeaderChain boundaryNet
  let g = blockHeader (netGenesisBlock boundaryNet)
      mk prev h v =
        let base = BlockHeader v prev (Hash256 (BS.replicate 32 0x55))
                     (bhTimestamp g + 600 * h) (bhBits g) 0
        in head [ x | n <- [0 ..], let x = base { bhNonce = n }
                    , checkProofOfWork x (netPowLimit boundaryNet) ]
      go prev _ [] = return prev
      go prev h (v:vs) = do
        let hdr = mk prev h v
        r <- addHeaderAt boundaryNet hc hdr True (Just 2000000000)
        case r of
          Left e -> expectationFailure ("prefix header rejected: " ++ e) >> return prev
          Right _ -> go (computeBlockHash hdr) (h + 1) vs
  tipHash <- go (computeBlockHash g) 1 prefix
  let h = fromIntegral (length prefix) + 1
  fmap ceHeight <$> addHeaderAt boundaryNet hc (mk tipHash h ver) True (Just 2000000000)

--------------------------------------------------------------------------------
-- 16. getblocktemplate on regtest at the first halving
--------------------------------------------------------------------------------

-- | The coinbase value getblocktemplate offers for the block at @height@
-- on an empty regtest mempool.
templateValueAt :: Word32 -> IO Word32
templateValueAt height = withSystemTempDirectory "haskoin-neon-gbt" $ \dir ->
  withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
    hc <- initHeaderChain regtest
    let g = blockHeader (netGenesisBlock regtest)
        go _ 0 = return ()
        go prev k = do
          let base = BlockHeader 4 prev (Hash256 (BS.replicate 32 0x44))
                       (bhTimestamp g + 600 * (height - k)) (bhBits g) 0
              hdr = head [ h | n <- [0 ..], let h = base { bhNonce = n }
                             , checkProofOfWork h (netPowLimit regtest) ]
          r <- addHeaderAt regtest hc hdr True (Just 2000000000)
          case r of
            Left e -> expectationFailure ("addHeaderAt: " ++ e)
            Right _ -> go (computeBlockHash hdr) (k - 1)
    go (computeBlockHash g) (height - 1)
    cache <- newUTXOCache db 1000
    mp <- newMempool regtest cache defaultMempoolConfig (height - 1) 0 (\_ -> return 0)
    bt <- createBlockTemplate regtest hc mp cache (BS.pack [0x51]) BS.empty
    btHeight bt `shouldBe` height
    return (fromIntegral (btCoinbaseValue bt `div` 1000000))   -- in 0.01 BTC

--------------------------------------------------------------------------------

main :: IO ()
main = hspec $ do
  describe "finding 10: assume-valid condition 6 is work-equivalent time > two weeks" $ do
    it "best header one block ahead with an EARLIER timestamp: scripts are verified" $
      skipAt [1000000, 1000000, 999999] 1 `shouldBe` False
    it "best header one block ahead but three weeks later in time: scripts are verified" $
      skipAt [1000000, 1000000, 1000000 + 3 * 604800] 1 `shouldBe` False
    it "exactly 2016 blocks (1209600 s of work) ahead: scripts are verified (Core: <=)" $
      skipAt (spaced 2018) 1 `shouldBe` False
    it "2017 blocks ahead with equal timestamps: scripts are skipped (work, not time)" $
      skipAt (replicate 2019 1000000) 1 `shouldBe` True
    it "control: 2017 blocks ahead, 600 s apart: scripts are skipped" $
      skipAt (spaced 2019) 1 `shouldBe` True
    it "control: no assume-valid block configured: scripts are verified" $ do
      let chain = mkChain (spaced 2019)
          best = last chain
          blk = chain !! 1
          idx = Map.fromList [ (ceHash e, e) | e <- chain ]
      shouldSkipScripts (ceHash blk) 1 (bhTimestamp (ceHeader blk))
        (mainnet { netAssumedValid = Nothing }) idx best `shouldBe` False

  describe "finding 12: outdated header versions are refused at header acceptance" $ do
    it "regtest height 1, nVersion=1: addHeaderAt refuses bad-version(0x00000001)" $ do
      (r, tipH) <- addOnGenesis 1
      r `shouldBe` Left "bad-version(0x00000001)"
      tipH `shouldBe` 0
    it "regtest height 1, nVersion=2 and 3: bad-version" $ do
      (r2, _) <- addOnGenesis 2
      r2 `shouldBe` Left "bad-version(0x00000002)"
      (r3, _) <- addOnGenesis 3
      r3 `shouldBe` Left "bad-version(0x00000003)"
    it "regtest height 1, nVersion=-1: bad-version(0xffffffff)" $ do
      (r, _) <- addOnGenesis (-1)
      r `shouldBe` Left "bad-version(0xffffffff)"
    it "contextualCheckBlockHeader (submitblock side-branch arm) refuses nVersion=1" $
      contextualOnGenesis 1 `shouldBe` Left "bad-version(0x00000001)"
    it "boundaries: each version is refused from its soft fork's activation height, not before" $ do
      -- BIP34 at 3: nVersion 1 is fine at 2, refused at 3.
      atHeight [1] 1 >>= (`shouldBe` Right 2)
      atHeight [1, 1] 1 >>= (`shouldBe` Left "bad-version(0x00000001)")
      -- BIP66 at 4: nVersion 2 is fine at 3, refused at 4.
      atHeight [1, 1] 2 >>= (`shouldBe` Right 3)
      atHeight [1, 1, 2] 2 >>= (`shouldBe` Left "bad-version(0x00000002)")
      -- BIP65 at 5: nVersion 3 is fine at 4, refused at 5; 4 is fine at 5.
      atHeight [1, 1, 2] 3 >>= (`shouldBe` Right 4)
      atHeight [1, 1, 2, 3] 3 >>= (`shouldBe` Left "bad-version(0x00000003)")
      atHeight [1, 1, 2, 3] 4 >>= (`shouldBe` Right 5)
    it "control: nVersion=4 and 0x20000000 are accepted at height 1" $ do
      (r4, t4) <- addOnGenesis 4
      r4 `shouldBe` Right 1
      t4 `shouldBe` 1
      (rb, _) <- addOnGenesis 0x20000000
      rb `shouldBe` Right 1
      contextualOnGenesis 4 `shouldBe` Right ()

  describe "finding 15: genesis bodies hash to their headers' merkle roots" $ do
    let root net = computeMerkleRoot (map computeTxId (blockTxns (netGenesisBlock net)))
        hdrRoot net = bhMerkleRoot (blockHeader (netGenesisBlock net))
    it "testnet4: the coinbase txid is the header's merkle root (Core 7aa0a7ae...)" $
      root testnet4 `shouldBe` hdrRoot testnet4
    it "testnet4: the coinbase pays <33 zero bytes> OP_CHECKSIG" $
      map txOutScript (concatMap txOutputs (blockTxns (netGenesisBlock testnet4)))
        `shouldBe` [BS.pack ([0x21] ++ replicate 33 0 ++ [0xac])]
    it "control: mainnet, testnet3 and regtest genesis bodies match their headers" $ do
      root mainnet `shouldBe` hdrRoot mainnet
      root testnet3 `shouldBe` hdrRoot testnet3
      root regtest `shouldBe` hdrRoot regtest

  describe "finding 16: regtest parameters" $ do
    it "regtest retarget interval is 144 (86400 / 600), as Core" $
      netRetargetInterval regtest `shouldBe` 144
    it "every network: retarget interval = target timespan / target spacing" $
      [ netRetargetInterval n == netPowTargetTimespan n `div` netPowTargetSpacing n
      | n <- [mainnet, testnet3, testnet4, regtest] ] `shouldBe` [True, True, True, True]
    it "control: getblocktemplate at regtest height 149 offers 50 BTC" $
      templateValueAt 149 >>= (`shouldBe` 5000)
    it "getblocktemplate at regtest height 150 offers 25 BTC (150-block halving)" $
      templateValueAt 150 >>= (`shouldBe` 2500)
