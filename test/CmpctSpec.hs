{-# LANGUAGE CPP #-}

-- | secfix-haskoin-cmpctblock-pending-unbounded (finding C4).
--
-- Pre-fix haskoin built a PartiallyDownloadedBlock for every cmpctblock it
-- received, whatever its header, and parked it in the global 'cbsPending'
-- map (keyed by block hash only) for up to 600 s: no proof-of-work check, no
-- known-parent check, no count cap and no punishment.  A peer could send
-- cmpctblocks with random 80-byte headers and fill the map without limit.
--
-- Core (bitcoin-core/src/net_processing.cpp, NetMsgType::CMPCTBLOCK):
--   1. LookupBlockIndex(hashPrevBlock) fails -> MaybeSendGetHeaders, return
--      (no punishment, nothing stored);
--   2. ProcessNewBlockHeaders (PoW, difficulty, timestamps, ...) fails ->
--      MaybePunishNodeForBlock, return;
--   3. only then is a PartiallyDownloadedBlock made, inside
--      mapBlocksInFlight, which holds at most MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK
--      (3) entries per block and MAX_BLOCKS_IN_TRANSIT_PER_PEER (16) per peer;
--   4. a blocktxn is matched only against the partial block requested from
--      THAT peer (ProcessCompactBlockTxns, requested_block_from_this_peer).
--
-- The tests drive the header gate and the pending-map admission that the
-- MCmpctBlock / MBlockTxn handlers in app/Main.hs call.  They need functions
-- the fix adds, so they sit behind HASKOIN_CMPCT_ADMISSION, a cpp flag only the
-- fix commit sets in this suite's stanza; without it every test fails by name.
--
-- secfix-haskoin-cmpctblock-mempool-rehash (finding H2): the handler then
-- matched short ids by recomputing every mempool transaction's wtxid (full
-- re-serialization + SHA256d per tx, per cmpctblock).  Core's
-- PartiallyDownloadedBlock::InitData uses the wtxid the mempool cached.  The
-- "mempool rehash (H2)" tests count how many mempool transactions the
-- handler's call forces; on a commit without HASKOIN_CMPCT_CACHED_WTXID they
-- drive the call master's handler makes ('initPartialBlock' on the txid map).
module CmpctSpec (spec) where

import Test.Hspec

#ifdef HASKOIN_CMPCT_ADMISSION
import Control.Concurrent.STM
import Control.Exception (evaluate)
import Control.Monad (forM)
import Data.IORef
import System.IO.Unsafe (unsafeInterleaveIO)
import qualified Data.ByteString as BS
import Data.Bits (shiftR, (.&.))
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust, isNothing)
import Data.Word (Word8, Word32)
import Network.Socket (SockAddr(..), tupleToHostAddress)

import Haskoin.Types
import qualified Haskoin.Crypto as Crypto
import Haskoin.Crypto (computeBlockHash)
import Haskoin.Consensus (regtest, initHeaderChain, getChainTip, HeaderChain(..),
                          ChainEntry(..), checkProofOfWork, Network(..))
import Haskoin.Network (CmpctBlock(..), PrefilledTx(..), PartiallyDownloadedBlock(..),
                        computeShortIdKey, computeShortId,
                        CmpctPendingAdmit(..), CmpctPendingMap,
                        admitPendingCompact, takePendingCompact,
                        maxCmpctPendingPerPeer, maxCmpctPendingPerBlock,
                        maxCmpctPendingGlobal, initPartialBlock,
#ifdef HASKOIN_CMPCT_CACHED_WTXID
                        initPartialBlockCached,
#endif
                        MisbehaviorReason(..))
import Haskoin.Sync (CmpctHeaderVerdict(..), cmpctHeaderGate, cmpctHeaderPunishment)

peer :: Word8 -> SockAddr
peer n = SockAddrInet (18000 + fromIntegral n) (tupleToHostAddress (10, 0, 0, n))

coinbase :: Word32 -> Tx
coinbase n = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
                        , txInScript     = BS.pack [0x03, fromIntegral n, fromIntegral (n `shiftR` 8), 0x00]
                        , txInSequence   = 0xffffffff } ]
  , txOutputs  = [ TxOut { txOutValue = 50, txOutScript = BS.pack [0x51] } ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

-- | A cmpctblock with the coinbase prefilled and one short id: with an empty
-- mempool the short id is missing, so the pre-fix handler stored it (1 of 2
-- missing is not > 50 %) and sent getblocktxn.
mkCmpct :: BlockHeader -> CmpctBlock
mkCmpct hdr = CmpctBlock
  { cbHeader    = hdr
  , cbNonce     = fromIntegral (bhNonce hdr)
  , cbShortIds  = [0x0000aabbccdd]
  , cbPrefilled = [PrefilledTx 0 (coinbase (bhNonce hdr))]
  }

-- | Deterministic pseudo-random 32 bytes.
rnd32 :: Word32 -> Word8 -> BS.ByteString
rnd32 i salt = BS.pack [ fromIntegral ((i * 2654435761 + fromIntegral k * 40503 + fromIntegral salt * 97) `shiftR` 7 .&. 0xff)
                       | k <- [0 .. 31 :: Int] ]

-- | A random header: random parent, random merkle root, random bits/nonce.
randomHeader :: Word32 -> BlockHeader
randomHeader i = BlockHeader 0x20000000 (BlockHash (Hash256 (rnd32 i 1)))
                   (Hash256 (rnd32 i 2)) (1296688602 + i) (0x1d00ffff + i) i

-- | A child of @parent@ with valid regtest PoW (grinds the nonce).
validChild :: ChainEntry -> Word32 -> BlockHeader
validChild parent salt = head
  [ h | n <- [0 ..]
      , let h = BlockHeader 0x20000000 (ceHash parent) (Hash256 (rnd32 salt 3))
                  (bhTimestamp (ceHeader parent) + 1 + salt) 0x207fffff n
      , checkProofOfWork h (netPowLimit regtest) ]

-- | A child of @parent@ whose hash does not meet its (mainnet-level) target.
badPowChild :: ChainEntry -> Word32 -> BlockHeader
badPowChild parent salt = head
  [ h | n <- [0 ..]
      , let h = BlockHeader 0x20000000 (ceHash parent) (Hash256 (rnd32 salt 4))
                  (bhTimestamp (ceHeader parent) + 1) 0x1d00ffff n
      , not (checkProofOfWork h (netPowLimit regtest)) ]

-- | What the MCmpctBlock handler does with one cmpctblock from @addr@:
-- header gate first, and only an accepted header goes on to the partial block
-- and the pending map.  Returns the verdict and the admission (if reached).
offer :: HeaderChain -> TVar CmpctPendingMap -> SockAddr -> BlockHeader
      -> IO (CmpctHeaderVerdict, Maybe CmpctPendingAdmit)
offer hc pend addr hdr = do
  v <- cmpctHeaderGate regtest hc hdr
  case v of
    CmpctHeaderAccepted _ -> case initPartialBlock (mkCmpct hdr) Map.empty of
      Right (pdb, missing) | not (null missing) -> do
        r <- atomically $ admitPendingCompact pend addr (computeBlockHash hdr) 0 pdb
        pure (v, Just r)
      _ -> pure (v, Nothing)
    _ -> pure (v, Nothing)

isUnknownParent, isInvalid :: CmpctHeaderVerdict -> Bool
isUnknownParent CmpctHeaderUnknownParent = True
isUnknownParent _ = False
isInvalid (CmpctHeaderInvalid _) = True
isInvalid _ = False

fresh :: IO (HeaderChain, TVar CmpctPendingMap, ChainEntry)
fresh = do
  hc <- initHeaderChain regtest
  g <- getChainTip hc
  pend <- newTVarIO Map.empty
  pure (hc, pend, g)

pdbFor :: BlockHeader -> PartiallyDownloadedBlock
pdbFor hdr = either error fst (initPartialBlock (mkCmpct hdr) Map.empty)

-- | The call the MCmpctBlock handler (app/Main.hs) makes once the header is
-- accepted, over a mempool of (cached wtxid, txid, tx).
handlerInit :: CmpctBlock -> [(Wtxid, TxId, Tx)]
            -> Either String (PartiallyDownloadedBlock, [Int])
#ifdef HASKOIN_CMPCT_CACHED_WTXID
handlerInit cb mp = initPartialBlockCached cb [ (w, tx) | (w, _, tx) <- mp ]
#else
handlerInit cb mp = initPartialBlock cb (Map.fromList [ (t, tx) | (_, t, tx) <- mp ])
#endif

-- | 32 bytes carrying @i@ and a salt, so ids are distinct by construction.
idBytes :: Int -> Word8 -> BS.ByteString
idBytes i salt = BS.pack ([salt] ++ [ fromIntegral (i `shiftR` (8 * k)) | k <- [0 .. 3] ]) <> BS.replicate 27 0

-- | @n@ mempool transactions with (random) cached wtxids.  Each tx is a thunk
-- that bumps @cnt@ when forced; only re-serializing it (to recompute its
-- wtxid) forces it, so @cnt@ counts the SHA256d re-hashes.
countedMempool :: IORef Int -> Int -> IO [(Wtxid, TxId, Tx)]
countedMempool cnt n = forM [1 .. n] $ \i -> do
  tx <- unsafeInterleaveIO $ do
    atomicModifyIORef' cnt (\c -> (c + 1, ()))
    pure (coinbase (fromIntegral i))
  pure (Wtxid (Hash256 (idBytes i 0xa1)), TxId (Hash256 (idBytes i 0xb2)), tx)

-- | A real mempool tx (with its real, cached wtxid) the cmpctblock refers to.
realMempoolTx :: Tx
realMempoolTx = coinbase 777777

-- | A cmpctblock: coinbase prefilled, one short id = the real mempool tx.
cmpctFor :: BlockHeader -> CmpctBlock
cmpctFor hdr =
  let nonce = fromIntegral (bhNonce hdr)
      sid   = computeShortId (computeShortIdKey hdr nonce)
                             (getHash256 (getWtxidHash (Crypto.computeWtxid realMempoolTx)))
  in CmpctBlock { cbHeader = hdr, cbNonce = nonce, cbShortIds = [sid]
                , cbPrefilled = [PrefilledTx 0 (coinbase (bhNonce hdr))] }

mempoolSize :: Int
mempoolSize = 10000

-- | Run the handler path (header gate, then the partial block) over a
-- counted mempool of 'mempoolSize' txs plus the real one.  Returns the
-- verdict, the (missing count, mempool hits) if reached, and the re-hashes.
handlerPath :: BlockHeader -> IO (CmpctHeaderVerdict, Maybe (Int, Int, Maybe Tx), Int)
handlerPath hdr = do
  hc <- initHeaderChain regtest
  cnt <- newIORef 0
  counted <- countedMempool cnt mempoolSize
  let real = (Crypto.computeWtxid realMempoolTx, Crypto.computeTxId realMempoolTx, realMempoolTx)
      mp = counted ++ [real]
  v <- cmpctHeaderGate regtest hc hdr
  r <- case v of
    CmpctHeaderAccepted _ -> case handlerInit (cmpctFor hdr) mp of
      Right (pdb, missing) -> do
        -- force each component (a tuple in WHNF would leave the fold unrun
        -- and the counter read before any re-hash could happen)
        m <- evaluate (length missing)
        h <- evaluate (pdbMempoolCount pdb)
        slot <- evaluate (Map.findWithDefault Nothing 1 (pdbAvailable pdb))
        pure (Just (m, h, slot))
      Left err -> error ("initPartialBlock failed: " ++ err)
    _ -> pure Nothing
  n <- readIORef cnt
  pure (v, r, n)

spec :: Spec
spec = do
 rehashSpec
 describe "cmpctblock pending admission (C4)" $ do
  it "cmpctblock_unknown_parent_not_stored" $ do
    (hc, pend, _) <- fresh
    n0 <- Map.size <$> readTVarIO (hcEntries hc)
    rs <- forM [1 .. 300] $ \i -> offer hc pend (peer 1) (randomHeader i)
    Map.size <$> readTVarIO pend `shouldReturn` 0
    -- Core: unknown parent -> getheaders, not punished, not indexed.
    all (isUnknownParent . fst) rs `shouldBe` True
    map (cmpctHeaderPunishment . fst) rs `shouldBe` replicate 300 Nothing
    Map.size <$> readTVarIO (hcEntries hc) `shouldReturn` n0

  it "cmpctblock_bad_pow_known_parent_punished_not_stored" $ do
    (hc, pend, g) <- fresh
    n0 <- Map.size <$> readTVarIO (hcEntries hc)
    rs <- forM [1 .. 300] $ \i -> offer hc pend (peer 1) (badPowChild g i)
    Map.size <$> readTVarIO pend `shouldReturn` 0
    all (isInvalid . fst) rs `shouldBe` True
    map (cmpctHeaderPunishment . fst) rs `shouldBe` replicate 300 (Just InvalidBlockHeader)
    Map.size <$> readTVarIO (hcEntries hc) `shouldReturn` n0

  it "control: a valid-PoW header on a known parent is accepted and stored" $ do
    (hc, pend, g) <- fresh
    (v, r) <- offer hc pend (peer 1) (validChild g 1)
    cmpctHeaderPunishment v `shouldBe` Nothing
    r `shouldBe` Just CmpctPendingStored
    Map.size <$> readTVarIO pend `shouldReturn` 1

  it "cmpctblock_pending_per_peer_cap: one peer holds at most 16" $ do
    (hc, pend, g) <- fresh
    rs <- forM [1 .. 40] $ \i -> snd <$> offer hc pend (peer 1) (validChild g i)
    maxCmpctPendingPerPeer `shouldBe` 16
    length (filter (== Just CmpctPendingStored) rs) `shouldBe` maxCmpctPendingPerPeer
    length (filter (== Just CmpctPendingPeerFull) rs) `shouldBe` (40 - maxCmpctPendingPerPeer)
    Map.size <$> readTVarIO pend `shouldReturn` maxCmpctPendingPerPeer

  it "cmpctblock_pending_per_block_cap: one block from at most 3 peers" $ do
    (hc, pend, g) <- fresh
    let hdr = validChild g 7
    rs <- forM [1 .. 6] $ \p -> snd <$> offer hc pend (peer p) hdr
    maxCmpctPendingPerBlock `shouldBe` 3
    rs `shouldBe` replicate 3 (Just CmpctPendingStored) ++ replicate 3 (Just CmpctPendingBlockFull)

  it "cmpctblock_pending_global_cap: all peers together are bounded" $ do
    (hc, pend, g) <- fresh
    let hdrs = [ validChild g i | i <- [1 .. 200] ]
    rs <- forM (zip [0 ..] hdrs) $ \(k, h) ->
      snd <$> offer hc pend (peer (fromIntegral (1 + (k :: Int) `div` 10))) h
    sz <- Map.size <$> readTVarIO pend
    sz `shouldBe` maxCmpctPendingGlobal
    length (filter (== Just CmpctPendingGlobalFull) rs) `shouldBe` (200 - maxCmpctPendingGlobal)

  it "cmpctblock_pending_duplicate_not_overwritten" $ do
    (hc, pend, g) <- fresh
    let hdr = validChild g 9
    (_, r1) <- offer hc pend (peer 1) hdr
    (_, r2) <- offer hc pend (peer 1) hdr
    r1 `shouldBe` Just CmpctPendingStored
    r2 `shouldBe` Just CmpctPendingDuplicate
    Map.size <$> readTVarIO pend `shouldReturn` 1

  it "blocktxn_only_completes_the_requesting_peers_partial_block" $ do
    pend <- newTVarIO Map.empty
    g <- initHeaderChain regtest >>= getChainTip
    let hdr = validChild g 11
        bh = computeBlockHash hdr
    r <- atomically $ admitPendingCompact pend (peer 1) bh 0 (pdbFor hdr)
    r `shouldBe` CmpctPendingStored
    other <- atomically $ takePendingCompact pend (peer 2) bh
    isNothing other `shouldBe` True
    Map.size <$> readTVarIO pend `shouldReturn` 1
    own <- atomically $ takePendingCompact pend (peer 1) bh
    isJust own `shouldBe` True
    Map.size <$> readTVarIO pend `shouldReturn` 0
rehashSpec :: Spec
rehashSpec = describe "cmpctblock mempool rehash (H2)" $ do
  it "cmpctblock_bad_header_no_mempool_hash" $ do
    g <- initHeaderChain regtest >>= getChainTip
    (v, r, n) <- handlerPath (badPowChild g 1)
    isInvalid v `shouldBe` True
    r `shouldBe` Nothing
    n `shouldBe` 0

  it "cmpctblock_valid_header_no_mempool_rehash" $ do
    g <- initHeaderChain regtest >>= getChainTip
    (v, r, n) <- handlerPath (validChild g 1)
    cmpctHeaderPunishment v `shouldBe` Nothing
    -- control: the real tx was found by its cached wtxid, so the match ran
    r `shouldBe` Just (0, 1, Just realMempoolTx)
    -- and none of the 10k other mempool txs was re-serialized / re-hashed
    n `shouldBe` 0

#ifdef HASKOIN_CMPCT_CACHED_WTXID
  it "cached_wtxid_matching_equals_recomputed_matching" $ do
    g <- initHeaderChain regtest >>= getChainTip
    let hdr  = validChild g 2
        txs  = [ coinbase i | i <- [900000 .. 900040] ] ++ [realMempoolTx]
        byId = Map.fromList [ (Crypto.computeTxId t, t) | t <- txs ]
        cached = [ (Crypto.computeWtxid t, t) | t <- Map.elems byId ]
        strip = fmap (\(p, m) -> (pdbAvailable p, pdbMempoolCount p, m))
    strip (initPartialBlockCached (cmpctFor hdr) cached)
      `shouldBe` strip (initPartialBlock (cmpctFor hdr) byId)
    fmap (\(p, _) -> pdbMempoolCount p) (initPartialBlockCached (cmpctFor hdr) cached)
      `shouldBe` Right 1
#else
  it "cached_wtxid_matching_equals_recomputed_matching" $
    expectationFailure "no initPartialBlockCached on this commit: the handler recomputes every mempool wtxid"
#endif
#else
noGate :: Expectation
noGate = expectationFailure
  "no cmpctblock header gate / pending caps on this commit: every cmpctblock is stored in cbsPending"

spec :: Spec
spec = do
 describe "cmpctblock mempool rehash (H2)" $ do
  it "cmpctblock_bad_header_no_mempool_hash" noGate
  it "cmpctblock_valid_header_no_mempool_rehash" noGate
  it "cached_wtxid_matching_equals_recomputed_matching" noGate
 describe "cmpctblock pending admission (C4)" $ do
  it "cmpctblock_unknown_parent_not_stored" noGate
  it "cmpctblock_bad_pow_known_parent_punished_not_stored" noGate
  it "control: a valid-PoW header on a known parent is accepted and stored" noGate
  it "cmpctblock_pending_per_peer_cap: one peer holds at most 16" noGate
  it "cmpctblock_pending_per_block_cap: one block from at most 3 peers" noGate
  it "cmpctblock_pending_global_cap: all peers together are bounded" noGate
  it "cmpctblock_pending_duplicate_not_overwritten" noGate
  it "blocktxn_only_completes_the_requesting_peers_partial_block" noGate
#endif
