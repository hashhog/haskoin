{-# LANGUAGE CPP #-}

-- | secfix-haskoin-headers-presync (finding H5).
--
-- Pre-fix the MHeaders handler (app/Main.hs) ran every peer header through
-- @addHeader net hc hdr False@ and persisted it with 'putBlockHeader'.
-- 'addHeader''s too-little-chainwork gate only fires once our own tip has
-- passed nMinimumChainWork, so a fresh node indexed and stored every
-- low-work header chain a peer sent, without limit.  The PRESYNC/REDOWNLOAD
-- machine in Haskoin.Sync existed but nothing called it.
--
-- Core (bitcoin-core/src/net_processing.cpp ProcessHeadersMessage,
-- TryLowWorkHeadersSync, GetAntiDoSWorkThreshold; headerssync.cpp):
-- a headers chain whose claimed work (chain_start work + the batch's work)
-- is below the anti-DoS threshold is never stored.  A full batch starts a
-- HeadersSyncState that keeps only 1-bit commitments (PRESYNC), and once
-- the chain is shown to reach the threshold re-downloads it, checks the
-- commitments and only then releases headers for storage (REDOWNLOAD).
--
-- 'step' below is one MHeaders message, in the handler's order.  With the
-- fix (HASKOIN_HEADERS_PRESYNC, set only by the fix commit in this suite's
-- stanza) it goes through 'peerHeadersGate' first; without it, it is the
-- pre-fix handler body, so on the base commit the tests fail on their
-- assertions, by name.
module HeaderSyncSpec (spec) where

import Test.Hspec

import Control.Concurrent.STM
import Control.Exception (bracket)
import Control.Monad (forM, forM_)
import qualified Data.ByteString as BS
import Data.IORef
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust, catMaybes)
import Data.Int (Int64)
import Data.Word (Word8, Word32)
import Network.Socket (SockAddr(..), tupleToHostAddress)
import System.Directory (getTemporaryDirectory, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)

import Haskoin.Types
import Haskoin.Crypto (computeBlockHash)
import Haskoin.Consensus
import Haskoin.Storage (HaskoinDB, defaultDBConfig, withDB, putBlockHeader, getBlockHeader)
#ifdef HASKOIN_HEADERS_PRESYNC
import Haskoin.Network (MisbehaviorReason(..))
import Haskoin.Sync (PeerHeadersVerdict(..), peerHeadersGate, HeadersSyncPeers,
                     headersSyncActive)
#endif

#ifndef HASKOIN_HEADERS_PRESYNC
type HeadersSyncPeers = TVar (Map.Map SockAddr ())
#endif

peerAddr :: SockAddr
peerAddr = SockAddrInet 18444 (tupleToHostAddress (10, 0, 0, 7))

genesisHdr :: BlockHeader
genesisHdr = blockHeader (netGenesisBlock regtest)

genesisHash :: BlockHash
genesisHash = computeBlockHash genesisHdr

-- | A chain of @n@ difficulty-1 (regtest powLimit) headers on @prev@, one
-- per 600 s after @t0@.  @salt@ goes in the merkle root so two chains on
-- the same parent differ from their first header.
mkChain :: Word32 -> BlockHash -> Word32 -> Int -> [BlockHeader]
mkChain salt prev0 tStart n = go prev0 1
  where
    go _ i | i > n = []
    go prev i =
      let root = Hash256 (BS.pack ([fromIntegral salt, fromIntegral (salt `div` 256)]
                                   ++ replicate 26 0
                                   ++ le32 (fromIntegral i)))
          base nonce = BlockHeader 1 prev root (tStart + fromIntegral i * 600) 0x207fffff nonce
          h = head [ base k | k <- [0 ..], checkProofOfWork (base k) (netPowLimit regtest) ]
      in h : go (computeBlockHash h) (i + 1)
    le32 :: Word32 -> [Word8]
    le32 w = [fromIntegral (w `div` (256 ^ k)) | k <- [0 .. 3 :: Int]]

-- | regtest with a minimum chain work @mcw@ (Core -minimumchainwork).
netWith :: Integer -> Network
netWith mcw = regtest { netMinimumChainWork = mcw }

data Env = Env
  { eNet   :: Network
  , eHc    :: HeaderChain
  , eDb    :: HaskoinDB
  , eSyncs :: HeadersSyncPeers
  , ePunished :: IORef [String]
  }

withEnv :: Network -> (Env -> IO a) -> IO a
withEnv net act = do
  tmp <- getTemporaryDirectory
  bracket (createTempDirectory tmp "haskoin-headers-presync-") removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig dir) $ \db -> do
      hc <- initHeaderChain net
      syncs <- newTVarIO Map.empty
      pun <- newIORef []
      act (Env net hc db syncs pun)

-- | One MHeaders message from 'peerAddr', in the handler's order.  Returns the
-- getheaders locator the node sends next, if any.
step :: Env -> [BlockHeader] -> IO (Maybe [BlockHash])
step env hdrs = do
  let net = eNet env
      hc = eHc env
  tipBefore <- readTVarIO (hcHeight hc)
#ifdef HASKOIN_HEADERS_PRESYNC
  -- A fresh node: nothing connected, the active tip is genesis.
  entries0 <- readTVarIO (hcEntries hc)
  activeTip <- maybe (fail "genesis missing from the index") pure
                 (Map.lookup genesisHash entries0)
  v <- peerHeadersGate net hc activeTip (eSyncs env) peerAddr gateNow hdrs
  forM_ (phvPunish v) $ \why -> modifyIORef' (ePunished env) (show why :)
  let accepted = phvAccept v
      minPowChecked = True
      syncActive = phvSyncActive v
      gateReq = phvGetHeaders v
#else
  let accepted = hdrs
      minPowChecked = False
      syncActive = False
      gateReq = Nothing
#endif
  forM_ accepted $ \h -> do
    r <- addHeader net hc h minPowChecked
    case r of
      Right e -> putBlockHeader (eDb env) (ceHash e) h
      Left _  -> pure ()
  tipAfter <- readTVarIO (hcHeight hc)
  case gateReq of
    Just loc -> pure (Just loc)
    Nothing
      | length hdrs == 2000 && tipAfter > tipBefore && not syncActive ->
          Just <$> buildBlockLocatorFromChain hc
      | otherwise -> pure Nothing

-- | A peer serving @chainFor@ (chosen per request) answers each getheaders
-- with the next 2000 headers after the first locator hash it knows.
serve :: [BlockHeader] -> [BlockHash] -> [BlockHeader]
serve chain loc =
  let idx = Map.fromList (zip (genesisHash : map computeBlockHash chain) [0 :: Int ..])
      pos = case catMaybes [Map.lookup h idx | h <- loc] of
              (p : _) -> p
              []      -> 0
  in take 2000 (drop pos chain)

-- | Drive a headers sync: start with the node's own locator, then follow its
-- getheaders until it stops asking (at most 200 rounds).  @pick n loc@
-- chooses which chain the peer serves for its n-th request.
drive :: Env -> (Int -> [BlockHash] -> [BlockHeader]) -> IO ()
drive env pick = driveWithBackstop env pick Nothing

-- | 'drive', plus the node's periodic getheaders (getheadersSender's 120 s
-- backstop, the stale-tip check): with @Just k@, after every k-th answer
-- the node also sends a getheaders from its header-tip locator, unless
-- 'backstopMaySend' says the peer is in a headers sync.  Requests are
-- answered in the order sent, so the backstop's answer lands between two
-- answers of the sync, as an in-flight reply would.
driveWithBackstop :: Env -> (Int -> [BlockHash] -> [BlockHeader]) -> Maybe Int -> IO ()
driveWithBackstop env pick mEvery = do
  loc0 <- buildBlockLocatorFromChain (eHc env)
  let go :: Int -> [[BlockHash]] -> IO ()
      go _ [] = pure ()
      go n (loc : queue)
        | n >= 200 = expectationFailure "headers sync did not settle in 200 rounds"
        | otherwise = do
            let hdrs = take 2000 (pick n loc)
            next <- if null hdrs then pure Nothing else step env hdrs
            extra <- case mEvery of
              Just k | n `mod` k == k - 1 -> do
                ok <- backstopMaySend env
                if ok then (: []) <$> buildBlockLocatorFromChain (eHc env) else pure []
              _ -> pure []
            go (n + 1) (queue ++ maybe [] (: []) next ++ extra)
  go 0 [if null loc0 then [genesisHash] else loc0]

-- | Unix time the test node runs at (every 'step').
gateNow :: Int64
gateNow = 1800000000

-- | The check the periodic getheaders senders make before sending to a peer.
backstopMaySend :: Env -> IO Bool
backstopMaySend env = backstopMaySendAt env gateNow

-- | 'backstopMaySend' at Unix time @t@.
backstopMaySendAt :: Env -> Int64 -> IO Bool
#ifdef HASKOIN_HEADERS_PRESYNC
backstopMaySendAt env t = not <$> headersSyncActive (eSyncs env) peerAddr t
#else
backstopMaySendAt _ _ = pure True
#endif

storedCount :: Env -> [BlockHeader] -> IO (Int, Int)
storedCount env hs = do
  entries <- readTVarIO (hcEntries (eHc env))
  onDisk <- forM hs $ \h -> isJust <$> getBlockHeader (eDb env) (computeBlockHash h)
  let inIndex = length [ () | h <- hs, Map.member (computeBlockHash h) entries ]
  pure (inIndex, length (filter id onDisk))

genesisWork :: Integer
genesisWork = headerWork genesisHdr

t0 :: Word32
t0 = bhTimestamp genesisHdr

spec :: Spec
spec = describe "secfix-haskoin-headers-presync: P2P headers anti-DoS work gate" $ do

  it "low_work_fork_headers_not_stored" $ do
    -- nMinimumChainWork far above anything a difficulty-1 chain can reach.
    let chain = mkChain 1 genesisHash t0 5000
    withEnv (netWith (2 ^ (100 :: Int))) $ \env -> do
      drive env (\_ loc -> serve chain loc)
      (inIndex, onDisk) <- storedCount env chain
      (inIndex, onDisk) `shouldBe` (0, 0)
      h <- readTVarIO (hcHeight (eHc env))
      h `shouldBe` 0

  it "low_work_short_batch_ignored: a non-full low-work batch is not stored" $ do
    let chain = mkChain 2 genesisHash t0 100
    withEnv (netWith (2 ^ (100 :: Int))) $ \env -> do
      _ <- step env chain
      storedCount env chain `shouldReturn` (0, 0)

  it "low_work_batch_with_bad_pow_punished_and_not_stored" $ do
    let good = mkChain 3 genesisHash t0 1999
        lastGood = computeBlockHash (last good)
        bad = head [ h | k <- [0 ..]
                       , let h = BlockHeader 1 lastGood (Hash256 (BS.replicate 32 9))
                                   (t0 + 2000 * 600) 0x207fffff k
                       , not (checkProofOfWork h (netPowLimit regtest)) ]
    withEnv (netWith (2 ^ (100 :: Int))) $ \env -> do
      _ <- step env (good ++ [bad])
      storedCount env good `shouldReturn` (0, 0)
#ifdef HASKOIN_HEADERS_PRESYNC
      readIORef (ePunished env) `shouldReturn` [show InvalidBlockHeader]
#endif

  it "control: a chain that reaches nMinimumChainWork is stored in full (PRESYNC then REDOWNLOAD)" $ do
    let chain = mkChain 4 genesisHash t0 5000
        perHdr = headerWork (head chain)
    -- The threshold is met at header 3000: the first 2000 are pre-synced,
    -- the next batch crosses it, the node re-downloads and stores all.
    withEnv (netWith (genesisWork + 3000 * perHdr)) $ \env -> do
      drive env (\_ loc -> serve chain loc)
      storedCount env chain `shouldReturn` (5000, 5000)
      h <- readTVarIO (hcHeight (eHc env))
      h `shouldBe` 5000

  it "backstop_getheaders_does_not_restart_presync: the periodic getheaders skips a peer in a headers sync" $ do
    -- The node's periodic getheaders fires after every second answer.  Its
    -- locator is the header tip (genesis: nothing is indexed during
    -- PRESYNC), so if it reached the syncing peer the answer would not
    -- continue the sync, abort it, and restart PRESYNC from genesis, again
    -- and again (a real PRESYNC to mainnet's minimum work spans many
    -- 120 s backstop periods).  The real chain must still be stored.
    let chain = mkChain 9 genesisHash t0 9000
        perHdr = headerWork (head chain)
    withEnv (netWith (genesisWork + 7000 * perHdr)) $ \env -> do
      driveWithBackstop env (\_ loc -> serve chain loc) (Just 2)
      storedCount env chain `shouldReturn` (9000, 9000)

  it "empty_headers_reply_ends_headers_sync: the periodic getheaders reaches the peer again" $ do
    -- Core ProcessHeadersMessage (nCount == 0) resets m_headers_sync.  If the
    -- sync stayed registered, every getheaders sender would keep skipping the
    -- peer although nothing is in flight any more.
    let chain = mkChain 10 genesisHash t0 2000
    withEnv (netWith (2 ^ (100 :: Int))) $ \env -> do
      next <- step env chain                 -- full low-work batch: PRESYNC
      next `shouldSatisfy` (/= Nothing)      -- the sync asks for more
      _ <- step env []                       -- the peer has nothing more
      backstopMaySend env `shouldReturn` True
      storedCount env chain `shouldReturn` (0, 0)

  it "headers_sync_request_expires_after_response_time: an unanswered sync getheaders is in flight for 120 s only" $ do
    -- Core MaybeSendGetHeaders: a getheaders counts as in flight for
    -- HEADERS_RESPONSE_TIME (2 min).  A syncing peer that stops answering
    -- must be probed again after that, not skipped for good.
    let chain = mkChain 11 genesisHash t0 2000
    withEnv (netWith (2 ^ (100 :: Int))) $ \env -> do
      next <- step env chain                 -- full low-work batch: PRESYNC, request sent
      next `shouldSatisfy` (/= Nothing)
      backstopMaySendAt env (gateNow + 60) `shouldReturn` False
      backstopMaySendAt env (gateNow + 121) `shouldReturn` True

  it "control: with nMinimumChainWork 0 (regtest default) headers are stored at once" $ do
    let chain = mkChain 5 genesisHash t0 2500
    withEnv regtest $ \env -> do
      drive env (\_ loc -> serve chain loc)
      storedCount env chain `shouldReturn` (2500, 2500)

  it "redownload_from_non_genesis_start_releases_all: chain_start work counts toward the threshold" $ do
    -- The node already has headers 1..1000; the peer's continuation needs
    -- PRESYNC.  REDOWNLOAD must count chain_start's work, or it never sees
    -- the threshold and the peer's whole continuation is dropped.
    let chain = mkChain 6 genesisHash t0 6000
        perHdr = headerWork (head chain)
    withEnv (netWith (genesisWork + 4000 * perHdr)) $ \env -> do
      forM_ (take 1000 chain) $ \h -> do
        r <- addHeader (eNet env) (eHc env) h True
        either (expectationFailure . ("prefix: " ++)) (\e -> putBlockHeader (eDb env) (ceHash e) h) r
      drive env (\_ loc -> serve chain loc)
      storedCount env chain `shouldReturn` (6000, 6000)

  it "redownload_swapped_low_work_chain_stores_nothing: a peer that swaps to a low-work chain after PRESYNC" $ do
    -- Chain A has the work; when the node restarts from chain_start for
    -- REDOWNLOAD the peer serves B instead, a low-work chain (5000 headers,
    -- threshold at 18000) that differs from A from its first header.  None
    -- of B, and none of A, may be stored: B ends before the threshold or the
    -- 15724-header redownload buffer could release anything, the sync then
    -- aborts, and B's batches only start a fresh PRESYNC that also ends.
    -- This does not prove the 1-bit commitment check itself (B could not be
    -- released even without it); Spec.hs "redownload verifies commitments
    -- from presync" / "redownload rejects mismatched chains" cover that.
    let a = mkChain 7 genesisHash t0 20000
        b = mkChain 8 genesisHash t0 5000
        perHdr = headerWork (head a)
        aSet = Map.fromList [ (computeBlockHash h, ()) | h <- a ]
        pick n loc
          | n == 0                    = serve a loc  -- PRESYNC starts on A
          | take 1 loc == [genesisHash] = serve b loc  -- REDOWNLOAD restart: B
          | any (`Map.member` aSet) (take 1 loc) = serve a loc
          | otherwise                 = serve b loc
    withEnv (netWith (genesisWork + 18000 * perHdr)) $ \env -> do
      drive env pick
      storedCount env b `shouldReturn` (0, 0)
      storedCount env a `shouldReturn` (0, 0)
