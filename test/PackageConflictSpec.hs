{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | A package must not double-spend a coin an in-pool transaction already
-- spends.
--
-- Core validation.cpp MemPoolAccept::PreChecks collects GetConflictTx for
-- every input on the package path too (AcceptMultipleTransactions), and a
-- package with conflicts is only admitted through PackageRBFChecks: exactly
-- one parent and one child, no in-mempool ancestors, PaysForRBF over every
-- evicted tx, package feerate above the parent's own, the cluster limits of
-- the new two-tx cluster, and an improved feerate diagram.  The conflicts are
-- then evicted.
--
-- haskoin's acceptPackage resolved package inputs from the chain UTXO set and
-- never looked at mpByOutpoint, and its insert overwrote mpByOutpoint, so the
-- pool could hold two spends of one coin (and getblocktemplate could build an
-- invalid block from it).
--
-- The assertions match on the shown error text, not on a constructor, so this
-- file compiles against the base commit and fails there on the assertions.
module PackageConflictSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, atomically, readTVarIO)
import Data.IORef (newIORef)
import Data.List (isInfixOf)
import qualified Data.Aeson as A
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Aeson.Key as Key
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Vector as V
import Data.Serialize (encode)
import Data.Word (Word8, Word64)
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeWtxid, sha256)
import Haskoin.Consensus (regtest, initHeaderChain)
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, addUTXO
  , UTXOEntry(..), UTXOCache )
import Haskoin.Mempool
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc
  ( RpcServer(..), RpcResponse(..), defaultRpcConfig, RpcConfig(..)
  , handleBatchRequest )

-- P2WSH of OP_DROP OP_TRUE OP_DROP: anyone can spend it with any one
-- witness item before the script.
dropScript :: BS.ByteString
dropScript = BS.pack [0x75, 0x51, 0x75]

dropSpk :: BS.ByteString
dropSpk = BS.pack [0x00, 0x20] <> sha256 dropScript

coinOf :: Word8 -> OutPoint
coinOf b = OutPoint (TxId (Hash256 (BS.replicate 32 b))) 0

-- | The coin the in-pool tx A spends and the package parent P double-spends.
coinO, coinB, coinM :: OutPoint
coinO = coinOf 0x71
coinB = coinOf 0x72
coinM = coinOf 0x73

mkTxWith :: [BS.ByteString] -> [OutPoint] -> Word64 -> Tx
mkTxWith wit ops out = Tx
  { txVersion = 2
  , txInputs  = [TxIn op BS.empty 0xfffffffd | op <- ops]
  , txOutputs = [TxOut out dropSpk]
  , txWitness = [wit | _ <- ops]
  , txLockTime = 0 }

mkTx :: [OutPoint] -> Word64 -> Tx
mkTx = mkTxWith [BS.replicate 80 0x11, BS.replicate 80 0x22, dropScript]

out0 :: Tx -> OutPoint
out0 t = OutPoint (computeTxId t) 0

-- | In-pool conflict A (fee 10_000) and its descendant D (fee 5_000).
txA, txD :: Tx
txA = mkTx [coinO] 90_000
txD = mkTx [out0 txA] 85_000

withPool :: (Mempool -> IO ()) -> IO ()
withPool action = withEnv $ \_ _ mp -> action mp

withEnv :: (FilePath -> UTXOCache -> Mempool -> IO ()) -> IO ()
withEnv action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-pkgconflict-")
    removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      cache <- newUTXOCache db 1000
      atomically $ mapM_ (\op -> addUTXO cache op (UTXOEntry (TxOut 100_000 dropSpk) 1 False False))
                         [coinO, coinB, coinM]
      mp <- newMempool regtest cache defaultMempoolConfig 0 0 (\_ -> return 0)
      action dir cache mp

-- | A and D admitted on their own.
seedConflict :: Mempool -> IO ()
seedConflict mp = do
  ra <- addTransaction mp txA
  ra `shouldBe` Right (computeTxId txA)
  rd <- addTransaction mp txD
  rd `shouldBe` Right (computeTxId txD)

inPool :: Mempool -> Tx -> IO Bool
inPool mp t = Map.member (computeTxId t) <$> readTVarIO (mpEntries mp)

-- | The invariant the bug broke: no two pool entries spend one outpoint, and
-- mpByOutpoint names the entry that really spends each outpoint.
noDoubleSpend :: Mempool -> IO ()
noDoubleSpend mp = do
  entries <- readTVarIO (mpEntries mp)
  byOp <- readTVarIO (mpByOutpoint mp)
  let spends = [ (txInPrevOutput i, meTxId e)
               | e <- Map.elems entries, i <- txInputs (meTransaction e) ]
      ops = map fst spends
  length ops `shouldBe` Set.size (Set.fromList ops)
  mapM_ (\(op, t) -> Map.lookup op byOp `shouldBe` Just t) spends

pkg :: [Tx] -> TxPackage
pkg ts = TxPackage (init ts) (last ts)

rejectedWith :: String -> Either PackageError [TxId] -> Expectation
rejectedWith needle r = case r of
  Left e  -> show e `shouldSatisfy` (needle `isInfixOf`)
  Right t -> expectationFailure ("package admitted: " ++ show t)

-- | Mempool and A/D state after a rejected package: A and D unchanged, no
-- package tx admitted.
conflictsKept :: Mempool -> [Tx] -> Expectation
conflictsKept mp ts = do
  inPool mp txA `shouldReturn` True
  inPool mp txD `shouldReturn` True
  mapM_ (\t -> inPool mp t `shouldReturn` False) ts
  noDoubleSpend mp

spec :: Spec
spec = describe "acceptPackage against in-pool conflicts (package RBF)" $ do

  it "package-conflict-underpaying-rejected: a 1p1c package paying less than A+D is refused and A, D stay" $
    withPool $ \mp -> do
      seedConflict mp
      let p = mkTx [coinO] 99_000           -- fee 1_000, double-spends A's coin
          c = mkTx [out0 p] 98_000          -- fee 1_000
      r <- acceptPackage (pkg [p, c]) mp
      rejectedWith "package RBF failed: insufficient anti-DoS fees" r
      conflictsKept mp [p, c]

  it "package-conflict-rbf-replaces: a 1p1c package that pays for A+D replaces both" $
    withPool $ \mp -> do
      seedConflict mp
      let p = mkTx [coinO] 99_000           -- fee 1_000 (below A alone)
          c = mkTx [out0 p] 70_000          -- fee 29_000: package pays 30_000 > 15_000
      r <- acceptPackage (pkg [p, c]) mp
      r `shouldBe` Right [computeTxId p, computeTxId c]
      inPool mp txA `shouldReturn` False
      inPool mp txD `shouldReturn` False
      inPool mp p `shouldReturn` True
      inPool mp c `shouldReturn` True
      noDoubleSpend mp

  it "package-conflict-rbf-cpfp-conflict-replaces: a package beating the merged feerate of a conflict and its high-feerate child replaces both" $
    withPool $ \mp -> do
      -- A2 pays 1_000 and its child D2 pays 20_000, so Core linearizes them as
      -- one chunk (~103 sat/vB).  The package pays 30_000 (~147 sat/vB):
      -- better than that chunk, worse than D2 alone.  Pick amounts whose
      -- txids put D2 BEFORE A2 in txid order, the order the eviction set
      -- comes back in, so a diagram built from it without sorting parents
      -- first sees D2 as its own leading chunk and refuses the package.
      let (a2, d2) = head
            [ (a, d) | n <- [1 .. 200 :: Word64]   -- n = 0 would make A2 == P
                     , let a = mkTx [coinO] (99_000 - n)
                           d = mkTx [out0 a] (79_000 - n)
                     , computeTxId d < computeTxId a ]
      ra <- addTransaction mp a2
      ra `shouldBe` Right (computeTxId a2)
      rd <- addTransaction mp d2
      rd `shouldBe` Right (computeTxId d2)
      let p = mkTx [coinO] 99_000           -- fee 1_000
          c = mkTx [out0 p] 70_000          -- fee 29_000
      r <- acceptPackage (pkg [p, c]) mp
      r `shouldBe` Right [computeTxId p, computeTxId c]
      inPool mp a2 `shouldReturn` False
      inPool mp d2 `shouldReturn` False
      noDoubleSpend mp

  it "package-conflict-not-1p1c-rejected: a conflicting package with two parents is refused" $
    withPool $ \mp -> do
      seedConflict mp
      let p1 = mkTx [coinO] 99_000
          p2 = mkTx [coinB] 99_000
          c  = mkTx [out0 p1, out0 p2] 100_000   -- fee 98_000
      r <- acceptPackage (pkg [p1, p2, c]) mp
      rejectedWith "package RBF failed: package must be 1-parent-1-child" r
      conflictsKept mp [p1, p2, c]

  it "package-conflict-mempool-ancestor-rejected: a conflicting parent with an in-pool parent is refused" $
    withPool $ \mp -> do
      seedConflict mp
      let m = mkTx [coinM] 90_000
      rm <- addTransaction mp m
      rm `shouldBe` Right (computeTxId m)
      let p = mkTx [coinO, out0 m] 189_000       -- fee 1_000, spends in-pool M
          c = mkTx [out0 p] 150_000              -- fee 39_000
      r <- acceptPackage (pkg [p, c]) mp
      rejectedWith "package RBF failed: new transaction cannot have mempool ancestors" r
      conflictsKept mp [p, c]
      inPool mp m `shouldReturn` True

  it "package-conflict-parent-feerate-rejected: a child that does not raise the package feerate above the parent's is refused" $
    withPool $ \mp -> do
      seedConflict mp
      let p = mkTx [coinO] 60_000           -- fee 40_000: pays for A+D alone
          c = mkTx [out0 p] 59_900          -- fee 100: drags the package rate down
      r <- acceptPackage (pkg [p, c]) mp
      rejectedWith "package RBF failed: package feerate is less than or equal to parent feerate" r
      conflictsKept mp [p, c]

  it "package-conflict-invalid-child-keeps-conflicts: a child failing script checks leaves A and D in the pool and P out" $
    withPool $ \mp -> do
      seedConflict mp
      let p = mkTx [coinO] 99_000
          -- witness script does not hash to the P2WSH program: script failure
          c = mkTxWith [BS.replicate 80 0x11, BS.pack [0x51, 0x51]] [out0 p] 70_000
      r <- acceptPackage (pkg [p, c]) mp
      rejectedWith "ErrScriptVerificationFailed" r
      conflictsKept mp [p, c]

  it "package-conflict-truc-after-evict-restores: a package the real insert refuses after eviction (TRUC) puts A and D back" $
    withPool $ \mp -> do
      seedConflict mp
      -- The dry run leaves TRUC to the real insert (it needs the parent in
      -- the pool), so this is the one refusal that comes AFTER the
      -- conflicts were evicted: a v2 child may not spend an unconfirmed v3
      -- parent (BIP-431 version inheritance).  The pool must end as it
      -- started.
      let p = (mkTx [coinO] 99_000) { txVersion = 3 }   -- fee 1_000
          c = mkTx [out0 p] 70_000                       -- v2, fee 29_000
      r <- acceptPackage (pkg [p, c]) mp
      rejectedWith "ErrTrucViolation" r
      conflictsKept mp [p, c]

  it "package-conflict-parent-feerate-exact: a package feerate above the parent's by less than 1 sat/kvB is still a replacement" $
    withPool $ \mp -> do
      -- Core compares CFeeRates as exact fractions (FeeRateCompare), not as
      -- truncated sat/kvB.  Find a package whose feerate is strictly above
      -- the parent's but truncates to the same sat/kvB.  One satoshi moves
      -- the package rate by 1000/vsize sat/kvB, so the child needs many
      -- outputs (package > 1000 vB).  The conflict is a lone cheap A3, so the
      -- PaysForRBF and diagram checks pass and only this comparison decides.
      let a3 = mkTx [coinB] 99_000                    -- fee 1_000
          parentOf f = mkTx [coinB] (100_000 - f)
          pv = fromIntegral (calculateVSize (parentOf 0)) :: Integer
          childOf par n v = Tx
            { txVersion = 2
            , txInputs  = [TxIn (out0 par) BS.empty 0xfffffffd]
            , txOutputs = TxOut v dropSpk : replicate (n - 1) (TxOut 1_000 dropSpk)
            , txWitness = [[BS.replicate 80 0x11, BS.replicate 80 0x22, dropScript]]
            , txLockTime = 0 }
          picks =
            [ (pf, n, tot)
            | n <- [20 .. 40]
            , let cv = fromIntegral (calculateVSize (childOf (parentOf 0) n 0)) :: Integer
                  tv = pv + cv
            , pf <- [3_000 .. 6_000 :: Integer]
            , let tot = (pf * tv) `div` pv + 1
            , (tot * 1000) `div` tv == (pf * 1000) `div` pv
            , tot * pv > pf * tv
            , tot + fromIntegral (n - 1) * 1_000 < 99_000 ]
      (pf, n, tot) <- case picks of
             (x : _) -> return x
             [] -> fail "no (parent fee, child outputs) pair hits the truncation case"
      let p = parentOf (fromIntegral pf)
          change = (100_000 - pf) - (tot - pf) - fromIntegral (n - 1) * 1_000
          c = childOf p n (fromIntegral change)
      ra <- addTransaction mp a3
      ra `shouldBe` Right (computeTxId a3)
      r <- acceptPackage (pkg [p, c]) mp
      r `shouldBe` Right [computeTxId p, computeTxId c]
      inPool mp a3 `shouldReturn` False
      noDoubleSpend mp

  it "package-conflict-maxfeerate-keeps-conflicts: submitpackage refusing a package RBF on maxfeerate leaves A and D in the pool" $
    withEnv $ \dir cache mp -> do
      seedConflict mp
      -- Core checks client_maxfeerate per tx in AcceptMultipleTransactions'
      -- PreChecks loop, before PackageRBFChecks, so the conflicts are never
      -- touched.  C pays ~280 sat/vB against a 100 sat/vB cap.
      let p = mkTx [coinO] 99_000
          c = mkTx [out0 p] 70_000
      res <- withServer dir cache mp $ \server ->
        rpc server "submitpackage" [A.toJSON [hexTx p, hexTx c], A.Number 0.001]
      let get k = case res of
            A.Object o -> KM.lookup k o
            _ -> Nothing
          cErr = case get "tx-results" of
            Just (A.Object o) -> case KM.lookup (Key.fromText (wtx c)) o of
              Just (A.Object co) -> KM.lookup "error" co
              _ -> Nothing
            _ -> Nothing
      get "package_msg" `shouldBe` Just (A.String "transaction failed")
      cErr `shouldBe` Just (A.String "max feerate exceeded")
      conflictsKept mp [p, c]

  it "package-conflict-submitpackage-replaced: submitpackage lists A and D in replaced-transactions" $
    withEnv $ \dir cache mp -> do
      seedConflict mp
      let p = mkTx [coinO] 99_000
          c = mkTx [out0 p] 70_000
      res <- withServer dir cache mp $ \server ->
        rpc server "submitpackage" [A.toJSON [hexTx p, hexTx c]]
      let get k = case res of
            A.Object o -> KM.lookup k o
            _ -> Nothing
          -- Core rpc/mempool.cpp: std::set<Txid>, i.e. ordered by the
          -- internal byte order, which is TxId's Ord.
          expected = map hex (Set.toList (Set.fromList [computeTxId txA, computeTxId txD]))
      get "package_msg" `shouldBe` Just (A.String "success")
      get "replaced-transactions" `shouldBe` Just (A.toJSON expected)
      inPool mp txA `shouldReturn` False
      inPool mp p `shouldReturn` True
      noDoubleSpend mp

--------------------------------------------------------------------------------
-- RPC plumbing (as PackageAcceptChildSpec)
--------------------------------------------------------------------------------

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withServer :: FilePath -> UTXOCache -> Mempool -> (RpcServer -> IO a) -> IO a
withServer dir cache mp action =
    withDB (defaultDBConfig (dir </> "rpcdb")) $ \db -> do
      hc <- initHeaderChain regtest
      fe <- newFeeEstimator
      let pmCfg = defaultPeerManagerConfig { pmcDataDir = dir, pmcDnsSeed = False }
      bracket (startPeerManager regtest pmCfg liveNoopHandler) stopPeerManager $ \pm -> do
        threadVar     <- newTVarIO Nothing
        mockTimeVar   <- newTVarIO Nothing
        pauseVar      <- newTVarIO False
        payjoinOffers <- newTVarIO Map.empty
        orphanRef     <- newIORef emptyOrphanPool
        assumeUtxoVar <- newIORef Nothing
        let cfg = defaultRpcConfig { rpcDataDir = dir }
        action RpcServer
              { rsConfig = cfg, rsDB = db, rsHeaderChain = hc, rsPeerMgr = pm
              , rsMempool = mp, rsFeeEst = fe, rsUTXOCache = cache
              , rsNetwork = regtest, rsBlockStore = Nothing
              , rsThread = threadVar, rsMockTime = mockTimeVar
              , rsWalletMgr = Nothing, rsStartTime = 0
              , rsCookieFile = dir </> ".cookie", rsCookiePassword = T.empty
              , rsBlockSubmissionPaused = pauseVar, rsIndexMgr = Nothing
              , rsPruneConfig = defaultPruneConfig, rsAsmapData = BS.empty
              , rsPayjoinOffers = payjoinOffers, rsPayjoinConfig = defaultPayjoinConfig
              , rsOrphanPool = orphanRef, rsAssumeUtxo = assumeUtxoVar
              }

rpc :: RpcServer -> T.Text -> [A.Value] -> IO A.Value
rpc server m ps = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String m), ("params", A.Array (V.fromList ps)) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  resError resp `shouldBe` A.Null
  body <- maybe (fail "not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o | Just r <- KM.lookup "result" o -> return r
    other -> fail ("unexpected response: " ++ show other)

hexTx :: Tx -> A.Value
hexTx = A.String . TE.decodeUtf8 . B16.encode . encode

wtx :: Tx -> T.Text
wtx t = hex (TxId (getWtxidHash (computeWtxid t)))

hex :: TxId -> T.Text
hex (TxId (Hash256 bs)) = T.pack (concatMap byte (reverse (BS.unpack bs)))
  where byte b = [d (b `div` 16), d (b `mod` 16)]
        d n = "0123456789abcdef" !! fromIntegral (n :: Word8)
