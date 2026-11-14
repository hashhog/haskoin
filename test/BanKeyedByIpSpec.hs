{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}

-- | secfix-haskoin-ban-keyed-by-ip (H3): bans and discouragement apply to the
-- peer's IP address, not to the IP:port pair, and the map that holds them is
-- bounded and pruned.
--
-- Core: banman.cpp keys both stores by address. @BanMan::Discourage(const
-- CNetAddr&)@ inserts the bare address into @m_discouraged@, a
-- @CRollingBloomFilter{50000, 0.000001}@ (banman.h), and @IsBanned(const
-- CNetAddr&)@ / @IsDiscouraged(const CNetAddr&)@ look the address up with no
-- port. @CNetAddr@ has no port at all; the port lives in @CService@.
--
-- haskoin keyed @pmBannedAddrs@ by the full 'SockAddr'. An inbound peer's
-- SockAddr carries its ephemeral source port, so a discouraged peer came
-- straight back from the next source port, and every ban added a new key
-- that nothing removed until an operator ran listbanned.
--
-- The cap must reach automatic discouragement only.  Core keeps operator
-- bans (@setban@) in a separate, unbounded @m_banned@, so a flood of
-- discouragements cannot evict them, @setban add@ on a merely discouraged IP
-- succeeds, and @setban remove@ leaves a discouragement in place.  Those are
-- driven through the real @setban@ dispatcher below.
module BanKeyedByIpSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.STM (atomically, modifyTVar', newTVarIO, readTVarIO)
import Control.Exception (bracket)
import Control.Monad (forM_)
import Data.Aeson (Value (..))
import qualified Data.Aeson.Key as K
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString as BS
import Data.IORef (newIORef)
import Data.Int (Int64)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import Data.Time.Clock.POSIX (getPOSIXTime)
import qualified Data.Vector as V
import Data.Word (Word16)
import Network.Socket (SockAddr (..), tupleToHostAddress)
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)
import Test.Hspec

import Haskoin.Consensus (initHeaderChain, regtest)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Mempool (defaultMempoolConfig, newMempool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc
  ( RpcConfig (..)
  , RpcResponse (..)
  , RpcServer (..)
  , defaultRpcConfig
  , handleBatchRequest
  )
import Haskoin.Storage (defaultDBConfig, defaultPruneConfig, newUTXOCache, withDB)
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Network
  ( PeerManager (..)
  , PeerManagerConfig (..)
  , PreHandshakeResult (..)
  , banPeer
  , checkPreHandshake
  , defaultPeerManagerConfig
  , getBanList
  , isDiscouraged
  , loadBanList
  , saveBanList
  , startPeerManager
  , stopPeerManager
  )

-- | Core's discouragement filter size (banman.h: @m_discouraged{50000, ...}@).
-- Written as a literal so this file compiles against a tree without the fix.
coreDiscourageCap :: Int
coreDiscourageCap = 50000

v4 :: (Int, Int, Int, Int) -> Word16 -> SockAddr
v4 (a, b, c, d) port =
  SockAddrInet (fromIntegral port)
    (tupleToHostAddress (fromIntegral a, fromIntegral b, fromIntegral c, fromIntegral d))

withPm :: (PeerManager -> IO a) -> IO a
withPm act =
  withSystemTempDirectory "haskoin-ban-keyed-by-ip" $ \dir -> do
    let cfg =
          defaultPeerManagerConfig
            { pmcDataDir = dir
            , pmcDnsSeed = False
            , pmcMaxOutbound = 0
            , pmcMaxBlockRelayOnly = 0
            }
    bracket (startPeerManager regtest cfg (\_ _ -> pure ())) stopPeerManager act

-- | A minimal live regtest 'RpcServer' (as in W125RPCErrorParitySpec) whose
-- data dir is @dir@, so setban persists to @dir/banlist.json@.
withServer :: FilePath -> (RpcServer -> IO a) -> IO a
withServer dir action =
  withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
    hc <- initHeaderChain regtest
    cache <- newUTXOCache db 1000
    mp <- newMempool regtest cache defaultMempoolConfig 0 0 (\_ -> return 0)
    fe <- newFeeEstimator
    let pmCfg =
          defaultPeerManagerConfig
            { pmcDataDir = dir
            , pmcDnsSeed = False
            , pmcMaxOutbound = 0
            , pmcMaxBlockRelayOnly = 0
            }
    bracket (startPeerManager regtest pmCfg (\_ _ -> pure ())) stopPeerManager $ \pm -> do
      threadVar <- newTVarIO Nothing
      mockTimeVar <- newTVarIO Nothing
      pauseVar <- newTVarIO False
      payjoinOffers <- newTVarIO Map.empty
      orphanRef <- newIORef emptyOrphanPool
      assumeUtxoVar <- newIORef Nothing
      let server =
            RpcServer
              { rsConfig = defaultRpcConfig {rpcDataDir = dir}, rsDB = db
              , rsHeaderChain = hc, rsPeerMgr = pm
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
      action server

-- | Call @setban@ through the real dispatcher; 'Nothing' on success, else the
-- error value.
setban :: RpcServer -> [Value] -> IO (Maybe Value)
setban server params = do
  let req =
        Object $
          KM.fromList
            [ (K.fromText "jsonrpc", String "2.0")
            , (K.fromText "id", Number 1)
            , (K.fromText "method", String "setban")
            , (K.fromText "params", Array (V.fromList params))
            ]
  resps <- handleBatchRequest server [req]
  case resps of
    (r : _) -> pure (if resError r == Null then Nothing else Just (resError r))
    [] -> fail "handleBatchRequest returned no responses"

-- | Discourage 'coreDiscourageCap' + 500 distinct IPs (10.x.y.{1,2}).
flood :: PeerManager -> IO ()
flood pm =
  forM_ (take (coreDiscourageCap + 500) [v4 (10, a, b, c) 8333 | a <- [0 .. 255], b <- [0 .. 255], c <- [1, 2]]) $
    banPeer pm

spec :: Spec
spec = describe "secfix-haskoin-ban-keyed-by-ip: bans are keyed by IP" $ do
  it "ban_applies_to_ip_not_port" $ withPm $ \pm -> do
    banPeer pm (v4 (192, 0, 2, 5) 1000)
    isDiscouraged pm (v4 (192, 0, 2, 5) 2000) >>= (`shouldBe` True)
    isDiscouraged pm (v4 (192, 0, 2, 5) 1000) >>= (`shouldBe` True)
    -- A different host is not caught by the ban.
    isDiscouraged pm (v4 (192, 0, 2, 6) 1000) >>= (`shouldBe` False)
    -- The inbound accept path refuses the same IP from a fresh source port.
    checkPreHandshake pm (v4 (192, 0, 2, 5) 54321) >>= (`shouldBe` RejectBanned)

  it "a ban via an IPv4-mapped IPv6 address covers the IPv4 address" $ withPm $ \pm -> do
    -- ::ffff:192.0.2.5 (a dual-stack listener reports IPv4 peers this way).
    banPeer pm (SockAddrInet6 1000 0 (0, 0, 0xffff, 0xc0000205) 0)
    isDiscouraged pm (v4 (192, 0, 2, 5) 2000) >>= (`shouldBe` True)
    isDiscouraged pm (v4 (192, 0, 2, 6) 2000) >>= (`shouldBe` False)

  it "5000 bans of one IP from different ports keep one ban entry" $ withPm $ \pm -> do
    forM_ [1 .. 5000] $ \p -> banPeer pm (v4 (192, 0, 2, 5) p)
    banned <- getBanList pm
    Map.size banned `shouldBe` 1

  it "the discouragement map stays within Core's 50000-entry bound" $ withPm $ \pm -> do
    let addrs =
          [ v4 (10, a, b, c) 8333
          | a <- [0 .. 255], b <- [0 .. 255], c <- [1, 2]
          ]
        n = coreDiscourageCap + 500
    forM_ (take n addrs) (banPeer pm)
    banned <- getBanList pm
    Map.size banned `shouldSatisfy` (<= coreDiscourageCap)
    -- The newest discouragement is the one that must survive.
    isDiscouraged pm (addrs !! (n - 1)) >>= (`shouldBe` True)

  it "expired bans are pruned by the peer manager timer" $ withPm $ \pm -> do
    let stale = v4 (198, 51, 100, 7) 0
    atomically $ modifyTVar' (pmBannedAddrs pm) (Map.insert stale 1)
    let waitGone :: Int -> IO Bool
        waitGone 0 = Map.notMember stale <$> readTVarIO (pmBannedAddrs pm)
        waitGone k = do
          gone <- Map.notMember stale <$> readTVarIO (pmBannedAddrs pm)
          if gone then pure True else threadDelay 500_000 >> waitGone (k - 1)
    -- peerManagerLoop ticks every 10 s; allow two ticks.
    waitGone 50 >>= (`shouldBe` True)

  it "a persisted ban still applies to the IP from any port after reload" $
    withSystemTempDirectory "haskoin-ban-persist" $ \dir -> do
      let file = dir ++ "/banlist.json"
      withPm $ \pm -> do
        banPeer pm (v4 (203, 0, 113, 9) 8333)
        saveBanList pm file
      withPm $ \pm2 -> do
        _ <- loadBanList pm2 file
        isDiscouraged pm2 (v4 (203, 0, 113, 9) 40000) >>= (`shouldBe` True)

  it "a manual setban survives a discouragement flood past the cap" $
    withSystemTempDirectory "haskoin-ban-manual" $ \dir -> withServer dir $ \server -> do
      let pm = rsPeerMgr server
      -- A 1 h ban expires before every 24 h discouragement, so it is the
      -- entry an expiry-ordered eviction would drop first.
      setban server [String "198.51.100.1", String "add", Number 3600] >>= (`shouldBe` Nothing)
      flood pm
      isDiscouraged pm (v4 (198, 51, 100, 1) 8333) >>= (`shouldBe` True)
      banned <- getBanList pm
      Map.size banned `shouldSatisfy` (<= coreDiscourageCap + 1)

  it "setban add on an IP that is only discouraged succeeds and sets the manual expiry" $
    withSystemTempDirectory "haskoin-ban-manual" $ \dir -> withServer dir $ \server -> do
      let pm = rsPeerMgr server
      banPeer pm (v4 (192, 0, 2, 9) 4000)
      setban server [String "192.0.2.9", String "add", Number 31536000] >>= (`shouldBe` Nothing)
      isDiscouraged pm (v4 (192, 0, 2, 9) 5000) >>= (`shouldBe` True)
      now <- (round <$> getPOSIXTime) :: IO Int64
      banned <- getBanList pm
      Map.size banned `shouldBe` 1
      maximum (Map.elems banned) `shouldSatisfy` (> now + 30 * 86400)

  it "setban add then remove bans and unbans the IP on every port" $
    withSystemTempDirectory "haskoin-ban-manual" $ \dir -> withServer dir $ \server -> do
      let pm = rsPeerMgr server
      setban server [String "192.0.2.11", String "add"] >>= (`shouldBe` Nothing)
      isDiscouraged pm (v4 (192, 0, 2, 11) 7000) >>= (`shouldBe` True)
      setban server [String "192.0.2.11", String "remove"] >>= (`shouldBe` Nothing)
      isDiscouraged pm (v4 (192, 0, 2, 11) 7000) >>= (`shouldBe` False)

  it "setban remove leaves an automatic discouragement in place" $
    withSystemTempDirectory "haskoin-ban-manual" $ \dir -> withServer dir $ \server -> do
      let pm = rsPeerMgr server
      banPeer pm (v4 (192, 0, 2, 10) 4000)
      r <- setban server [String "192.0.2.10", String "remove"]
      r `shouldSatisfy` (/= Nothing)
      isDiscouraged pm (v4 (192, 0, 2, 10) 4000) >>= (`shouldBe` True)

  it "a manual ban reloaded from banlist.json stays outside the cap" $
    withSystemTempDirectory "haskoin-ban-manual" $ \dir -> do
      withServer dir $ \server ->
        setban server [String "198.51.100.2", String "add", Number 3600] >>= (`shouldBe` Nothing)
      withPm $ \pm2 -> do
        _ <- loadBanList pm2 (dir </> "banlist.json")
        flood pm2
        isDiscouraged pm2 (v4 (198, 51, 100, 2) 8333) >>= (`shouldBe` True)
