{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | The Prometheus metrics listener binds loopback by default
-- (secfix-haskoin-metrics-bind-all, audit H8).
--
-- Core has no metrics listener.  haskoin's was started with @Warp.run@,
-- which binds every interface, so the unauthenticated endpoint was on
-- 0.0.0.0 wherever the node ran, with no cap on open connections.
--
-- These tests start the real @haskoin@ binary on regtest (the build puts
-- it on PATH through @build-tool-depends@; @HASKOIN_BIN@ overrides) and
-- probe its metrics port from outside, so they compile against any
-- revision of the library and fail on the assertion, not the build.
module MetricsBindSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Exception (SomeException, bracket, try, finally)
import Control.Monad (forM, forM_, unless)
import qualified Data.ByteString as BS
import Data.Maybe (fromMaybe)
import Network.Socket
import qualified Network.Socket.ByteString as NSB
import System.Directory (findExecutable)
import System.Environment (lookupEnv)
import System.Exit (ExitCode)
import System.IO (Handle, IOMode (WriteMode), hClose, openFile)
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)
import System.Process
import System.Timeout (timeout)
import Test.Hspec

-- | A port nothing is listening on right now.
freePort :: IO PortNumber
freePort = bracket (socket AF_INET Stream defaultProtocol) close $ \s -> do
  bind s (SockAddrInet 0 (tupleToHostAddress (127, 0, 0, 1)))
  SockAddrInet p _ <- getSocketName s
  pure p

-- | This host's primary non-loopback IPv4 address, found by "connecting" a
-- UDP socket toward TEST-NET-1 (no packet is sent).  Nothing when the host
-- has no such address.
nonLoopbackAddr :: IO (Maybe HostAddress)
nonLoopbackAddr = do
  r <- try $ bracket (socket AF_INET Datagram defaultProtocol) close $ \s -> do
    connect s (SockAddrInet 9 (tupleToHostAddress (192, 0, 2, 1)))
    getSocketName s
  pure $ case r of
    Right (SockAddrInet _ h)
      | let (a, _, _, _) = hostAddressToTuple h, a /= 127, a /= 0 -> Just h
    Right _ -> Nothing
    Left (_ :: SomeException) -> Nothing

loopback :: HostAddress
loopback = tupleToHostAddress (127, 0, 0, 1)

-- | Open a TCP connection, or Nothing if it is refused or times out.
tryConnect :: HostAddress -> PortNumber -> IO (Maybe Socket)
tryConnect h p = do
  s <- socket AF_INET Stream defaultProtocol
  r <- try (timeout 5_000_000 (connect s (SockAddrInet p h)))
  case r of
    Right (Just ()) -> pure (Just s)
    Right Nothing -> close s >> pure Nothing
    Left (_ :: SomeException) -> close s >> pure Nothing

-- | Everything the server sends on @s@ until it closes (bounded).
recvAll :: Socket -> IO BS.ByteString
recvAll s = go []
  where
    go acc = do
      r <- try (timeout 10_000_000 (NSB.recv s 65536))
             :: IO (Either SomeException (Maybe BS.ByteString))
      case r of
        Right (Just c) | not (BS.null c) -> go (c : acc)
        _ -> pure (BS.concat (reverse acc))

-- | Send a GET /metrics on an open socket and return the raw reply ("" when
-- the server closed the connection without answering).
getOn :: Socket -> IO BS.ByteString
getOn s = do
  _ <- try (NSB.sendAll s "GET /metrics HTTP/1.0\r\nHost: x\r\n\r\n")
         :: IO (Either SomeException ())
  recvAll s

-- | GET /metrics on a fresh connection; Nothing if the connect fails.
scrape :: HostAddress -> PortNumber -> IO (Maybe BS.ByteString)
scrape h p = do
  ms <- tryConnect h p
  case ms of
    Nothing -> pure Nothing
    Just s -> Just <$> (getOn s `finally` close s)

answered :: Maybe BS.ByteString -> Bool
answered (Just b) = "HTTP/1." `BS.isPrefixOf` b && "bitcoin_blocks_total" `BS.isInfixOf` b
answered Nothing = False

haskoinBin :: IO FilePath
haskoinBin = do
  env <- lookupEnv "HASKOIN_BIN"
  case env of
    Just b | not (null b) -> pure b
    _ -> fromMaybe (error "haskoin binary not on PATH; set HASKOIN_BIN")
           <$> findExecutable "haskoin"

-- | Run a regtest node with the metrics listener on @mport@ plus @extra@
-- arguments, wait until 127.0.0.1:@mport@ (or @probe@) accepts, then run
-- the action.  Fails if the node exits or never comes up.
withNode :: [String] -> HostAddress -> (PortNumber -> IO a) -> IO a
withNode extra probe act = withSystemTempDirectory "haskoin-metrics-bind" $ \dir -> do
  bin <- haskoinBin
  [rpc, p2p, mport] <- forM [(), (), ()] (const freePort)
  logH <- openFile (dir </> "node.log") WriteMode
  let args =
        [ "--datadir=" ++ (dir </> "data"), "--network=Regtest", "node"
        , "--rpcport=" ++ show rpc, "--rpcuser=t", "--rpcpassword=t"
        , "--port=" ++ show p2p, "--listen=False", "--nodnsseed"
        , "--discover=False", "--connect=127.0.0.1:1"
        , "--metricsport=" ++ show mport, "--par=1", "--printtoconsole"
        ] ++ extra
      cp = (proc bin args) { std_out = UseHandle logH, std_err = UseHandle logH }
  bracket (createProcess cp) (stop logH) $ \(_, _, _, ph) -> do
    up <- waitUp ph mport (120 :: Int)
    unless up $ do
      hClose logH
      out <- readFile (dir </> "node.log")
      expectationFailure $ "metrics listener never came up on the "
        ++ (if probe == loopback then "loopback" else "non-loopback")
        ++ " address"
        ++ " for args " ++ show extra ++ "\n--- node log tail ---\n"
        ++ unlines (reverse (take 15 (reverse (lines out))))
    act mport
  where
    waitUp :: ProcessHandle -> PortNumber -> Int -> IO Bool
    waitUp _ _ 0 = pure False
    waitUp ph p n = do
      ex <- getProcessExitCode ph :: IO (Maybe ExitCode)
      case ex of
        Just _ -> pure False
        Nothing -> do
          ms <- tryConnect probe p
          case ms of
            Just s -> close s >> pure True
            Nothing -> threadDelay 1_000_000 >> waitUp ph p (n - 1)
    stop :: Handle -> (a, b, c, ProcessHandle) -> IO ()
    stop logH (_, _, _, ph) = do
      terminateProcess ph
      _ <- timeout 30_000_000 (waitForProcess ph)
      _ <- try (hClose logH) :: IO (Either SomeException ())
      pure ()

spec :: Spec
spec = describe "Prometheus metrics listener (audit H8; Core has no such listener)" $ do

  it "metrics_binds_loopback_by_default" $ do
    mext <- nonLoopbackAddr
    case mext of
      Nothing -> pendingWith "host has no non-loopback IPv4 address to probe"
      Just ext -> withNode [] loopback $ \p -> do
        r <- scrape loopback p
        r `shouldSatisfy` answered
        -- Only a refused connect counts: a connect that times out (a
        -- firewall dropping packets) has not shown what is bound.
        s <- socket AF_INET Stream defaultProtocol
        r <- try (timeout 5_000_000 (connect s (SockAddrInet p ext)))
               :: IO (Either SomeException (Maybe ()))
        close s
        -- The address itself is not printed: it is this host's LAN address.
        ("metrics port on the non-loopback address: " ++ case r of
            Left _ -> "refused"
            Right Nothing -> "connect timed out (inconclusive)"
            Right (Just ()) -> "accepted a connection")
          `shouldBe` "metrics port on the non-loopback address: refused"

  it "metrics_bind_opt_in_all_interfaces (--metricsbind=0.0.0.0)" $ do
    mext <- nonLoopbackAddr
    case mext of
      Nothing -> pendingWith "host has no non-loopback IPv4 address to probe"
      Just ext -> withNode ["--metricsbind=0.0.0.0"] ext $ \p -> do
        r <- scrape ext p
        r `shouldSatisfy` answered

  it "metrics_connection_cap (16 open; the 17th is closed unanswered, a freed slot is reused)" $
    withNode [] loopback $ \p -> do
      held <- forM [1 .. 16 :: Int] $ \_ -> tryConnect loopback p
      length [() | Just _ <- held] `shouldBe` 16
      threadDelay 1_000_000
      over <- scrape loopback p
      (case held of
         (Just s0 : _) -> close s0
         _ -> pure ())
      threadDelay 1_000_000
      again <- scrape loopback p
      forM_ (drop 1 held) (maybe (pure ()) close)
      (answered over, answered again) `shouldBe` (False, True)
