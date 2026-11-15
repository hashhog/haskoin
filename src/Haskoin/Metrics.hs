-- | Listener settings for the Prometheus @/metrics@ endpoint.
--
-- Bitcoin Core has no metrics listener at all; this one is a haskoin
-- addition, unauthenticated and on by default.  It used to be started with
-- @Warp.run@, which binds every interface (0.0.0.0 and [::]) and accepts any
-- number of connections, so anyone who could reach the host could scrape it
-- and hold open as many sockets as they liked.  It now binds the loopback
-- address unless the operator names another with @--metricsbind@ (the same
-- opt-in Core uses for its RPC server, @-rpcbind@), drops idle clients after
-- 'metricsIdleTimeoutSecs', and refuses connections beyond
-- 'metricsMaxConnections'.
module Haskoin.Metrics
  ( defaultMetricsBind
  , metricsMaxConnections
  , metricsIdleTimeoutSecs
  , metricsSettings
  ) where

import Data.IORef (atomicModifyIORef', newIORef)
import Data.String (fromString)
import qualified Network.Wai.Handler.Warp as Warp

-- | Address the metrics listener binds when @--metricsbind@ is not given.
defaultMetricsBind :: String
defaultMetricsBind = "127.0.0.1"

-- | Connections served at once.  A Prometheus scraper uses one; the rest
-- are closed as soon as they are accepted.
metricsMaxConnections :: Int
metricsMaxConnections = 16

-- | Seconds a client may stay silent before Warp closes the connection.
metricsIdleTimeoutSecs :: Int
metricsIdleTimeoutSecs = 30

-- | Warp settings for the metrics listener on @host@:@port@.
--
-- Warp brackets every accepted connection with @settingsOnOpen@ /
-- @settingsOnClose@, and calls @settingsOnClose@ even when @settingsOnOpen@
-- returned 'False', so counting in one and uncounting in the other keeps
-- the number exact.
metricsSettings :: String -> Int -> IO Warp.Settings
metricsSettings host port = do
  open <- newIORef (0 :: Int)
  let onOpen _ = atomicModifyIORef' open $ \n ->
        let n' = n + 1 in (n', n' <= metricsMaxConnections)
      onClose _ = atomicModifyIORef' open $ \n -> (n - 1, ())
  pure $ Warp.setHost (fromString host)
       $ Warp.setPort port
       $ Warp.setTimeout metricsIdleTimeoutSecs
       $ Warp.setOnOpen onOpen
       $ Warp.setOnClose onClose
       $ Warp.defaultSettings
