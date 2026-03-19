{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | Stub ZMQ4 module (no-op implementation for building without libzmq)
module System.ZMQ4
  ( Context
  , Socket
  , Pub(..)
  , Restrict
  , Flag(..)
  , Switch(..)
  , context
  , socket
  , bind
  , close
  , term
  , sendMulti
  , setSendHighWM
  , setTcpKeepAlive
  , setLinger
  , restrict
  ) where

import Data.ByteString (ByteString)
import Data.List.NonEmpty (NonEmpty)

data Context = Context
data Socket a = Socket
data Pub = Pub
newtype Restrict a = Restrict a

data Flag = SendMore
data Switch = On | Off

context :: IO Context
context = return Context

socket :: Context -> Pub -> IO (Socket Pub)
socket _ _ = return Socket

bind :: Socket a -> String -> IO ()
bind _ _ = return ()

close :: Socket a -> IO ()
close _ = return ()

term :: Context -> IO ()
term _ = return ()

sendMulti :: Socket a -> NonEmpty ByteString -> IO ()
sendMulti _ _ = return ()

setSendHighWM :: Restrict Int -> Socket a -> IO ()
setSendHighWM _ _ = return ()

setTcpKeepAlive :: Switch -> Socket a -> IO ()
setTcpKeepAlive _ _ = return ()

setLinger :: Restrict Int -> Socket a -> IO ()
setLinger _ _ = return ()

restrict :: a -> Restrict a
restrict = Restrict
