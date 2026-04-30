{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : System.ZMQ4
-- Description : Direct-ABI Haskell wrapper for libzmq.so.5
--
-- Provides the publisher (and minimal subscriber, for tests) surface that
-- 'Haskoin.Rpc' uses to deliver Bitcoin-Core-compatible 3-frame ZMQ
-- notifications.
--
-- == Wire-up
--
-- * @cbits\/zmq_stubs.c@ holds C wrappers around the libzmq 4.x ABI.
--   We deliberately do not include @<zmq.h>@: the Debian shared-library
--   package (libzmq5) does not always carry the dev headers
--   (libzmq3-dev). The forward declarations in @zmq_stubs.c@ mirror the
--   stable ZMQ 4.x ABI per <https:\/\/api.zeromq.org\/4-3:zmq>.
--
-- * @haskoin.cabal@'s library section adds:
--
--     > c-sources:       cbits/zmq_stubs.c, ...
--     > extra-libraries: :libzmq.so.5, ...
--
--   The @:libname@ syntax is the GNU @ld@ exact-name form. Cabal\/GHC
--   pass it through as-is, and the resulting binary's @ldd@ shows
--   @libzmq.so.5@ (verified during the patch that introduced this
--   module). No @libzmq3-dev@ headers are required at build time —
--   only the @libzmq.so.5@ shared object at link\/run time, which is
--   present on every Debian system that has @libzmq5@ installed.
--
-- == Lineage
--
-- Mirrors the camlcoin pattern (@camlcoin\/lib\/zmq_stubs.c@,
-- @camlcoin\/lib\/zmq_bindings.ml@, commit @23c02ac@). The OCaml side
-- exposes a @[topic; body; seq_le32]@ atomic three-frame send; this
-- Haskell binding does the same shape via 'sendMulti' over a
-- 'NonEmpty' 'ByteString' so existing callers in @Haskoin.Rpc@ keep
-- working unchanged.
module System.ZMQ4
  ( -- * Types
    Context
  , Socket
  , Pub(..)
  , Sub(..)
  , SocketType(..)
  , Restrict
  , Flag(..)
  , Switch(..)
    -- * Lifecycle
  , context
  , term
  , socket
  , bind
  , connect
  , close
    -- * Sending
  , send
  , sendMulti
    -- * Receiving (subscribers)
  , receive
  , receiveMulti
  , subscribe
    -- * Options
  , setSendHighWM
  , setReceiveHighWM
  , setLinger
  , setTcpKeepAlive
  , restrict
  ) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.MVar
import Control.Exception (Exception, throwIO, mask_)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BSU
import Data.List.NonEmpty (NonEmpty(..))
import qualified Data.List.NonEmpty as NE
import Foreign.C.String (CString, peekCString, withCStringLen)
import Foreign.C.Types (CInt(..), CSize(..))
import Foreign.ForeignPtr (ForeignPtr, FinalizerPtr, newForeignPtr,
                           withForeignPtr, finalizeForeignPtr)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, nullPtr, castPtr)

--------------------------------------------------------------------------------
-- FFI imports against haskoin_zmq_* (cbits/zmq_stubs.c)
--------------------------------------------------------------------------------

foreign import ccall safe "haskoin_zmq_ctx_new"
  c_ctx_new :: IO (Ptr ())

foreign import ccall safe "haskoin_zmq_ctx_term"
  c_ctx_term :: Ptr () -> IO CInt

-- | @c_ctx_term@ as a finaliser, for ForeignPtr.
foreign import ccall safe "&haskoin_zmq_ctx_term"
  c_ctx_term_finalizer :: FinalizerPtr ()

foreign import ccall safe "haskoin_zmq_pub_socket"
  c_pub_socket :: Ptr () -> IO (Ptr ())

foreign import ccall safe "haskoin_zmq_sub_socket"
  c_sub_socket :: Ptr () -> IO (Ptr ())

foreign import ccall safe "haskoin_zmq_close"
  c_close :: Ptr () -> IO CInt

foreign import ccall safe "&haskoin_zmq_close"
  c_close_finalizer :: FinalizerPtr ()

foreign import ccall safe "haskoin_zmq_bind"
  c_bind :: Ptr () -> CString -> IO CInt

foreign import ccall safe "haskoin_zmq_connect"
  c_connect :: Ptr () -> CString -> IO CInt

foreign import ccall safe "haskoin_zmq_set_sndhwm"
  c_set_sndhwm :: Ptr () -> CInt -> IO CInt

foreign import ccall safe "haskoin_zmq_set_rcvhwm"
  c_set_rcvhwm :: Ptr () -> CInt -> IO CInt

foreign import ccall safe "haskoin_zmq_set_linger"
  c_set_linger :: Ptr () -> CInt -> IO CInt

foreign import ccall safe "haskoin_zmq_set_tcp_keepalive"
  c_set_keepalive :: Ptr () -> CInt -> IO CInt

foreign import ccall safe "haskoin_zmq_subscribe"
  c_subscribe :: Ptr () -> CString -> CSize -> IO CInt

foreign import ccall safe "haskoin_zmq_send_frame"
  c_send_frame :: Ptr () -> Ptr () -> CSize -> CInt -> CInt -> IO CInt

foreign import ccall safe "haskoin_zmq_send_three"
  c_send_three
    :: Ptr ()
    -> Ptr () -> CSize
    -> Ptr () -> CSize
    -> Ptr () -> CSize
    -> IO CInt

foreign import ccall safe "haskoin_zmq_recv_into"
  c_recv_into :: Ptr () -> Ptr () -> CSize -> CInt -> IO CInt

foreign import ccall safe "haskoin_zmq_errno"
  c_errno :: IO CInt

foreign import ccall safe "haskoin_zmq_strerror"
  c_strerror :: CInt -> IO CString

--------------------------------------------------------------------------------
-- Public types
--------------------------------------------------------------------------------

-- | A libzmq context. One per process is the canonical pattern (Bitcoin
-- Core uses a single @CZMQNotificationInterface@). The 'ForeignPtr'
-- finaliser calls @zmq_ctx_term@ on GC, but operators are encouraged
-- to call 'term' explicitly at shutdown so socket teardown order is
-- deterministic.
newtype Context = Context (ForeignPtr ())

-- | A libzmq socket. The phantom @t@ pins the socket type ('Pub' or
-- 'Sub'); the type system therefore prevents 'sendMulti' on a 'Sub'
-- socket. The 'MVar' serialises multipart sends because libzmq's
-- @zmq_send@ is thread-safe per call but a multipart message must
-- come from one thread to avoid frame interleaving.
data Socket t = Socket !(ForeignPtr ()) !(MVar ())

-- | Phantom marker for a PUB socket.
data Pub = Pub
-- | Phantom marker for a SUB socket.
data Sub = Sub

-- | Newtype-wrapped @Int@ used by 'setSendHighWM' / 'setLinger'.
-- Mirrors the original @zeromq4-haskell@ surface so existing call
-- sites compile unchanged.
newtype Restrict a = Restrict a deriving (Eq, Show)

-- | Wrap a value in 'Restrict'.
restrict :: a -> Restrict a
restrict = Restrict

-- | Per-frame send flags. We only model 'SendMore' — non-blocking
-- semantics are not exposed because the 3-frame publisher path uses
-- @ZMQ_DONTWAIT@ unconditionally inside @haskoin_zmq_send_three@.
data Flag = SendMore deriving (Eq, Show)

-- | Boolean-ish toggle for 'setTcpKeepAlive'. Mirrors the original
-- @zeromq4-haskell@ shape.
data Switch = On | Off deriving (Eq, Show)

-- | Errors raised by this module.
data ZmqError
  = ZmqError !String  -- ^ libzmq returned non-zero; message via @zmq_strerror@.
  | ZmqNullPtr String -- ^ libzmq returned NULL where a pointer was expected.
  deriving (Show)

instance Exception ZmqError

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Read @zmq_errno()@ + @zmq_strerror()@ and raise 'ZmqError'.
zmqFail :: String -> IO a
zmqFail ctx = do
  e   <- c_errno
  cstr <- c_strerror e
  msg <- if cstr == nullPtr then pure "(null)" else peekCString cstr
  throwIO (ZmqError (ctx ++ ": " ++ msg))

-- | Run @act@ with the underlying @void*@ pointer for the context.
withCtx :: Context -> (Ptr () -> IO a) -> IO a
withCtx (Context fp) = withForeignPtr fp

-- | Run @act@ with the underlying @void*@ pointer for the socket,
-- holding the per-socket multipart mutex so concurrent block-connect
-- and tx-accept hooks cannot interleave frames on the wire.
withSock :: Socket t -> (Ptr () -> IO a) -> IO a
withSock (Socket fp mv) f =
  withMVar mv $ \_ -> withForeignPtr fp f

-- | Like 'withSock' but does not take the multipart mutex. For
-- single-frame ops (set*, bind, connect, close) where ordering with
-- multipart sends does not matter.
withSockNoLock :: Socket t -> (Ptr () -> IO a) -> IO a
withSockNoLock (Socket fp _) f = withForeignPtr fp f

--------------------------------------------------------------------------------
-- Lifecycle
--------------------------------------------------------------------------------

-- | Create a new ZMQ context. Each context spawns one I/O thread by
-- default; one context per process is the canonical pattern.
context :: IO Context
context = do
  p <- c_ctx_new
  if p == nullPtr
    then throwIO (ZmqNullPtr "zmq_ctx_new returned NULL")
    else do
      fp <- newForeignPtr c_ctx_term_finalizer p
      pure (Context fp)

-- | Terminate the context. Blocks until all sockets owned by the
-- context are closed. Idempotent: calling it multiple times after
-- the first is a no-op (the underlying ForeignPtr finaliser becomes
-- a no-op once detached).
term :: Context -> IO ()
term (Context fp) = finalizeForeignPtr fp

-- | Class of socket type tags. Each instance knows which @zmq_socket@
-- entry-point to dispatch to in C. The two instances we ship are
-- 'Pub' and 'Sub'; if you need REQ/REP/etc., add an instance and a
-- new C entry-point in @cbits\/zmq_stubs.c@.
class SocketType t where
  -- | Open a libzmq socket of this type on the given context.
  rawSocket :: Ptr () -> t -> IO (Ptr ())

instance SocketType Pub where
  rawSocket cp _ = c_pub_socket cp
instance SocketType Sub where
  rawSocket cp _ = c_sub_socket cp

-- | Open a socket of the given type on this context. Use 'Pub' for
-- publishers and 'Sub' for subscribers; the phantom type prevents
-- e.g. 'sendMulti' on a SUB socket.
socket :: SocketType t => Context -> t -> IO (Socket t)
socket ctx witness = withCtx ctx $ \cp -> mask_ $ do
  sp <- rawSocket cp witness
  if sp == nullPtr
    then zmqFail "zmq_socket"
    else do
      fp <- newForeignPtr c_close_finalizer sp
      mv <- newMVar ()
      pure (Socket fp mv)

-- | Bind a socket to an endpoint (server side). The endpoint follows
-- the libzmq URL grammar:
--
-- * @tcp:\/\/host:port@
-- * @ipc:\/\/path@
-- * @inproc:\/\/name@
--
-- The Bitcoin Core notifier convention is @tcp:\/\/127.0.0.1:28332@.
bind :: Socket t -> String -> IO ()
bind sk endpoint = withSockNoLock sk $ \sp ->
  withCStringLen endpoint $ \(cs, _) -> do
    rc <- c_bind sp cs
    if rc /= 0 then zmqFail ("zmq_bind " ++ endpoint) else pure ()

-- | Connect a socket to an endpoint (client side). Used by the
-- in-process round-trip test; production use only binds.
connect :: Socket t -> String -> IO ()
connect sk endpoint = withSockNoLock sk $ \sp ->
  withCStringLen endpoint $ \(cs, _) -> do
    rc <- c_connect sp cs
    if rc /= 0 then zmqFail ("zmq_connect " ++ endpoint) else pure ()

-- | Close the socket. The owning context's 'term' must be called
-- separately to release the I/O thread; closing all sockets first is
-- required for 'term' to return. Idempotent.
close :: Socket t -> IO ()
close (Socket fp _) = finalizeForeignPtr fp

--------------------------------------------------------------------------------
-- Sending
--------------------------------------------------------------------------------

-- | Send a single frame on a PUB socket. The frame is sent
-- non-blocking; if the SNDHWM is hit, libzmq drops the message
-- silently and we return without error (matching Bitcoin Core
-- semantics).
send :: Socket Pub -> [Flag] -> ByteString -> IO ()
send sk flags bs = withSock sk $ \sp ->
  BSU.unsafeUseAsCStringLen bs $ \(p, n) -> do
    let more = if SendMore `elem` flags then 1 else 0
    rc <- c_send_frame sp (castPtr p) (fromIntegral n) more 1
    if rc < 0
      then do
        -- EAGAIN (HWM hit) is NOT an error from the publisher's POV;
        -- only "real" failures escalate. errno=EAGAIN=11 on Linux.
        e <- c_errno
        if e == 11 then pure () else zmqFail "zmq_send"
      else pure ()

-- | Send a multi-part message atomically. For the 3-frame
-- @[topic | body | seq]@ pattern this routes through
-- @haskoin_zmq_send_three@ for one C call (the camlcoin pattern); for
-- other sizes we fall back to a per-frame loop. All frames are sent
-- non-blocking; SNDHWM-induced drops are silent (Bitcoin Core
-- semantics).
sendMulti :: Socket Pub -> NonEmpty ByteString -> IO ()
sendMulti sk frames = case NE.toList frames of
  [topic, body, seqBs] -> withSock sk $ \sp ->
    BSU.unsafeUseAsCStringLen topic $ \(tp, tn) ->
    BSU.unsafeUseAsCStringLen body  $ \(bp, bn) ->
    BSU.unsafeUseAsCStringLen seqBs $ \(qp, qn) -> do
      _ <- c_send_three sp
             (castPtr tp) (fromIntegral tn)
             (castPtr bp) (fromIntegral bn)
             (castPtr qp) (fromIntegral qn)
      -- Silent drop on HWM, matching Core. Real teardown errors are
      -- swallowed here too — the publisher must not stall validation.
      pure ()
  parts -> withSock sk $ \sp -> sendLoop sp parts
  where
    sendLoop _  []     = pure ()
    sendLoop sp [x]    = sendOne sp x 0
    sendLoop sp (x:xs) = sendOne sp x 1 >> sendLoop sp xs

    sendOne sp bs more =
      BSU.unsafeUseAsCStringLen bs $ \(p, n) -> do
        rc <- c_send_frame sp (castPtr p) (fromIntegral n) more 1
        if rc < 0
          then do
            e <- c_errno
            if e == 11 then pure () else zmqFail "zmq_send (multi)"
          else pure ()

--------------------------------------------------------------------------------
-- Receiving (subscribers — used in tests only)
--------------------------------------------------------------------------------

-- | Subscribe a SUB socket to all messages whose topic frame begins
-- with @prefix@. An empty 'BS.empty' subscribes to everything.
subscribe :: Socket Sub -> ByteString -> IO ()
subscribe sk prefix = withSockNoLock sk $ \sp ->
  BSU.unsafeUseAsCStringLen prefix $ \(p, n) -> do
    rc <- c_subscribe sp p (fromIntegral n)
    if rc /= 0 then zmqFail "zmq_setsockopt(SUBSCRIBE)" else pure ()

-- | Receive a single frame, polling up to ~1s for a message to
-- arrive. Returns 'Nothing' if nothing arrived within the budget,
-- otherwise the frame contents. Uses non-blocking @zmq_recv@ in a
-- 50-step poll because exposing @zmq_poll@ would be a larger ABI
-- footprint than the test surface needs.
receive :: Socket Sub -> Int -> IO (Maybe ByteString)
receive sk maxBytes = pollFor 50  -- 50 * 20 ms = 1 s budget
  where
    pollFor 0 = pure Nothing
    pollFor k = do
      r <- tryOnce
      case r of
        Just _  -> pure r
        Nothing -> do
          -- Short sleep to let the libzmq I/O thread move bytes
          -- between PUB and SUB on inproc.
          threadDelay 20000
          pollFor (k - 1)

    tryOnce = withSock sk $ \sp ->
      allocaBytes maxBytes $ \buf -> do
        n <- c_recv_into sp buf (fromIntegral maxBytes) 1  -- non-blocking
        if n < 0
          then do
            e <- c_errno
            if e == 11
              then pure Nothing  -- EAGAIN: no message ready
              else zmqFail "zmq_recv"
          else do
            let n' = min (fromIntegral n) maxBytes
            bs <- BS.packCStringLen (castPtr buf, n')
            pure (Just bs)

-- | Receive a multi-part message. Reads the first frame with the
-- ~1s poll budget; subsequent frames are taken with a tight retry
-- because if frame 0 arrived, frames 1..N are already buffered or
-- en route and waiting another full second per frame is wasteful.
receiveMulti :: Socket Sub -> Int -> IO [ByteString]
receiveMulti sk maxBytes = do
  r1 <- receive sk maxBytes
  case r1 of
    Nothing -> pure []
    Just b1 -> do
      r2 <- receive sk maxBytes
      case r2 of
        Nothing -> pure [b1]
        Just b2 -> do
          r3 <- receive sk maxBytes
          case r3 of
            Nothing -> pure [b1, b2]
            Just b3 -> pure [b1, b2, b3]

--------------------------------------------------------------------------------
-- Options
--------------------------------------------------------------------------------

-- | Set the send-side high-water mark. ZMQ buffers up to @hwm@
-- outbound messages per peer; further sends are dropped (PUB) when
-- 'sendMulti' is in use (which always sets ZMQ_DONTWAIT).
setSendHighWM :: Restrict Int -> Socket t -> IO ()
setSendHighWM (Restrict hwm) sk = withSockNoLock sk $ \sp -> do
  rc <- c_set_sndhwm sp (fromIntegral hwm)
  if rc /= 0 then zmqFail "zmq_setsockopt(SNDHWM)" else pure ()

-- | Set the receive-side high-water mark. Used by SUB sockets in
-- tests so the test rig doesn't grow unbounded.
setReceiveHighWM :: Restrict Int -> Socket t -> IO ()
setReceiveHighWM (Restrict hwm) sk = withSockNoLock sk $ \sp -> do
  rc <- c_set_rcvhwm sp (fromIntegral hwm)
  if rc /= 0 then zmqFail "zmq_setsockopt(RCVHWM)" else pure ()

-- | Set the linger period (ms) on close. 0 = drop pending messages
-- on close (Bitcoin Core's choice; shutdown latency matters more than
-- at-most-once retry).
setLinger :: Restrict Int -> Socket t -> IO ()
setLinger (Restrict ms) sk = withSockNoLock sk $ \sp -> do
  rc <- c_set_linger sp (fromIntegral ms)
  if rc /= 0 then zmqFail "zmq_setsockopt(LINGER)" else pure ()

-- | Toggle TCP keepalive on / off.
setTcpKeepAlive :: Switch -> Socket t -> IO ()
setTcpKeepAlive sw sk = withSockNoLock sk $ \sp -> do
  let v = case sw of On -> 1; Off -> 0
  rc <- c_set_keepalive sp v
  if rc /= 0 then zmqFail "zmq_setsockopt(TCP_KEEPALIVE)" else pure ()
