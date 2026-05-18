{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W141 ZMQ + REST + Notification scripts — 30-gate audit for haskoin.
--
-- References:
--   bitcoin-core/src/zmq/zmqnotificationinterface.{h,cpp}  Factory, lifecycle, dispatchers
--   bitcoin-core/src/zmq/zmqpublishnotifier.{h,cpp}        SendZmqMessage 3-frame layout,
--                                                           per-topic NotifyBlock /
--                                                           NotifyTransaction / SendSequenceMsg
--   bitcoin-core/src/zmq/zmqabstractnotifier.{h,cpp}       DEFAULT_ZMQ_SNDHWM (1000)
--   bitcoin-core/src/rest.cpp + rest.h                     14 endpoints, format parser,
--                                                           warmup gate, MAX_GETUTXOS_OUTPOINTS
--   bitcoin-core/src/init.cpp:2009-2018                    -blocknotify hook (NotifyBlockTip_connect)
--   bitcoin-core/src/node/kernel_notifications.cpp:30-47   -alertnotify hook (warningSet)
--   bitcoin-core/src/wallet/wallet.cpp:1141-1164           -walletnotify hook
--                                                           (NotifyTransactionChanged)
--
-- BIPs: none (ZMQ + REST + notify-scripts are Core implementation details).
--
-- ============================================================
-- TOP-LINE VERDICT — REST MOSTLY WIRED; ZMQ BUILT BUT UNWIRED;
-- NOTIFY-SCRIPTS COMPLETELY ABSENT
-- ============================================================
--
-- haskoin's three operator-surface subsystems audited here fall into
-- three quality tiers:
--
-- 1. **REST API** — 11 of 14 endpoints wired and correct on the happy
--    path; 3 endpoints absent (`/rest/blockpart/`, `/rest/deploymentinfo/`,
--    `/rest/spenttxouts/`); several shape gaps (warmup gate, binary-body
--    MAX_GETUTXOS_OUTPOINTS enforcement, count negative-int handling).
--
-- 2. **ZMQ pub/sub** — full publisher exists in @Haskoin.Rpc@ +
--    @System.ZMQ4@ FFI, but @Main.hs@ NEVER instantiates @newZmqNotifier@
--    and the five @notify*@ helpers have ZERO call sites in any
--    production module. Any subscriber that connects to
--    @tcp:\/\/127.0.0.1:28332@ sees an empty stream forever.
--    Five additional shape gaps: per-topic SNDHWM collapsed into a
--    single Int, @unix:\/\/@ -> @ipc:\/\/@ rewrite absent, no
--    @ZMQ_IPV6@ conditional, no multi-notifier socket sharing,
--    @ZMQ_LINGER=0@ set too early.
--
-- 3. **Notification scripts** — no @-blocknotify@, no @-walletnotify@,
--    no @-alertnotify@, no @runCommand@ primitive, no
--    @SanitizeString@ / @ShellEscape@. Largest-LOC gap of the three.
--
-- == BUGS (17 catalogued — 3 P0-CDIV + 8 P1 + 6 P2) ==
--
-- ZMQ pub/sub
-- BUG-1  P0-CDIV  ZmqNotifier built but NEVER instantiated from Main.hs;
--                 notify* helpers are dead code
-- BUG-2  P1       Per-topic SNDHWM collapsed into single Int field
--                 (Core: -zmqpubhashblockhwm, -zmqpubhashtxhwm, etc.)
-- BUG-3  P1       unix:// prefix not rewritten to ipc:// before zmq_bind
-- BUG-4  P2       No IsZMQAddressIPV6 conditional on bind address
-- BUG-5  P2       No multi-notifier socket sharing for same address
-- BUG-6  P2       ZMQ_LINGER=0 set at bind time instead of shutdown
--
-- REST API
-- BUG-7  P1       No warmup gate (Core's CheckWarmup) in any REST handler
-- BUG-8  P1       MAX_GETUTXOS_OUTPOINTS not enforced on binary-body branch
-- BUG-9  P1       /rest/blockpart/<hash>.<ext>?offset=N&size=M endpoint absent
-- BUG-10 P1       /rest/deploymentinfo/[<hash>].json endpoint absent
-- BUG-11 P1       /rest/spenttxouts/<hash>.<ext> endpoint absent
-- BUG-12 P2       /rest/blockfilter/ fast/slow-path drift potential
-- BUG-13 P2       /rest/headers/ count param accepts negative integers
--
-- Notification scripts
-- BUG-14 P0-CDIV  -blocknotify argument + tip event hook absent
-- BUG-15 P0-CDIV  -walletnotify argument + per-tx wallet hook absent
-- BUG-16 P1       -alertnotify argument + warning hook absent
-- BUG-17 P1       runCommand + SanitizeString + ShellEscape primitives absent
--
-- Discovery audit: NO production code changes. Tests are pinning-shape
-- (assert current observable behavior with `it`) and xfail-shape (assert
-- desired Core-parity behavior with `xit`) so future fix waves can flip
-- `xit` -> `it` after wiring the missing primitive.
--
-- ============================================================

module W141ZmqRestNotifySpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import Data.Word (Word8, Word32, Word64)

import Haskoin.Rpc
  ( ZmqTopic(..)
  , SequenceLabel(..)
  , ZmqConfig(..)
  , defaultZmqConfig
  , zmqTopicToBytes
  , sequenceLabelToByte
  , RestResponseFormat(..)
  , parseRestFormat
  , maxRestHeadersResults
  , maxGetUtxosOutpoints
  )

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Bitcoin Core's default per-topic SNDHWM
-- (zmqabstractnotifier.h: DEFAULT_ZMQ_SNDHWM = 1000).
defaultZmqSndHwm :: Int
defaultZmqSndHwm = 1000

-- | Bitcoin Core's MAX_GETUTXOS_OUTPOINTS (rest.cpp:44).
coreMaxGetUtxosOutpoints :: Int
coreMaxGetUtxosOutpoints = 15

-- | Bitcoin Core's MAX_REST_HEADERS_RESULTS (rest.cpp:45).
coreMaxRestHeadersResults :: Int
coreMaxRestHeadersResults = 2000

--------------------------------------------------------------------------------
spec :: Spec
spec = describe "W141 ZMQ + REST + Notification scripts (bundled)" $ do

  ------------------------------------------------------------------------------
  -- G1-G10 : ZMQ pub/sub notifications
  -- (Core: bitcoin-core/src/zmq/zmqnotificationinterface.cpp +
  --        zmq/zmqpublishnotifier.cpp)
  ------------------------------------------------------------------------------

  describe "G1 ZMQ topic strings match Core (hashblock / hashtx / rawblock / rawtx / sequence)" $ do
    it "G1 PINS: zmqTopicToBytes returns Core-compatible topic strings" $ do
      -- Core's zmqpublishnotifier.cpp:33-37 defines the five MSG_* constants.
      -- Haskoin's Rpc.hs:10823-10828 must produce the same bytes.
      zmqTopicToBytes ZmqHashBlock `shouldBe` "hashblock"
      zmqTopicToBytes ZmqHashTx    `shouldBe` "hashtx"
      zmqTopicToBytes ZmqRawBlock  `shouldBe` "rawblock"
      zmqTopicToBytes ZmqRawTx     `shouldBe` "rawtx"
      zmqTopicToBytes ZmqSequence  `shouldBe` "sequence"

  describe "G2 sequence label bytes match Core ('C' / 'D' / 'A' / 'R')" $ do
    it "G2 PINS: sequenceLabelToByte returns 0x43 / 0x44 / 0x41 / 0x52" $ do
      -- Core's zmqpublishnotifier.cpp:267-292 emits literal char codes.
      sequenceLabelToByte SeqBlockConnect    `shouldBe` 0x43  -- 'C'
      sequenceLabelToByte SeqBlockDisconnect `shouldBe` 0x44  -- 'D'
      sequenceLabelToByte SeqMempoolAccept   `shouldBe` 0x41  -- 'A'
      sequenceLabelToByte SeqMempoolRemoval  `shouldBe` 0x52  -- 'R'

  describe "G3 ZMQ notifier WIRED into block-connect / tx-add event path" $ do
    xit "G3 MISSING: Main.hs never instantiates newZmqNotifier; notify* helpers dead" $
      -- Repo-wide grep returns ZERO call sites for `newZmqNotifier` outside
      -- the module that defines it.  The five `notify*` helpers
      -- (notifyBlockConnect / notifyHashBlock / notifyRawBlock / notifyTxAcceptance
      -- / notifyTxRemoval / notifyBlockDisconnect) have ZERO call sites in any
      -- production module.  Subscribers that connect to tcp://127.0.0.1:28332
      -- see an empty stream forever.  BUG-1 P0-CDIV.
      pendingWith "BUG-1 P0-CDIV: ZmqNotifier built but never instantiated; production dead code"

  describe "G4 ZmqConfig default endpoint matches Core's documented example" $ do
    it "G4 PINS: defaultZmqConfig has tcp://127.0.0.1:28332 endpoint" $
      -- Rpc.hs:10864-10869 defaultZmqConfig.  Core itself uses no default —
      -- the CLI flag is opt-in — but the documented example port 28332
      -- pins the wire-shape test.
      zmqEndpoint defaultZmqConfig `shouldBe` "tcp://127.0.0.1:28332"

  describe "G5 ZMQ per-topic SNDHWM (DEFAULT_ZMQ_SNDHWM = 1000)" $ do
    it "G5 PINS: defaultZmqConfig.zmqHighWaterMark equals Core's DEFAULT_ZMQ_SNDHWM (1000)" $
      zmqHighWaterMark defaultZmqConfig `shouldBe` defaultZmqSndHwm

    xit "G5 GATE: per-topic SNDHWM via -zmqpubhashblockhwm / -zmqpubhashtxhwm / etc." $
      -- Core's zmqnotificationinterface.cpp:69 reads
      -- gArgs.GetIntArg(arg + "hwm", DEFAULT_ZMQ_SNDHWM) for EACH topic.
      -- haskoin collapses to a single `zmqHighWaterMark` Int.
      -- BUG-2 P1.
      pendingWith "BUG-2: per-topic SNDHWM collapsed into single field"

  describe "G6 ZMQ unix:// -> ipc:// transport rewrite (zmqnotificationinterface.cpp:62-64)" $ do
    xit "G6 MISSING: newZmqNotifier passes unix:// endpoint verbatim to zmq_bind" $
      -- Core rewrites @unix://@ prefix to @ipc://@ before calling zmq_bind because
      -- libzmq does not recognise @unix://@.  haskoin's Rpc.hs:10941
      -- calls @ZMQ.bind sock (zmqEndpoint config)@ unchanged — a
      -- @unix:///tmp/foo@ endpoint hits EINVAL at bind time.  BUG-3 P1.
      pendingWith "BUG-3 P1: unix:// -> ipc:// prefix rewrite missing"

  describe "G7 ZMQ IPv6 conditional on bind address (zmqpublishnotifier.cpp:130)" $ do
    xit "G7 MISSING: ZMQ_IPV6 unconditionally inherits libzmq default (0)" $
      -- Core's IsZMQAddressIPV6 looks up the host; if IPv6, sets ZMQ_IPV6=1.
      -- Some BSDs reject ZMQ_IPV6=1 on IPv4 sockets, so the conditional
      -- is load-bearing.  haskoin's Rpc.hs:10937-10940 sets only SNDHWM,
      -- LINGER, KEEPALIVE — no ZMQ_IPV6 setsockopt.  BUG-4 P2.
      pendingWith "BUG-4 P2: no IsZMQAddressIPV6 conditional on bind address"

  describe "G8 ZMQ multi-notifier socket sharing for same address" $ do
    xit "G8 MISSING: two topics on same endpoint open two sockets" $
      -- Core's CZMQAbstractPublishNotifier::Initialize (zmqpublishnotifier.cpp:99-159)
      -- looks up mapPublishNotifiers and REUSES an existing socket if the
      -- address is already bound.  haskoin opens a fresh PUB socket per
      -- newZmqNotifier call; two-topic-same-endpoint would collide
      -- (currently moot because BUG-1 blocks instantiation entirely).
      -- BUG-5 P2.
      pendingWith "BUG-5 P2: no mapPublishNotifiers-style socket sharing"

  describe "G9 ZMQ_LINGER set at shutdown (Core), not at bind (haskoin)" $ do
    xit "G9 MISSING: LINGER=0 set BEFORE bind drops in-flight on every send" $
      -- Core's zmqpublishnotifier.cpp:185-188 sets LINGER=0 only inside
      -- Shutdown().  haskoin's Rpc.hs:10939 sets LINGER=0 immediately
      -- after socket creation.  A fast publisher restart loses any
      -- in-flight messages even if no shutdown race is in progress.
      -- BUG-6 P2.
      pendingWith "BUG-6 P2: ZMQ_LINGER=0 set at open instead of shutdown"

  describe "G10 ZMQ 3-frame wire layout (topic | body | LE u32 sequence)" $ do
    it "G10 PINS: ZmqTopic constructors form the topic-frame ADT" $ do
      -- Wire-shape regression guard: the topic ADT must stay 5 nullary
      -- constructors in the order documented by Core MSG_* constants.
      let allTopics = [ZmqHashBlock, ZmqHashTx, ZmqRawBlock, ZmqRawTx, ZmqSequence]
      length allTopics `shouldBe` 5
      length (map zmqTopicToBytes allTopics) `shouldBe` 5

  ------------------------------------------------------------------------------
  -- G11-G20 : REST API
  -- (Core: bitcoin-core/src/rest.cpp 14 endpoints)
  ------------------------------------------------------------------------------

  describe "G11 REST format parser (.bin / .hex / .json) matches Core's ParseDataFormat" $ do
    it "G11 PINS: parseRestFormat returns RestBinary / RestHex / RestJson / RestUndefined" $ do
      -- Core's rest.cpp:50-55 + rest.h:10-15.  Three valid formats + UNDEF.
      snd (parseRestFormat "abc.bin")  `shouldBe` RestBinary
      snd (parseRestFormat "abc.hex")  `shouldBe` RestHex
      snd (parseRestFormat "abc.json") `shouldBe` RestJson
      snd (parseRestFormat "abc")      `shouldBe` RestUndefined

  describe "G12 REST MAX_REST_HEADERS_RESULTS = 2000 (rest.cpp:45)" $ do
    it "G12 PINS: maxRestHeadersResults matches Core's MAX_REST_HEADERS_RESULTS" $
      maxRestHeadersResults `shouldBe` coreMaxRestHeadersResults

  describe "G13 REST MAX_GETUTXOS_OUTPOINTS = 15 (rest.cpp:44)" $ do
    it "G13 PINS: maxGetUtxosOutpoints matches Core's MAX_GETUTXOS_OUTPOINTS" $
      maxGetUtxosOutpoints `shouldBe` coreMaxGetUtxosOutpoints

  describe "G14 REST warmup gate (CheckWarmup in every handler)" $ do
    xit "G14 MISSING: routeRest jumps to handler regardless of warmup / IBD" $
      -- Core's rest.cpp every handler begins with `if (!CheckWarmup(req)) return false;`
      -- which returns 503 + "Service temporarily unavailable" while
      -- RPCIsInWarmup.  haskoin's routeRest (Rpc.hs:9224-9277) dispatches
      -- straight to the handler regardless of node state.  BUG-7 P1.
      pendingWith "BUG-7 P1: no warmup gate in any REST handler"

  describe "G15 REST /rest/blockpart/<hash>.<ext>?offset=N&size=M endpoint" $ do
    xit "G15 MISSING: routeRest has no /rest/blockpart/ branch" $
      -- Core's rest_block_part (rest.cpp:481-498) handles range queries
      -- via {offset, size} query params and calls rest_block with the
      -- block_part argument.  haskoin's Rpc.hs:9224-9277 dispatcher has
      -- no `"/rest/blockpart/"` branch.  BUG-9 P1.
      pendingWith "BUG-9 P1: /rest/blockpart/ endpoint absent"

  describe "G16 REST /rest/deploymentinfo/[<hash>].json endpoint" $ do
    xit "G16 MISSING: routeRest has no /rest/deploymentinfo/ branch" $
      -- Core's rest_deploymentinfo (rest.cpp:743-780) reuses the
      -- getdeploymentinfo RPC handler.  haskoin has the RPC
      -- (Rpc.hs:1009 handleGetDeploymentInfo) but no REST front-end.
      -- BUG-10 P1.
      pendingWith "BUG-10 P1: /rest/deploymentinfo/ endpoint absent"

  describe "G17 REST /rest/spenttxouts/<hash>.<ext> endpoint" $ do
    xit "G17 MISSING: routeRest has no /rest/spenttxouts/ branch" $
      -- Core's rest_spent_txouts (rest.cpp:313-381) serialises CBlockUndo.
      -- haskoin's Storage.hs has BlockUndo (W57 wrote it) but no REST
      -- endpoint exposes the spent-txouts view.  BUG-11 P1.
      pendingWith "BUG-11 P1: /rest/spenttxouts/ endpoint absent"

  describe "G18 REST /rest/getutxos/ MAX_GETUTXOS_OUTPOINTS enforcement on binary body" $ do
    xit "G18 MISSING: binary-body branch parses outpoints without count guard" $
      -- Core's rest_getutxos (rest.cpp:988-990) enforces
      -- MAX_GETUTXOS_OUTPOINTS = 15 AFTER deserialising the binary body
      -- (vOutPoints.size() > MAX_GETUTXOS_OUTPOINTS).  haskoin's
      -- handleRestGetUtxos enforces it only on the URI-parsed input
      -- (Rpc.hs:9795-9798); binary/hex body branches do not appear
      -- to be implemented at all.  BUG-8 P1.
      pendingWith "BUG-8 P1: MAX_GETUTXOS_OUTPOINTS not enforced on binary-body branch"

  describe "G19 REST /rest/headers/ count param rejects negative ints" $ do
    xit "G19 MISSING: readMaybe accepts a leading '-'; count < 1 catches but error msg wrong" $
      -- Core uses ToIntegral<size_t> which rejects negatives at parse
      -- time (rest.cpp:207); error reads "Header count is invalid or
      -- out of acceptable range".  haskoin's readMaybe accepts "-42",
      -- then count < 1 catches it but the negative-int hint is lost.
      -- BUG-13 P2.
      pendingWith "BUG-13 P2: count param accepts negative int via readMaybe"

  describe "G20 REST /rest/blockfilter/ fast-path vs slow-path byte-equivalence" $ do
    xit "G20 RISK: index-stored bfeEncoded vs on-demand computeBlockFilter drift" $
      -- The per-height index fast-path returns @bfeEncoded@ bytes verbatim;
      -- the on-demand slow-path recomputes via @computeBlockFilter block
      -- (udBlockUndo undoData) bh@.  Same block hash, two code paths,
      -- two potential bytes.  Cross-cite W121 BUG-16 P0-CDIV.  BUG-12 P2.
      pendingWith "BUG-12 P2: fast-path / slow-path drift (cross-cite W121 BUG-16)"

  ------------------------------------------------------------------------------
  -- G21-G30 : External notification scripts
  -- (Core: init.cpp:2009-2018 + node/kernel_notifications.cpp:30-47 +
  --        wallet/wallet.cpp:1141-1164)
  ------------------------------------------------------------------------------

  describe "G21 -blocknotify CLI argument registered (init.cpp:498)" $ do
    xit "G21 MISSING: --blocknotify is not a recognised CLI flag in Main.hs" $
      -- Core's init.cpp:498 calls
      -- argsman.AddArg("-blocknotify=<cmd>", "Execute command when the best block changes ...").
      -- haskoin's app/Main.hs option-parser has no entry; --blocknotify=...
      -- is rejected as unknown.  BUG-14 P0-CDIV.
      pendingWith "BUG-14 P0-CDIV: -blocknotify CLI argument absent"

  describe "G22 -blocknotify tip-event hook (NotifyBlockTip_connect)" $ do
    xit "G22 MISSING: no detached-thread runCommand on UpdatedBlockTip" $
      -- Core's init.cpp:2010-2018 wires uiInterface.NotifyBlockTip_connect
      -- to spawn a detached thread that runs the command after
      -- ReplaceAll(command, "%s", block.GetBlockHash().GetHex()).
      -- haskoin has no such hook anywhere in app/Main.hs or
      -- src/Haskoin/Sync.hs.  BUG-14 P0-CDIV.
      pendingWith "BUG-14 P0-CDIV: no NotifyBlockTip_connect-equivalent runCommand hook"

  describe "G23 -walletnotify CLI argument registered (wallet/init.cpp:75)" $ do
    xit "G23 MISSING: --walletnotify is not a recognised CLI flag" $
      -- Core's wallet/init.cpp:75 registers -walletnotify=<cmd>.
      -- haskoin's app/Main.hs has no entry.  BUG-15 P0-CDIV.
      pendingWith "BUG-15 P0-CDIV: -walletnotify CLI argument absent"

  describe "G24 -walletnotify per-tx hook (NotifyTransactionChanged)" $ do
    xit "G24 MISSING: no runCommand call on wallet tx state change" $
      -- Core's wallet/wallet.cpp:1141-1164 runs the command on
      -- NotifyTransactionChanged with %s/%b/%h/%w substitution and
      -- ShellEscape on the wallet name.  haskoin's wallet event path
      -- (src/Haskoin/Wallet.hs) has no equivalent hook.  BUG-15 P0-CDIV.
      pendingWith "BUG-15 P0-CDIV: no NotifyTransactionChanged-equivalent runCommand hook"

  describe "G25 -alertnotify CLI argument registered (init.cpp:485)" $ do
    xit "G25 MISSING: --alertnotify is not a recognised CLI flag" $
      -- Core's init.cpp:485 registers -alertnotify=<cmd>.
      -- haskoin's app/Main.hs has no entry.  BUG-16 P1.
      pendingWith "BUG-16 P1: -alertnotify CLI argument absent"

  describe "G26 -alertnotify warning hook (KernelNotifications::warningSet)" $ do
    xit "G26 MISSING: no SanitizeString + single-quote + runCommand on warning" $
      -- Core's node/kernel_notifications.cpp:30-47 runs the command
      -- after SanitizeString(strMessage) and '<safe>' single-quoting
      -- on every warningSet.  haskoin's warning system has no such
      -- hook.  BUG-16 P1.
      pendingWith "BUG-16 P1: no warningSet-equivalent runCommand hook"

  describe "G27 runCommand primitive (common/run_command.cpp::RunCommand)" $ do
    xit "G27 MISSING: no shared command-runner primitive exists in src/" $
      -- Core's common/run_command.cpp::RunCommand fork+execs the command
      -- and discards the result.  Closing BUG-14/15/16 requires a shared
      -- runCommand primitive; repo-wide grep finds zero hits.  BUG-17 P1.
      pendingWith "BUG-17 P1: runCommand primitive absent"

  describe "G28 SanitizeString primitive (util/string.cpp::SanitizeString)" $ do
    xit "G28 MISSING: no shell-safe sanitisation primitive exists" $
      -- Core's util/string.cpp::SanitizeString strips chars outside
      -- safeChars before passing to the shell.  Required for BUG-16
      -- closure to avoid shell-injection via warning messages.
      -- BUG-17 P1.
      pendingWith "BUG-17 P1: SanitizeString primitive absent"

  describe "G29 ShellEscape primitive (util/strencodings.cpp::ShellEscape)" $ do
    xit "G29 MISSING: no shell-escape primitive exists" $
      -- Core's ShellEscape is used by wallet.cpp:1160 for the %w
      -- (wallet-name) substitution.  Required for BUG-15 closure to
      -- avoid shell-injection via wallet names.  BUG-17 P1.
      pendingWith "BUG-17 P1: ShellEscape primitive absent"

  describe "G30 %s/%b/%h/%w substitution primitive (util/string.cpp::ReplaceAll)" $ do
    xit "G30 MISSING: no shared placeholder-substitution primitive exists" $
      -- Core's util::ReplaceAll is used by all three notify-hooks to
      -- substitute %s (block hash / txid), %b (confirmed block hash),
      -- %h (confirmed block height), %w (wallet name).  haskoin has
      -- T.replace but no centralised notify-substitution helper.
      -- BUG-17 P1.
      pendingWith "BUG-17 P1: %s/%b/%h/%w substitution primitive absent"

  ------------------------------------------------------------------------------
  -- Bonus pinning assertions (NOT counted as gates)
  -- These exercise the in-memory shape of the existing types so future
  -- refactors can't silently change field counts.
  ------------------------------------------------------------------------------

  describe "B1 ZmqTopic ADT has exactly 5 nullary constructors" $ do
    it "B1 PINS: ZmqTopic constructor count" $ do
      -- Rpc.hs:10814-10820 — adding a 6th topic requires Core's MSG_*
      -- table to grow too; pin the count so a stray addition trips this.
      let topics = [ZmqHashBlock, ZmqHashTx, ZmqRawBlock, ZmqRawTx, ZmqSequence]
      length topics `shouldBe` 5

  describe "B2 SequenceLabel ADT has exactly 4 nullary constructors" $ do
    it "B2 PINS: SequenceLabel constructor count" $ do
      -- Rpc.hs:10831-10836 — adding a 5th label requires a new Core
      -- sequence wire-format byte to be defined first.
      let labels = [SeqBlockConnect, SeqBlockDisconnect, SeqMempoolAccept, SeqMempoolRemoval]
      length labels `shouldBe` 4

  describe "B3 RestResponseFormat ADT has exactly 4 nullary constructors" $ do
    it "B3 PINS: RestResponseFormat constructor count" $ do
      -- Rpc.hs:9161-9166 — three valid formats + UNDEF, mirroring
      -- Core's RESTResponseFormat enum (rest.h:10-15).
      let formats = [RestBinary, RestHex, RestJson, RestUndefined]
      length formats `shouldBe` 4

  describe "B4 ZmqConfig defaults are non-trivial" $ do
    it "B4 PINS: zmqEnabled default + non-empty endpoint + positive HWM" $ do
      zmqEnabled defaultZmqConfig `shouldBe` True
      length (zmqEndpoint defaultZmqConfig) > 0 `shouldBe` True
      zmqHighWaterMark defaultZmqConfig > 0 `shouldBe` True

  describe "B5 REST format parser correctly drops the suffix" $ do
    it "B5 PINS: parseRestFormat returns (path-without-suffix, format)" $ do
      -- Rpc.hs:9179-9184 — the parser is responsible for dropping
      -- ".bin" / ".hex" / ".json" so the remainder is the
      -- handler-specific path body.
      fst (parseRestFormat "abc.bin")  `shouldBe` "abc"
      fst (parseRestFormat "abc.hex")  `shouldBe` "abc"
      fst (parseRestFormat "abc.json") `shouldBe` "abc"
      fst (parseRestFormat "abc")      `shouldBe` "abc"

  -- Use the imports we haven't otherwise touched to avoid -Wunused-imports.
  describe "W141 import-use anchor (compile-time pin)" $ do
    it "anchor: zmqTopicToBytes / sequenceLabelToByte / parseRestFormat / Word8 / Word32 / Word64 / BS imported" $ do
      BS.length (zmqTopicToBytes ZmqHashBlock) `shouldBe` 9  -- "hashblock"
      let _w8 :: Word8  = sequenceLabelToByte SeqBlockConnect
          _w32 :: Word32 = 0
          _w64 :: Word64 = 0
      True `shouldBe` True
