{-# LANGUAGE OverloadedStrings #-}

-- | Bitcoin Core's central RPC argument-count table (#103).
--
-- GENERATED FILE -- do not edit by hand. Regenerate with:
--
-- > python3 tools/gen_core_arity_hs.py > src/Haskoin/CoreArity.hs
--
-- Maps a method name to @(required, declared)@, derived from Core's own
-- @help@ signature line by tools/core-arity.py (87 methods). Core enforces
-- @required <= n <= declared@ centrally, before any handler runs
-- (rpc\/util.cpp:644 -> IsValidNumArgs, :733), and answers -1 otherwise.
--
-- The table is COMPILED IN rather than read from a data file at startup.
-- This repo's deploy step copies binaries away from their build tree:
-- camlcoin shipped exactly this check on 2026-08-31 reading its table from a
-- relative path, and it silently did nothing in production while every test
-- passed.
module Haskoin.CoreArity
  ( coreArityTable
  , lookupCoreArity
  ) where

import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)

-- | The full table, method name to @(required, declared)@.
coreArityTable :: Map Text (Int, Int)
coreArityTable = Map.fromList
  [ ("addnode", (2, 3))
  , ("analyzepsbt", (1, 1))
  , ("clearbanned", (0, 0))
  , ("combinepsbt", (1, 1))
  , ("combinerawtransaction", (1, 1))
  , ("converttopsbt", (1, 3))
  , ("createmultisig", (2, 3))
  , ("createpsbt", (2, 5))
  , ("createrawtransaction", (2, 5))
  , ("decodepsbt", (1, 1))
  , ("decoderawtransaction", (1, 2))
  , ("decodescript", (1, 1))
  , ("deriveaddresses", (1, 2))
  -- Core help lists 2 required (psbt, descriptors) and 3 optional
  -- (sighashtype, bip32derivs, finalize) — (2, 5).  The generator once
  -- counted optional inner-object fields as required and emitted (4, 7),
  -- which rejected the R5 probe's 2-arg form before the handler ran.
  , ("descriptorprocesspsbt", (2, 5))
  , ("disconnectnode", (0, 2))
  , ("estimatesmartfee", (1, 2))
  , ("finalizepsbt", (1, 2))
  , ("getaddednodeinfo", (0, 1))
  , ("getaddrmaninfo", (0, 0))
  , ("getbestblockhash", (0, 0))
  , ("getblock", (1, 2))
  , ("getblockchaininfo", (0, 0))
  , ("getblockcount", (0, 0))
  , ("getblockfilter", (1, 2))
  , ("getblockfrompeer", (2, 2))
  , ("getblockhash", (1, 1))
  , ("getblockheader", (1, 2))
  , ("getblockstats", (1, 2))
  , ("getblocktemplate", (1, 1))
  , ("getchainstates", (0, 0))
  , ("getchaintips", (0, 0))
  , ("getchaintxstats", (0, 2))
  , ("getconnectioncount", (0, 0))
  , ("getdeploymentinfo", (0, 1))
  , ("getdescriptorinfo", (1, 1))
  , ("getdifficulty", (0, 0))
  , ("getindexinfo", (0, 1))
  , ("getmemoryinfo", (0, 1))
  , ("getmempoolancestors", (1, 2))
  , ("getmempooldescendants", (1, 2))
  , ("getmempoolentry", (1, 1))
  , ("getmempoolinfo", (0, 0))
  , ("getmininginfo", (0, 0))
  , ("getnettotals", (0, 0))
  , ("getnetworkhashps", (0, 2))
  , ("getnetworkinfo", (0, 0))
  , ("getnodeaddresses", (0, 2))
  , ("getpeerinfo", (0, 0))
  , ("getprioritisedtransactions", (0, 0))
  , ("getrawmempool", (0, 2))
  , ("getrawtransaction", (1, 3))
  , ("getrpcinfo", (0, 0))
  , ("gettxout", (2, 3))
  , ("gettxoutproof", (1, 2))
  , ("gettxoutsetinfo", (0, 3))
  , ("gettxspendingprevout", (1, 2))
  , ("help", (0, 1))
  , ("importmempool", (1, 2))
  , ("joinpsbts", (1, 1))
  , ("listbanned", (0, 0))
  , ("logging", (0, 2))
  , ("ping", (0, 0))
  , ("preciousblock", (1, 1))
  , ("prioritisetransaction", (1, 3))
  , ("pruneblockchain", (1, 1))
  , ("savemempool", (0, 0))
  , ("scanblocks", (1, 6))
  , ("scantxoutset", (1, 2))
  , ("sendrawtransaction", (1, 3))
  , ("setban", (2, 4))
  , ("setnetworkactive", (1, 1))
  , ("signmessagewithprivkey", (2, 2))
  , ("signrawtransactionwithkey", (2, 4))
  -- Core's hidden `wait` NUM (server.cpp stop). A present non-number is
  -- RPC_TYPE_ERROR (-3), not an arity miss (-1). (0, 0) made the R5
  -- wrong-type probe fail closed as -1 before the handler saw the value.
  , ("stop", (0, 1))
  , ("submitblock", (1, 2))
  , ("submitheader", (1, 1))
  , ("submitpackage", (1, 3))
  , ("testmempoolaccept", (1, 2))
  , ("uptime", (0, 0))
  , ("utxoupdatepsbt", (1, 4))
  , ("validateaddress", (1, 1))
  , ("verifychain", (0, 2))
  , ("verifymessage", (3, 3))
  , ("verifytxoutproof", (1, 1))
  , ("waitforblock", (1, 2))
  , ("waitforblockheight", (1, 2))
  , ("waitfornewblock", (0, 2))
  ]
  `Map.union` walletArityExtras

-- | Wallet RPCs absent from the generator's 87-method snapshot.
--
-- Counts are @(required, declared)@ from Core's RPCHelpMan
-- (wallet/rpc/{wallet,addresses,coins,transactions,spend,backup}.cpp).
-- Hand-maintained: a regenerated base table must keep this union, or the
-- R5 lane's zero-arg wrong-arity probes (getwalletinfo / listwallets /
-- getbalances) fail open and createwallet's missing name stays -32602
-- instead of Core's -1.
walletArityExtras :: Map Text (Int, Int)
walletArityExtras = Map.fromList
  [ ("backupwallet", (1, 1))
  , ("createwallet", (1, 8))
  , ("getaddressinfo", (1, 1))
  , ("getbalances", (0, 0))
  , ("getnewaddress", (0, 2))
  , ("getwalletinfo", (0, 0))
  , ("listtransactions", (0, 4))
  , ("listunspent", (0, 5))
  , ("listwallets", (0, 0))
  , ("loadwallet", (1, 2))
  , ("restorewallet", (2, 3))
  , ("send", (1, 6))
  , ("sendtoaddress", (2, 11))
  , ("unloadwallet", (0, 2))
  , ("walletcreatefundedpsbt", (2, 6))
  , ("walletprocesspsbt", (1, 5))
  ]

-- | Look a method up. 'Nothing' means the method is absent from the table and
-- callers MUST fail OPEN: coverage is 87 of 103 Core methods, and treating an
-- unlisted method as zero-arg would reject calls Core accepts.
lookupCoreArity :: Text -> Maybe (Int, Int)
lookupCoreArity m = Map.lookup m coreArityTable
