{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | ParseHashV parity — txid/blockhash malformed-argument error codes.
--
-- Bitcoin Core v31.99 rejects a MALFORMED txid/blockhash argument at the
-- PARSE boundary, BEFORE any chainstate/mempool lookup, with
-- RPC_INVALID_PARAMETER (-8) and one of two messages
-- (bitcoin-core/src/rpc/util.cpp:117 ParseHashV):
--
--   wrong length : "<name> must be of length 64 (not N, for '<hex>')"
--   bad hex chars: "<name> must be hexadecimal string (not '<hex>')"
--
-- A WELL-FORMED 64-hex hash that is simply absent is NOT rejected here —
-- it parses to Right and the per-RPC lookup decides the outcome
-- (getrawtransaction -> -5, gettxout -> JSON null, getblock/getblockheader
-- -> -5, getmempoolentry -> "not in mempool").  That -5/null path is
-- asserted by the existing handler-level specs and is deliberately NOT
-- changed; this spec pins ONLY the -8 parse boundary.
--
-- haskoin routes every in-scope RPC through the shared 'parseHashV' helper
-- with the SAME argument label Core uses:
--   getrawtransaction : "parameter 1" (txid) / "parameter 3" (blockhash)
--   gettxout          : "txid"
--   getblock          : "blockhash"
--   getblockheader    : "hash"
--   getmempoolentry   : "txid"
-- (verified against bitcoin-core/src/rpc/{rawtransaction,blockchain,mempool}.cpp)
--
-- References:
--   bitcoin-core/src/rpc/util.cpp:117      ParseHashV
--   bitcoin-core/src/rpc/protocol.h        RPC_INVALID_PARAMETER = -8,
--                                          RPC_INVALID_ADDRESS_OR_KEY = -5

module ParseHashVSpec (spec) where

import Test.Hspec
import qualified Data.Text as T
import Data.Either (isRight)

import Haskoin.Rpc
  ( RpcError(..)
  , parseHashV
  , parseHash
  , rpcInvalidParameter
  )

-- A well-formed but absent hash: 64 zero hex chars.  Core's uint256::FromHex
-- accepts it; haskoin's parseHashV returns Right; the absent case is the
-- caller's -5 / null, NOT a -8 here.
zeroHash :: T.Text
zeroHash = T.replicate 64 "0"

-- A too-short hex string (Core: wrong-length -8).
tooShort :: T.Text
tooShort = "abc"

-- A 64-char NON-hex string (Core: right-length, bad-hex -8).
sixtyFourZs :: T.Text
sixtyFourZs = T.replicate 64 "z"

-- Argument labels exactly as each Core RPC passes them to ParseHashV.
argNames :: [(String, T.Text)]
argNames =
  [ ("getrawtransaction txid",      "parameter 1")
  , ("getrawtransaction blockhash", "parameter 3")
  , ("gettxout txid",               "txid")
  , ("getblock blockhash",          "blockhash")
  , ("getblockheader hash",         "hash")
  , ("getmempoolentry txid",        "txid")
  ]

spec :: Spec
spec = describe "ParseHashV malformed txid/blockhash -> -8 (Core v31.99 parity)" $ do

  ------------------------------------------------------------------------------
  -- (a) MALFORMED -> RPC_INVALID_PARAMETER (-8) at the parse boundary.
  ------------------------------------------------------------------------------
  describe "(a) malformed hash -> error code -8" $ do

    -- Sanity: the constant we route to is genuinely Core's -8.
    it "rpcInvalidParameter == -8 (Core RPC_INVALID_PARAMETER)" $
      rpcInvalidParameter `shouldBe` (-8)

    -- For every in-scope RPC's argument label, BOTH malformed forms (wrong
    -- length AND right-length-bad-hex) reject with -8.
    mapM_ (\(desc, name) -> do
        it (desc ++ ": too-short hex \"abc\" -> -8") $
          case parseHashV name tooShort of
            Left err  -> errCode err `shouldBe` (-8)
            Right _   -> expectationFailure "expected -8, got Right (parsed)"

        it (desc ++ ": 64 'z' chars (non-hex) -> -8") $
          case parseHashV name sixtyFourZs of
            Left err  -> errCode err `shouldBe` (-8)
            Right _   -> expectationFailure "expected -8, got Right (parsed)"
      ) argNames

  ------------------------------------------------------------------------------
  -- Core's two distinct messages (util.cpp:122 / :124).
  ------------------------------------------------------------------------------
  describe "Core-style message text" $ do

    it "wrong length -> \"<name> must be of length 64 (not N, for '<hex>')\"" $
      case parseHashV "txid" tooShort of
        Left err -> errMessage err
          `shouldBe` "txid must be of length 64 (not 3, for 'abc')"
        Right _  -> expectationFailure "expected Left"

    it "right length, bad hex -> \"<name> must be hexadecimal string (not '<hex>')\"" $
      case parseHashV "blockhash" sixtyFourZs of
        Left err -> errMessage err
          `shouldBe` ("blockhash must be hexadecimal string (not '"
                       <> sixtyFourZs <> "')")
        Right _  -> expectationFailure "expected Left"

  ------------------------------------------------------------------------------
  -- (b) WELL-FORMED but absent -> NOT -8.  Parses to Right; the per-RPC
  --     lookup (unchanged) yields -5 / null.  This guards against the fix
  --     over-rejecting a legitimately-absent hash.
  ------------------------------------------------------------------------------
  describe "(b) well-formed 64-hex hash -> Right (absent case stays -5/null)" $ do

    it "64 zero hex chars parses to Right (NOT a -8 parse error)" $
      isRight (parseHashV "txid" zeroHash) `shouldBe` True

    it "parseHashV success path agrees with parseHash for a valid hash" $
      case (parseHashV "txid" zeroHash, parseHash zeroHash) of
        (Right bh, Just bh') -> bh `shouldBe` bh'
        _                    -> expectationFailure "expected both to parse the valid hash"

    it "a real 64-hex hash parses to Right" $
      isRight (parseHashV "blockhash"
        "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09")
        `shouldBe` True
