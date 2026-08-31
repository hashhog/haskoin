#!/usr/bin/env python3
"""Regenerate src/Haskoin/CoreArity.hs from the meta-repo's arity table.

Usage (from the haskoin submodule root):

    python3 tools/gen_core_arity_hs.py > src/Haskoin/CoreArity.hs

The input, ../tools/core-arity.json, is derived from Bitcoin Core's own `help`
output by the meta-repo's tools/core-arity.py. Committing the generated module
keeps the table compiled in, so nothing is read from disk at startup.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "..", "tools", "core-arity.json")

HEADER = '''{-# LANGUAGE OverloadedStrings #-}

-- | Bitcoin Core's central RPC argument-count table (#103).
--
-- GENERATED FILE -- do not edit by hand. Regenerate with:
--
-- > python3 tools/gen_core_arity_hs.py > src/Haskoin/CoreArity.hs
--
-- Maps a method name to @(required, declared)@, derived from Core's own
-- @help@ signature line by tools/core-arity.py (%d methods). Core enforces
-- @required <= n <= declared@ centrally, before any handler runs
-- (rpc\\/util.cpp:644 -> IsValidNumArgs, :733), and answers -1 otherwise.
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
  [ %s
  ]

-- | Look a method up. 'Nothing' means the method is absent from the table and
-- callers MUST fail OPEN: coverage is %d of 103 Core methods, and treating an
-- unlisted method as zero-arg would reject calls Core accepts.
lookupCoreArity :: Text -> Maybe (Int, Int)
lookupCoreArity m = Map.lookup m coreArityTable
'''


def main() -> int:
    with open(SRC) as fh:
        table = json.load(fh)
    rows = "\n  , ".join(
        '("%s", (%d, %d))' % (n, int(table[n]["required"]), int(table[n]["declared"]))
        for n in sorted(table)
    )
    sys.stdout.write(HEADER % (len(table), rows, len(table)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
