module Haskoin.Types where

import Data.ByteString (ByteString)

data BlockHeader = BlockHeader
  { bhVersion    :: !Int
  , bhPrevHash   :: !ByteString
  , bhMerkleRoot :: !ByteString
  , bhTimestamp  :: !Int
  , bhBits       :: !Int
  , bhNonce      :: !Int
  } deriving (Show, Eq)
