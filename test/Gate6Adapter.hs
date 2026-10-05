-- | FIX tree: the MBlock handler's validate-then-mark step as it now is in
-- app/Main.hs (validation forced inside 'validateBlockGuarded'; a verdict
-- only on a classified VERDICT).
module Gate6Adapter (mblockValidate) where

import Control.Monad (when, void)
import qualified Data.Map.Strict as Map
import Data.Word (Word32)
import Haskoin.Types
import Haskoin.Consensus
import Haskoin.Storage (HaskoinDB, Coin, getBestBlockHash)

mblockValidate :: HaskoinDB -> Network -> HeaderChain -> ChainState
               -> (Word32 -> Word32) -> Block -> BlockHash -> Map.Map OutPoint Coin
               -> IO (Either String ())
mblockValidate db net hc cs getMtp block bh spent = do
  vr <- validateBlockGuarded ("block " ++ show bh)
          (validateFullBlockIO db net cs getMtp False block spent)
  case vr of
    Left verr -> do
      mBestNow <- getBestBlockHash db
      when (classifyBlockReject verr == BlockRejectVerdict
            && mBestNow == Just (csBestBlock cs)) $
        void (invalidBlockFound db hc bh)
      return (Left ("Core full-block validation: " <> verr))
    Right () -> return (Right ())
