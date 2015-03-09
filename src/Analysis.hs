{-# LANGUAGE
    DeriveGeneric
    , GeneralizedNewtypeDeriving
    , OverloadedStrings #-}

module Analysis where

import Conduit as CC hiding (sinkHandle, sinkList)
import Control.Applicative
import Control.Monad.Reader
import Data.Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Builder as BSLB
import qualified Data.Csv as CSV
import Control.Monad hiding (mapM, mapM_)
import qualified Data.Conduit.Combinators as CC
import qualified Data.Conduit.Binary as CB
import qualified Data.List as DL
import Data.Maybe (fromJust)
import qualified Data.Trie as TR
import qualified Data.Trie.Convenience as TR
import qualified Data.Text as T
import qualified Data.Text.Encoding as T (encodeUtf8)
import qualified Data.Text.Read as T
import qualified Data.Vector as V
import Data.Word
import Filesystem.Path
import Filesystem.Path.CurrentOS
import GHC.Generics
import qualified System.IO as SI (stdout)
import Prelude hiding (FilePath, map, mapM, mapM_)

import Debug.Trace

{-
data CsvData = CsvData
    { fileSignatures :: [FileSignature]
    } deriving (Eq, Show)
-}
newtype CsvResource a = CsvResource { unCsvResource :: ReaderT (TR.Trie T.Text) (ResourceT IO) a }
    deriving ( Applicative
             , Functor
             , Monad
             , MonadBase IO
             , MonadIO
             , MonadResource
             , MonadReader (TR.Trie T.Text)
             , MonadThrow
             )

run :: TR.Trie T.Text -> CsvResource a -> ResourceT IO a
run csv = flip runReaderT csv . unCsvResource

--test :: FilePath -> IO ()
test fp1 fp2 = do
    sigs <- loadSigsFromCsv fp1
    runResourceT $ run sigs $ do
        sourceDirectoryDeep False fp2 $= determineFileType $$ CC.print


sink :: Sink (String,T.Text) (CsvResource) ()
sink = do
    val <- await
    case val of
        Just t -> do
            liftIO $ print t
            sink
        _ -> return ()


determineFileType :: Conduit FilePath (CsvResource) (FilePath, T.Text)
determineFileType = do
    trie <- lift ask
    awaitForever (\fp ->
        CB.sourceFile (encodeString fp) $=
        CC.concatC $=
        determineFileType' [] trie =$
        CC.map (\t -> (fp, t)))


determineFileType' :: [Word8] -> TR.Trie T.Text -> Conduit Word8 CsvResource T.Text
determineFileType' ws trie = do
    maybeWord1 <- await
    case maybeWord1 of
        Just w1 -> do
            let sm = TR.submap (BS.pack (ws ++ [w1])) trie
            if TR.null sm then do
                if Prelude.null ws then
                   yield $ "No signature found."
                else
                    yield $ T.concat $ TR.elems trie
            else
                determineFileType' (ws ++ [w1]) sm
        _ -> return ()


-------------------------------------------------------------------------------
-- The magic begins!
-------------------------------------------------------------------------------

data Signatures = Signatures
    { signatures :: [FileSignature]
    } deriving (Eq, Generic, Show)


data FileSignature = FileSignature
    { desc     :: T.Text
    , sig      :: BS.ByteString
    , sigType  :: T.Text
    , offset   :: Int
    , fileType :: T.Text
    , moreInfo :: T.Text
    } deriving (Eq, Show)


-- | Convert a Text type to a Word8.
-- FIXME : There must be  better way than using read.
string2w8 :: String -> Word8
string2w8 t = (read t) :: Word8


-- | Convert a strict ByteString into its hex format.
-- FIXME : Lots of conversions here, is there a better way?
bs2hex :: BS.ByteString -> BS.ByteString
bs2hex bs = BSL.toStrict $ BSLB.toLazyByteString $ BSLB.byteStringHex bs


loadSigsFromCsv :: FilePath -> IO (TR.Trie T.Text)
loadSigsFromCsv fp = do
    csvData <- BSL.readFile $ encodeString fp
    case CSV.decode CSV.NoHeader csvData of
        Left err -> error err
        Right v -> return $
            trieify $ V.foldl (\acc (d,s,st,off,ft,mi) ->
                (FileSignature d (BS.pack $ fmap (string2w8 . ("0x"++))$ words s)
                    st (offset2int off) ft mi) : acc)
                [] v
  where
    -- Offset in the csv data can be an integer or N/A.
    offset2int :: T.Text -> Int
    offset2int t | t == "N/A" = 0
           | otherwise =
                case T.decimal t of
                    -- Left is an error, so return 0. This is safe because
                    -- we are only returning the startpoint.
                    Left _ -> 0
                    Right (n,_) -> n
    rmSpace :: T.Text -> T.Text
    rmSpace t = T.filter (\c -> c /= ' ') t


trieify :: [FileSignature] -> TR.Trie T.Text
trieify fss =
    foldl trieBuilder TR.empty fss
  where
    trieBuilder :: TR.Trie T.Text -> FileSignature -> TR.Trie T.Text
    trieBuilder t (FileSignature d s _ _ ft _) =
        let resolveConflict v1 v2 = T.append (T.append v1 " or ") v2
        in  TR.insertWith' resolveConflict s (T.append (T.append ft " : ") d ) t

