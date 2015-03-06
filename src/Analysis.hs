{-# LANGUAGE
    DeriveGeneric
    , GeneralizedNewtypeDeriving
    , OverloadedStrings #-}

module Analysis where

import Conduit hiding (sinkHandle)
import Control.Applicative
import Control.Monad.Reader
import Data.Aeson
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy.Char8 as BSL
import qualified Data.ByteString.Lazy.Builder as BSLB
import qualified Data.Csv as CSV
import Control.Monad hiding (mapM, mapM_)
import qualified Data.Conduit.Combinators as CC
import qualified Data.Conduit.Binary as CB
import qualified Data.List as DL
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
        determineFileType' trie =$
        CC.map (\t -> (fp, t)))




{-
    trie <- lift ask
    maybeFilePath <- await
    case maybeFilePath of
        Just fp -> do
            sig <- CB.sourceFile (encodeString fp) $= determineFileType' trie =$ CC.sinkList
            yield $ (encodeString fp, sig)
            determineFileType
        _ -> return ()
-}
determineFileType' :: TR.Trie T.Text -> Conduit BS.ByteString CsvResource T.Text
determineFileType' trie = do
    maybeBs1 <- await
    maybeBs2 <- await
    case maybeBs1 of
        Just bs -> do
            let sm = TR.submap bs trie
            if TR.null sm then do
                yield $ T.concat $ TR.elems trie
            else do
                case maybeBs2 of
                    Just bsn -> do
                        leftover $ BS.append bs bsn
                        determineFileType' trie
                    _ -> return ()
            {-case checkSig fsigs bs of
                Just fs -> yield $ desc fs
                _       -> return ()-}
        _ -> return ()
{-
checkSig :: TR.Trie T.Text -> BS.ByteString -> Maybe T.Text
checkSig trie bs =


checkSig' :: TR.Trie T.Text -> BS.ByteString -> TR.Trie T.Text -> BS.ByteString -> TR.Trie T.Text
checkSig' tAcc bsAcc trie b
    | null $ TR.subMap b t = tAcc
    |
-}

{-
checkSig' :: TR.Trie T.Text -> TR.Trie T.Text -> BS.ByteString -> TR.Trie T.Text
checkSig' trie prevSubTrie bs  =
    if null $ TR.subMap bs trie then
        prevSubTrie
    else
       checkSig'
-}

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

isSignatureOf :: BS.ByteString -> FileSignature -> Bool
isSignatureOf bs fs = isSignatureOf' (hexRep bs fs) fs
  where
    -- The hex representation of a ByteString.
    -- FIXME : Waaaay too many conversions...
    hexRep :: BS.ByteString -> FileSignature -> BS.ByteString
    hexRep bs' fs' = bs2hex $ BS.take (offset fs' + BS.length (sig fs')) bs'


-- | Does the bytestring match the signature.
isSignatureOf' :: BS.ByteString -> FileSignature -> Bool
isSignatureOf' bsl fs = and $ BS.zipWith (\l r -> l == r) bsl (sig fs)


-- | Convert a Text type to a strict ByteString
-- FIXME : Lots of conversions here, not sure if they are all needed...
text2hex :: T.Text -> BS.ByteString
text2hex t = BSL.toStrict $ BSLB.toLazyByteString $ BSLB.wordHex $ read $ T.unpack t


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
                (FileSignature d (text2hex $ T.append "0x" $ rmSpace s)
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
    trieBuilder t (FileSignature _ s _ _ ft _) =
        let resolveConflict v1 v2 = T.append (T.append v1 " or ") v2
        in  TR.insertWith' resolveConflict s ft t
