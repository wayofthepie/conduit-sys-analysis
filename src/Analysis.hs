{-# LANGUAGE
    DeriveGeneric
    , OverloadedStrings #-}

module Analysis where

import Conduit hiding (sinkHandle)
import Control.Applicative
import Data.Aeson
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy.Char8 as BSL
import qualified Data.ByteString.Lazy.Builder as BSLB
import Control.Monad hiding (mapM, mapM_)
import qualified Data.Conduit.Combinators as CC
import qualified Data.Conduit.Binary as CB
import qualified Data.List as DL
import qualified Data.Text as T
import qualified Data.Text.Encoding as T (encodeUtf8)
import Data.Word
import Filesystem.Path
import Filesystem.Path.CurrentOS
import GHC.Generics
import qualified System.IO as SI (stdout)
import Prelude hiding (FilePath, map, mapM, mapM_)

import Debug.Trace

--test :: FilePath -> IO ()
test fp = runResourceT $ sourceDirectoryDeep False fp $= determineFileType $$ sink

sink :: (MonadResource m, MonadIO m) => Sink (String,[T.Text]) m ()
sink = do
    val <- await
    case val of
        Just t -> do
            liftIO $ print t
            sink
        _ -> return ()


determineFileType :: MonadResource m => Conduit FilePath m (String, [T.Text])
determineFileType = do
    maybeFilePath <- await
    case maybeFilePath of
        Just fp -> do
            sig <- CB.sourceFile (encodeString fp) $= determineFileType' $= CC.sinkList
            yield $ (encodeString fp, sig)
            determineFileType
        _ -> return ()



determineFileType' :: MonadResource m => Conduit BS.ByteString m T.Text
determineFileType' = do
    maybeBs <- await
    case maybeBs of
        Just bs -> do
            case checkSig bs  of
                Just fs -> yield $ desc fs
                _       -> return ()
            determineFileType'
        _ -> return ()

checkSig :: BS.ByteString -> Maybe FileSig
checkSig bs = DL.find (isSignatureOf bs) signatures'

--sourceDirectoryDeepWithName b f = (f, sourceDirectoryDeep
{-
streamFile :: MonadResource m => Conduit FilePath m (FilePath, BS.ByteString)
--streamFile = awaitForever sourceFile
streamFile = do
    filePath <- await
    case filePath of
        Just fp -> do
            yield (fp, sourceFile fp)
        _ -> return ()

-}

-------------------------------------------------------------------------------
-- The magic begins!
-------------------------------------------------------------------------------
data Signatures = Signatures
    { signatures :: [FileSig]
    } deriving (Eq, Generic, Show)

data FileSig = FileSig
    { desc   :: T.Text
    , mime   :: T.Text
    , sig    :: T.Text
    , offset :: Int
    , size   :: Int
    } deriving (Eq, Generic, Show)

instance FromJSON Signatures
instance ToJSON Signatures

instance FromJSON FileSig where
    parseJSON (Object v) =
        FileSig <$> v .: "desc"
                <*> v .: "mime"
                <*> v .: "signature"
                <*> v .: "offset"
                <*> v .: "size"

instance ToJSON FileSig


constructFileSig :: T.Text -> T.Text -> T.Text -> Int -> Int -> FileSig
constructFileSig d m sig off size = FileSig d m sig off size


isSignatureOf :: BS.ByteString -> FileSig -> Bool
isSignatureOf bs fs = isSignatureOf' (hexRep bs fs) fs
  where
    -- The hex representation of a ByteString.
    -- FIXME : Waaaay too many conversions...
    hexRep :: BS.ByteString -> FileSig -> BS.ByteString
    hexRep bs' fs' = bs2hex $ BS.take (offset fs' + size fs') bs'


-- | Does the bytestring match the signature.
isSignatureOf' :: BS.ByteString -> FileSig -> Bool
isSignatureOf' bsl fs = and $ BS.zipWith (\l r -> l == r) bsl (text2hex $ sig fs)


-- | Convert a Text type to a strict ByteString
-- FIXME : Lots of conversions here, not sure if they are all needed...
text2hex :: T.Text -> BS.ByteString
text2hex t = BSL.toStrict $ BSLB.toLazyByteString $ BSLB.wordHex $ read $ T.unpack t


-- | Convert a strict ByteString into its hex format.
-- FIXME : Lots of conversions here, is there a better way?
bs2hex :: BS.ByteString -> BS.ByteString
bs2hex bs = BSL.toStrict $ BSLB.toLazyByteString $ BSLB.byteStringHex bs


-- Load signatures from json sigs file.
loadSigs :: FilePath -> IO (Either String Signatures)
loadSigs sigsFile = (BSL.readFile $ encodeString sigsFile) >>=
    \bs -> return $ (eitherDecode bs ::  Either String Signatures)


-------------------------------------------------------------------------------
-- Test signatures
-------------------------------------------------------------------------------
signatures' :: [FileSig]
signatures' = [
        elf_sig,
        comp_7z_sig
    ]


elf_sig :: FileSig
elf_sig = constructFileSig "ELF Executable" "" "0x7f454c46" 0 8

comp_7z_sig :: FileSig
comp_7z_sig = constructFileSig "7zip compressed file"
    "application/x-7z-compressed" "0x377abcaf271c" 0 6



