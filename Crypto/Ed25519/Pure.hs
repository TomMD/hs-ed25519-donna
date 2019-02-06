module Crypto.Ed25519.Pure (
             PrivateKey
           , PublicKey
           , Signature(..)
           , generatePrivate
           , generatePublic
           , generateKeyPair
           , sign, valid
           -- , makeShared
           -- * Import/Export interface
           , importPublic, importPrivate
           , exportPublic, exportPrivate
           ) where

import Crypto.Random
import Data.ByteString(ByteString)
import qualified Data.ByteString        as B
import qualified Data.ByteString.Unsafe as BU
import Foreign.C.Types
import Foreign.Ptr
import Foreign.Marshal.Alloc (allocaBytes)
import System.IO.Unsafe (unsafePerformIO)
import Control.DeepSeq (NFData)

-- |The type of a Ed25519 private key.
newtype PrivateKey = Priv ByteString
            deriving (Show, NFData)

-- |The type of a Ed25519 public key.
newtype PublicKey  = Pub ByteString
            deriving (Show, NFData)

newtype Signature  = Sig ByteString
            deriving (Show, NFData)

-- Randomly generate an Ed25519 private key
generatePrivate :: CryptoRandomGen g => g -> Either GenError (PrivateKey, g)
generatePrivate g =
    case genBytes privateKeySize g of
        Left e          -> Left e
        Right (bs, g')  -> Right (Priv bs, g')

generatePublic :: PrivateKey -> PublicKey
generatePublic (Priv priv) = Pub (ed25519_publickey priv)

generateKeyPair :: CryptoRandomGen g => g -> Either GenError (PrivateKey, PublicKey, g)
generateKeyPair g =
    case generatePrivate g of
        Left e       -> Left e
        Right (q,g2) -> Right (q, generatePublic q, g2)

sign :: ByteString -> PrivateKey -> PublicKey -> Signature
sign = ed25519_sign

-- | Returns true if the signature is valid
valid :: ByteString -> PublicKey -> Signature -> Bool
valid = ed25519_sign_open

--------------------------------------------------------------------------------
--  Lifted-C Functions

ed25519_publickey :: ByteString -> ByteString
ed25519_publickey priv =
    unsafePerformIO $ B.useAsCString priv $ \q -> createByteString publicKeySize (ed25519_publickey_c q)

createByteString :: Int -> (Ptr CChar -> IO ()) -> IO ByteString
createByteString len f = do
       allocaBytes len $ \p -> do
           f p
           B.packCStringLen (p,len)

-- XXX Use c2hs or some such? Probably not worth the overhead to users.
signatureSize :: Int
signatureSize  = 64

publicKeySize, privateKeySize :: Int
publicKeySize  = 32
privateKeySize = 32

ed25519_sign :: ByteString -- ^ Message
             -> PrivateKey
             -> PublicKey
             -> Signature
ed25519_sign msg (Priv q) (Pub p) = unsafePerformIO $ do
    BU.unsafeUseAsCStringLen msg $ \(mp,mlen) -> BU.unsafeUseAsCString q $ \qp -> BU.unsafeUseAsCString p $ \pp ->
        Sig `fmap` (createByteString signatureSize $ \sigPtr -> ed25519_sign_c mp (fromIntegral mlen) qp pp sigPtr)

ed25519_sign_open :: ByteString -- ^ Message
                  -> PublicKey
                  -> Signature
                  -> Bool
ed25519_sign_open bs (Pub p) (Sig s)
    | B.length s /= 64 = False
    | otherwise = unsafePerformIO $ do
    BU.unsafeUseAsCStringLen bs $ \(mp,mlen) -> BU.unsafeUseAsCString p $ \pp -> BU.unsafeUseAsCString s $ \sp ->
        return (0 == ed25519_sign_open_c mp (fromIntegral mlen) pp sp)

-- | Only included in hopes of a 'curve25519_scalarmult' function being
-- added.
curve25519_scalarmult_basepoint :: PrivateKey -> PublicKey
curve25519_scalarmult_basepoint (Priv q) = Pub $ unsafePerformIO $ do
    BU.unsafeUseAsCString q $ \qp -> createByteString 32 (curved25519_scalarmult_basepoint_c qp)

-- curve25519_scalarmult :: PublicKey -> PrivateKey -> ByteString
-- curve25519_scalarmult (Pub p) (Priv q) = unsafePeformIO $ do
--     BU.unsafeUseAsCString q $ \qp -> BU.unsafeUseAsCString p $ \pp -> createByteString multSize $ curved25519_scalarmult_c qp pp

importPublic :: ByteString -> Maybe PublicKey
importPublic bs | B.length bs == 32 = Just (Pub bs)
                | otherwise         = Nothing

exportPublic :: PublicKey -> ByteString
exportPublic (Pub bs) = bs

importPrivate :: ByteString -> Maybe PrivateKey
importPrivate bs | B.length bs == 32 = Just (Priv bs)
                 | otherwise         = Nothing

exportPrivate :: PrivateKey -> ByteString
exportPrivate (Priv bs) = bs

--------------------------------------------------------------------------------
--  C Bindings

foreign import ccall unsafe "ed25519_publickey"
    ed25519_publickey_c :: Ptr CChar -> Ptr CChar -> IO ()

foreign import ccall unsafe "ed25519_sign"
    ed25519_sign_c :: Ptr CChar {- msg -} -> CInt {- mlen -}
                   -> Ptr CChar {- priv key -} -> Ptr CChar {- pub key -}
                   -> Ptr CChar {- signature -} -> IO ()

foreign import ccall unsafe "ed25519_sign_open"
    ed25519_sign_open_c :: Ptr CChar {- msg -} -> CInt {- mlen -}
                        -> Ptr CChar {- pub key -}
                        -> Ptr CChar {- signature -} -> CInt

foreign import ccall unsafe "curved25519_scalarmult_basepoint"
    curved25519_scalarmult_basepoint_c :: Ptr CChar {- pub ey -}
                                       -> Ptr CChar {- priv key -}
                                       -> IO ()
