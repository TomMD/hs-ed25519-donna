module Crypto.Ed25519.Exceptions (
                PrivateKey(..)
              , PublicKey(..)
              , Signature(..)
              , generatePrivate
              , generatePublic
              , generateKeyPair
              , sign, valid
              ) where

import Data.ByteString(ByteString)
import Crypto.Ed25519.Pure(PublicKey(..),PrivateKey(..),Signature(..))
import qualified Crypto.Ed25519.Pure as Pure
import Crypto.Random

-- |Randomly generate an Ed25519 private key.
generatePrivate :: CryptoRandomGen g => g -> (PrivateKey, g)
generatePrivate = throwLeft . Pure.generatePrivate

-- |Randomly generate a curve25519 public key.
generatePublic :: PrivateKey -> PublicKey
generatePublic = Pure.generatePublic

generateKeyPair :: CryptoRandomGen g => g -> (PrivateKey, PublicKey, g)
generateKeyPair = throwLeft . Pure.generateKeyPair

sign :: ByteString -> PrivateKey -> PublicKey -> Signature
sign = Pure.sign

valid :: ByteString -> PublicKey -> Signature -> Bool
valid = Pure.valid
