This is a trivial Haskell binding to floodyberry's Ed25519 C implementation in
much the same style as [ACW's curve25519 bindings](https://github.com/acw/curve25519).

# Usage

Just import, generate keys, sign and verify:

```
{-# LANGUAGE OverloadedStrings #-}
import Crypto.Ed25519
import Crypto.Random
import Data.ByteString.Char8 ()

main :: IO ()
main =
  do g1 <- newGenIO :: IO SystemRandom
     let (q1,p1,g2) = generateKeyPair g1
         (q2,p2,_) = generateKeyPair g2
         msg1 = "Some message I want to sign."
         msg2 = "Another message someone else signed"
         sig1 = sign msg1 q1 p1
         sig2 = sign msg2 q2 p2
     putStrLn "Valid signature and public key pairs: "
     print $ valid msg1 p1 sig1
     print $ valid msg2 p2 sig2
     putStrLn "Invalid signature and public key pairs: "
     print $ valid msg1 p2 sig2
     print $ valid msg2 p1 sig2
```

# Batch Signature Verification

One of the features of Ed25519 is the ability to perform batch signature
verification.  This is harder to support than might be expected due to its need
for cryptographically strong random numbers during batch verification.  I have
an issue filed with the upstream package to allow the randomness as an
additional parameter.  Till then you'll have to do without or cook-up your own
one-off binding.

