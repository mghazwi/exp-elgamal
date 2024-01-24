## Exponential ElGamal (Homomorphic) Encryption on Arkworks
### This code is for academic purposes ONLY. DO NOT USE IT IN PRACTICE.

Implements the exponential ElGamal encryption which allow ciphertext addition. The implementations support distributed key generation, encryption, re-encryption (key switching), and decryption (using baby step giant step to solve dl). It uses [BabyJubJub EC](https://docs.rs/ark-ed-on-bn254/latest/ark_ed_on_bn254/) to provide a fast verification on blockchains that support BN254 such as Ethereum.

It is worth noting on distributed key generation: we assume that parties are not allowed to cancel their participation. This assumption is appropriate for the some use cases. However, an extension of this project would ideally explore more resilient methods of key generation.

### Features

* Distributed key generation (not designed to be secure against cancellation!)
* encryption
* re-encryption (key switching)
* decryption

as well as universally verifiable proofs:

This library was written and used for the paper[TODO](https://todo.com)