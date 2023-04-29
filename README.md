# tomaquet ecc

Primitives for elliptic curve cryptography. Contains:

- Basic Elliptic Curve Operations Support on secp256k1 curve
- Shamir Secret Sharing Scheme

### TODO 

- [ ] Add function to verify if a share is valid 
- [ ] Add DHKE support
- [ ] Add Scheme for nullifiers
- [ ] Publish the repo and add link inside the cryptography forum

Original scheme

- Multiparties have a secret key fraction and publicly commit to their public key fraction.
- Multiparties takes Alice's public key and generate a shared secret fraction, apply a scalar to it and publicly commit to it. Or it can actually be a signature.
- Alice can generate the shared secret key starting from her private key and the public key of the multiparties. 
- Alice can prove that she knows the secret behind the commitment and use the secret as a nullifier in the proving system.

