# tomaquet ecc

Primitives for elliptic curve cryptography. Contains:

- Basic Elliptic Curve Operations Support on secp256k1 curve
- Shamir Secret Sharing Scheme with optional support for Feldman Verifiable Secret Sharing Scheme
- Distributed Key Generation Scheme

### Useful Resources 

- Elliptic Curve Operations : [Programming Bitcoin](https://digilib.stekom.ac.id/assets/dokumen/ebook/feb_d82be9cf1cb52e2b294a82275318a5c8235444eb_1654093256.pdf)
- Shamir Secret Sharing Scheme : [Tanja Lange Course](https://www.youtube.com/watch?v=dPIp04ZB_xI&t=21s)
- Feldman Verifiable Secret Sharing Scheme : [Anoma](https://blog.anoma.net/demystifying-aggregatable-distributed-key-generation/), [Crypto StackExchange](https://crypto.stackexchange.com/questions/6637/understanding-feldmans-vss-with-a-simple-example), [Wikipedia](https://en.wikipedia.org/wiki/Verifiable_secret_sharing#Feldman.E2.80.99s_scheme)
- Distributed Key Generation Scheme: [Asynchronous Distributed Key Generation](https://youtu.be/3pJx-FCtQhc)

### TODO

- [ ] Add support for DKG
- [ ] Publish the repo and add link inside the cryptography forum
- [ ] Add DHKE support
- [ ] Add Scheme for nullifiers
- [ ] Add function to perform partial signature from a secret share
- [ ] Add ECC support to DKG

Original scheme

- Multiparties have a secret key fraction and publicly commit to their public key fraction.
- Multiparties takes Alice's public key and generate a shared secret fraction, apply a scalar to it and publicly commit to it. Or it can actually be a signature.
- Alice can generate the shared secret key starting from her private key and the public key of the multiparties. 
- Alice can prove that she knows the secret behind the commitment and use the secret as a nullifier in the proving system.

