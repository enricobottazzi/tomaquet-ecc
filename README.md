# ecc-pyt
Ecc experiements

Contains: 

- Basic ECC implementation and operations 
- Spec for secp256k1 curve
- Implementations for Shamir Secret Sharing Scheme managed by a dealer

# Experiments 

**nullifier_1** 

- Bob takes Alice's public key and apply a scalar of a constant value to it to generate a new public key
- Alice takes the result and apply the same scalar to her private key.
- Alice now has a private key that corresponds to the new public key that Bob generated.
- In a proving system, Alice's public key can be associated with this new public key. Alice can use this private key as a secret, prove that she knows it and use the hash of this secret as nullifier in the zkp system. The problem of that is that this private key2 still need to be passed as input for the circuit. Since this private key2 is generated just by applying a scalar to the original private key, and the scalar is known by everyone, leaking the private key2 is equivalent to leaking the original private key.

A solution to this scheme would be to generate the scalar as a shamir secret sharing multi party computation and just publish a commitment to it. In this way only Alice knows the scalar, so she can generate the private key2 and use it as a input for the proving system. In this scenario, leaking the private key2 wouldn't lead to leaking the original private as the scalar is not known by anyone.

**nullifier_2**

- [ ] Generate the scalar as a shamir secret sharing multi party computation. 

**nullifier_3**

- Trusted party generates secret a and a related public key A.
- The secret gets shared among n parties. The shamir secret sharing scheme is t of out n.
- Each party takes their secret and generate a fraction of a public key from it.
- Each party publishes their public key fraction.
- Combine these parts together using Lagrange Interpolation should result in the public key A.

This is wrong actually. We need to use Lagrange Interpolation here! 

- [ ] Modify prime. 


**nullifier_4**

Original scheme

- Multiparties have a secret key fraction and publicly commit to their public key fraction.
- Multiparties takes Alice's public key and generate a shared secret fraction, apply a scalar to it and publicly commit to it.
- Alice can generate the shared secret key starting from her private key and the public key of the multiparties. 
- Alice can prove that she knows the secret behind the commitment and use the secret as a nullifier in the proving system.

