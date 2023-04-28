import ecc
from hashlib import sha256

pub = 2 * ecc.G # g^b

# Trusted party comes up with a secret 
a = int.from_bytes(sha256(b'my secret key').digest(), 'big')

# Trusted party creates a Shamir secret sharing scheme of 3 out of 5
threshold = 3
total_shares = 5
sss = ecc.ShamirSecretSharing(threshold, total_shares, a)

# Generate shares
shares = sss.split_secret()

pub_commitments = []

# Let each party execute a computation with their share
for i in range(0, len(shares)):
    comp_share = shares[i][1] * pub
    # append a tuple to the list of public commitments
    pub_commitments.append((shares[i][0], comp_share))

# Combine the pubkeys using lagrange interpolation 
combined = sss.recover_secret(pub_commitments)

print("combined pubkey", combined)
print("pub*a", a * pub)

# assert that the combined pubkey is the same as g^b*a
assert combined == a * pub