import ecc
from hashlib import sha256

e = int.from_bytes(sha256(b'my secret key').digest(), 'big')
print(e)
kp = ecc.KeyPair(e)
print("priv key hex:", kp.private_key())
print("public key point:", kp.point) # the point is public available

# Execute scalar multiplication on the point
p2 = 2 * kp.point # Factor 2 is public! 
print("p2:", p2) # This is public!

# Alice should be in control of the private key for the point p2
# The factor should be secret then
private_key = e * 2
kp2 = ecc.KeyPair(private_key)
print("kp2:", kp2.point)
assert kp2.point == p2



