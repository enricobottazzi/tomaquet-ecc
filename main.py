import ecc
from unittest import TestSuite, TextTestRunner
from hashlib import sha256

suite = TestSuite()
suite.addTest(ecc.ECCTest('test_on_curve'))
suite.addTest(ecc.ECCTest('test_point_add'))
suite.addTest(ecc.ECCTest('test_point_mul'))
suite.addTest(ecc.ECCTest('test_gen_point_order'))
suite.addTest(ecc.ECCTest('test_gen_point_order_2'))
suite.addTest(ecc.ECCTest('test_key_pair'))
suite.addTest(ecc.ECCTest('test_shamir_secret_sharing'))
TextTestRunner().run(suite)

# Generate key pair from brain private key
e = int.from_bytes(sha256(b'my secret key').digest(), 'big')
kp = ecc.KeyPair(e)
print("priv key hex:", kp.private_key())
print("point:", kp.point)
