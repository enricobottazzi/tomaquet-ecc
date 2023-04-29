import unittest
import random

from ecc import FieldElement, Point, S256Field, G, N, KeyPair, ShamirSecretSharing, DistributedKeyGeneration, DistributedKeyGenerationMember

class ECCTest(unittest.TestCase):

    def test_on_curve(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        valid_points = ((192, 105), (17, 56), (1, 193))
        invalid_points = ((200, 119), (42, 99))
        for x_raw, y_raw in valid_points:
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            Point(x, y, a, b)  # <1>
        for x_raw, y_raw in invalid_points:
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            with self.assertRaises(ValueError):
                Point(x, y, a, b)  # <1>

    def test_point_add(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        x1 = FieldElement(192, prime)
        y1 = FieldElement(105, prime)
        x2 = FieldElement(17, prime)
        y2 = FieldElement(56, prime)
        p1 = Point(x1, y1, a, b)
        p2 = Point(x2, y2, a, b)
        assert (p1+p2).x == FieldElement(170, 223)
        assert (p1+p2).y == FieldElement(142, 223)

    def test_point_mul(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        x1 = FieldElement(15, prime)
        y1 = FieldElement(86, prime)
        p1 = Point(x1, y1, a, b)
        assert(7*p1).x == None 
        assert(7*p1).y == None 

    def test_gen_point_order(self):
        gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
        p = 2**256 - 2**32 - 977
        n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

        x = FieldElement(gx, p)
        y = FieldElement(gy, p)
        a = FieldElement(0, p)
        b = FieldElement(7, p)
        G = Point(x, y, a, b)
        assert (n*G).x == None
        assert (n*G).y == None

    def test_gen_point_order_2(self):
        assert (N*G).x == None
        assert (N*G).y == None

    def test_key_pair(self):
        # private key from ethereum book
        r = int("f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315", 16)
        kp2 = KeyPair(r)

        assert kp2.point.x == S256Field(0x6e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b)
        assert kp2.point.y == S256Field(0x83b5c38e5e2b0c8529d7fa3f64d46daa1ece2d9ac14cab9477d042c84c32ccd0)
        assert kp2.public_key() == '046e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b83b5c38e5e2b0c8529d7fa3f64d46daa1ece2d9ac14cab9477d042c84c32ccd0'
        assert kp2.public_key_no_prefix() == '6e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b83b5c38e5e2b0c8529d7fa3f64d46daa1ece2d9ac14cab9477d042c84c32ccd0'
        assert kp2.address() == '0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9'

    def test_shamir_secret_sharing(self):

        threshold = 3
        total_shares = 5
        degree = threshold - 1
        secret = 123
        sss = ShamirSecretSharing(threshold, total_shares, secret)

        # SSS should not be init if the threshold is greater than the total number of shares
        with self.assertRaises(AssertionError):
            ShamirSecretSharing(3, 2, secret)

        # Test the generation of the coefficients. 
        coefficients = sss.generate_coefficients()
        # Should return as many coefficients as the degree of the polynomial
        assert len(coefficients) == degree
        # Should not return more coefficients than the degree of the polynomial
        assert len(coefficients) <= degree

        # Test the shares generation 
        shares = sss.split_secret()
        # Should return as many shares as the total number of shares
        assert len(shares) == total_shares
        # Should not return a share with ID 0
        for ID, _ in shares:
            assert ID != 0
        # Should not return two shares with the same ID
        IDs = [ID for ID, _ in shares]
        unique_IDs = set(IDs)
        assert len(IDs) == len(unique_IDs)
        # Should recover the secret passing all the shares
        recovered_secret = sss.recover_secret(shares)
        assert recovered_secret == secret

        # Should recover the secret passing a random subset of the shares that is equal to the threshold
        random_subset = random.sample(shares, threshold)
        recovered_secret = sss.recover_secret(random_subset)
        assert recovered_secret == secret

        # Should throw an error if try to recover the secret passing a random subset of the shares that is less than the threshold
        random_subset = random.sample(shares, threshold - 1)
        with self.assertRaises(ValueError):
            sss.recover_secret(random_subset)

        # Applying a scalar to the secret should match the recovered secret generated from all the shares multiplied by the same scalar
        scalar = 2
        mul_secret = scalar * secret
        mul_shares = [(ID, scalar * share) for ID, share in shares]
        mul_recovered = sss.recover_secret(mul_shares)
        assert mul_recovered == mul_secret

        # Applying the secret to a pub value should match the recovered value generated from applying the secret shares to the same pub value
        pub = 123
        pub_shares = [(ID, pub * share) for ID, share in shares]
        pub_recovered = sss.recover_secret(pub_shares)
        assert pub_recovered == pub * secret

        # Apply the secret as a scalar multiplication of a generator point 
        pub_shares = [(ID, share * G) for ID, share in shares]
        pub_recovered = sss.recover_secret(pub_shares)
        assert pub_recovered == secret * G

    def test_distributed_key_generation(self):

        # Setup DKG
        threshold = 3
        n = 4
        dkg = DistributedKeyGeneration(threshold, n)

        # Create members of the DKG ceremony
        member_1_secret = 123
        member_2_secret = 456
        member_3_secret = 789
        member_4_secret = 102

        dkg.add_member(member_1_secret)
        dkg.add_member(member_2_secret)
        dkg.add_member(member_3_secret)
        dkg.add_member(member_4_secret)

        # Check that the members have been added to the ceremony correctly 
        assert len(dkg.members) == n

        # Check that the secrets of the members have been set correctly
        for i in range(n):
            assert dkg.members[i].secret == [member_1_secret, member_2_secret, member_3_secret, member_4_secret][i]

        # Check that their index has been set correctly
        for i in range(n):
            assert dkg.members[i].index == i

        # kick off the DKG ceremony
        dkg.kick_off_ceremony()
        
        # Check that the shares received by each users are equal to N
        for member in dkg.members:
            assert len(member.shares) == n

        # Check that for each share within the shares received by each the ID of the share is equal to the ID of the member
        for member in dkg.members:
            for share in member.shares:
                assert share[0] == member.index + 1

        # Should throw an error if try to add member to the ceremony if the ceremony is full (i.e. the number of members has reached n)
        with self.assertRaises(AssertionError):
            dkg.add_member(123)

if __name__ == '__main__':
    unittest.main()