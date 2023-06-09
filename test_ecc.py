import unittest
import random

from ecc import FieldElement, Point, S256Field, S256Point, G, N, KeyPair, ShamirSecretSharing, DistributedKeyGeneration, Utils, TimeLockPuzzle, RSA

class ECCTest(unittest.TestCase):

    def test_modulo_operations(self):
        prime = 223
        a = [FieldElement(0, prime), FieldElement(1, prime), FieldElement((prime-1)/2, prime), FieldElement((prime+1)/2, prime), FieldElement(prime - 1, prime)]
        b = [FieldElement(0, prime), FieldElement(1, prime), FieldElement((prime-1)/2, prime), FieldElement((prime+1)/2, prime), FieldElement(prime - 1, prime)]

        # compute all the possible combinations of a+b 
        for i in range(len(a)):
            for j in range(len(b)):
                sum = a[i] + b[j]
                print("a: {}, b: {}, sum: {}".format(a[i], b[j], sum))
                print(a[i] <= sum)
                print(b[j] <= sum)

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
        gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
        p = 2**256 - 2**32 - 977
        n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

        x = FieldElement(gx, p)
        y = FieldElement(gy, p)
        a = FieldElement(0, p)
        b = FieldElement(7, p)
        G = Point(x, y, a, b)
        
        # The scalar lives in the field n. Therefore n + 1 mod n should be equal to 1 mod n 
        assert ((n+1)*G).x == G.x
        assert ((n+1)*G).y == G.y

    def test_gen_point_order_3(self):
        assert (N*G).x == None
        assert (N*G).y == None

    def test_p256_point_homomorphic_operation(self):
        # Test homomorphic operation on P256 curve
        left = 21 * G 
        right = 19 * G + 2 * G
        assert left == right

    def test_key_pair(self):
        # private key from ethereum book
        r = int("f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315", 16)
        kp2 = KeyPair(r)

        assert kp2.point.x == S256Field(0x6e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b)
        assert kp2.point.y == S256Field(0x83b5c38e5e2b0c8529d7fa3f64d46daa1ece2d9ac14cab9477d042c84c32ccd0)
        assert kp2.public_key() == '046e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b83b5c38e5e2b0c8529d7fa3f64d46daa1ece2d9ac14cab9477d042c84c32ccd0'
        assert kp2.public_key_no_prefix() == '6e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b83b5c38e5e2b0c8529d7fa3f64d46daa1ece2d9ac14cab9477d042c84c32ccd0'
        assert kp2.address() == '0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9'

        private_key_over_range = N + 1
        expected_error_message = "secret must be an integer in the range [1, n-1]"

        with self.assertRaises(ValueError) as cm:
            KeyPair(private_key_over_range)

        self.assertEqual(str(cm.exception), expected_error_message)

    def test_shamir_secret_sharing(self):
            
        threshold = 3
        n = 4
        degree = threshold - 1

        # Test Shamir Secret Sharing using different prime field setups
        prime_1 = 5
        generator_1 = FieldElement(3, 11)
        set_up_1 = (prime_1, generator_1)

        prime_2 = N
        generator_2 = G
        set_up_2 = (prime_2, generator_2)

        for prime, generator in [set_up_1, set_up_2]:
            secret = FieldElement(random.randint(1, prime-1), prime)
            sss = ShamirSecretSharing(threshold, n, secret)

            # SSS should not be init if the threshold is greater than the total number of shares
            with self.assertRaises(AssertionError):
                ShamirSecretSharing(3, 2, secret)

            # Test the shares generation 
            (shares, coefficients) = sss.split_secret()

            # Should return as many coefficients as the degree of the polynomial
            assert len(coefficients) == degree
            # Should not return more coefficients than the degree of the polynomial
            assert len(coefficients) <= degree

            # Should return as many shares as the total number of shares
            assert len(shares) == n
            # Should not return a share with ID 0
            for ID, _ in shares:
                assert ID.num != 0
            # Should not return two shares with the same ID
            IDs = [ID.num for ID, _ in shares]
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
            if prime == N:
                pub_shares = [(ID, share.num * G) for ID, share in shares]
                pub_recovered_2 = sss.recover_secret_ec(pub_shares)
                assert pub_recovered_2 == secret.num * G

            # Should allow the dealer to commit to the coefficients using a correct generator point
            if type(generator) == S256Point:
                commitments_ec = sss.commit_coefficients_ec(coefficients, generator)
                assert type(commitments_ec[0]) == S256Point
                # User should be able to verify their share using the commimtnet
                for share in shares:
                    assert sss.verify_share_ec(share, commitments_ec, generator)

            else:
                commitments = sss.commit_coefficients(coefficients, generator)
                assert type(commitments[0]) == FieldElement
                # User should be able to verify their share using the commimtnet
                for share in shares:
                    assert sss.verify_share(share, commitments, generator)

    def test_distributed_key_generation(self):

        # Setup DKG
        threshold = 3
        n = 4
        prime = N
        dkg = DistributedKeyGeneration(threshold, n, N)

        # Create secrets for the members of the DKG ceremony and add them to the ceremony
        secrets = [FieldElement(random.randint(1, prime-1), prime) for _ in range(n)]
        for secret in secrets:
            dkg.add_member(secret)

        # Members should have been added to the ceremony correctly 
        assert len(dkg.members) == n

        # Index of the member should have been set correctly. For example, the first member added should have index 1
        for i in range(n):
            assert dkg.members[i].index == i + 1

        # kick off the DKG ceremony
        dkg.kick_off_ceremony()

        # Each member should have received three shares. Each share should have the same ID as the member
        for member in dkg.members:
            assert len(member.shares) == threshold
            for share in member.shares:
                assert share[0].num == member.index

        
        # # Consider member 1 as the dealer, check that the user 1 generates the correct number of shares
        # dealer = dkg.members[0]
        # shares = dealer.split_secret()
        # assert len(shares) == threshold

        # # The shares should have IDs of the other members but not of the dealer
        # IDs = [ID.num for ID, _ in shares]
        # assert IDs == [2, 3, 4]

    #     # Let member 1 generates the shares. The shares should be 3
    #     shares = dealer.generate_shares()
    #     print(shares)
    #     assert len(shares) == threshold

    #     # Check that the secrets of the members have been set correctly
    #     for i in range(n):
    #         assert dkg.members[i].secret == [member_1_secret, member_2_secret, member_3_secret, member_4_secret][i]

    #     # Each member shouldn't have their private share yet
    #     for member in dkg.members:
    #         assert member.private_share == None

        
    #     # Check that the shares received by each users are equal to N
    #     for member in dkg.members:
    #         assert len(member.shares) == n

    #     # Check that for each share within the shares received by each the ID of the share is equal to the ID of the member
    #     for member in dkg.members:
    #         for share in member.shares:
    #             assert share[0] == member.index + 1

    #     # Should throw an error if try to add member to the ceremony if the ceremony is full (i.e. the number of members has reached n)
    #     with self.assertRaises(AssertionError):
    #         dkg.add_member(123)

    #     # Each member should now have their private share
    #     for member in dkg.members:
    #         assert member.private_share != None

    #     # Should compute the public key for the DKG ceremony
    #     assert dkg.compute_public_key() == sum([member.secret for member in dkg.members])

    def test_dhke(self):

        a = int("f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315", 16)
        alice = KeyPair(a)

        b = int("aaaaa2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315", 16)
        bob = KeyPair(b)

        # Alice and Bob should generate the same shared secret
        assert alice.generate_shared_secret(bob.point) == bob.generate_shared_secret(alice.point)

    def test_mp_dhke(self):

        a = int("f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315", 16)
        alice = KeyPair(a)

        b = int("aaaaa2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315", 16)
        bob = KeyPair(b)

        c = int("bbbbb2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315", 16)
        carl = KeyPair(c)

        # Alice and Bob shared secret 
        ab_ss = alice.generate_shared_secret(bob.point)
        ba_ss = bob.generate_shared_secret(alice.point)

        # Alice and Carl shared secret 
        ac_ss = alice.generate_shared_secret(carl.point)
        ca_ss = carl.generate_shared_secret(alice.point)

        # At this point Alice has a secret. Bob and Carl cannot access this secret unless they collude
        alice_agg_secret = ab_ss + ac_ss

        assert alice_agg_secret == ba_ss + ca_ss

        # Bob commits to his shared secret 
        bob_commitment = 2 * ba_ss

        # Carl commits to his shared secret
        carl_commitment = 2 * ca_ss

        # Alice should be able to prove that she knows the secret behind the commitment 
        alice_commitment = 2 * alice_agg_secret

        assert alice_commitment == bob_commitment + carl_commitment

        # test a different commitment type 
        bob_commitment_2 = Utils.generate_hash_commitment(ba_ss.x)
        carl_commitment_2 = Utils.generate_hash_commitment(ca_ss.x)
        alice_commitment_2 = Utils.generate_hash_commitment(ab_ss.x) + Utils.generate_hash_commitment(ac_ss.x)

        assert alice_commitment_2 == bob_commitment_2 + carl_commitment_2 

    def test_puzzle(self):

        # generate a random message to encrypt
        message_to_encrypt = random.randint(1, 1000)

        (_, _, n, a, t, enc_key, enc_message, _) = TimeLockPuzzle.encrypt(message_to_encrypt, 10, 20) 

        assert TimeLockPuzzle.decrypt(n, a, t, enc_key, enc_message) == message_to_encrypt

    def test_xor_encryption(self):

        # generate a random message to encrypt
        message_to_encrypt = random.randint(1, 1000)

        # generate a random key to encrypt the message with
        key = random.randint(1, 1000)

        # encrypt the message
        enc_message = Utils.xor(message_to_encrypt, key)

        # decrypt the message
        dec_message = Utils.xor(enc_message, key)

        # check that the decrypted message is the same as the original message
        assert dec_message == message_to_encrypt


from sympy import randprime

class TestRSA(unittest.TestCase):

    def setUp(self):
        p = randprime(0, 200)
        q = randprime(0, 200)
        # if p == q, need to regenerate
        while p == q:
            p = randprime(0, 200)
            q = randprime(0, 200)
        self.rsa = RSA(p, q)

    def test_keys(self):
        # Ensure that public and private keys are generated
        self.assertIsNotNone(self.rsa.public_key)
        self.assertIsNotNone(self.rsa.private_key)
        
    def test_encryption_decryption(self):
        # Ensure that encryption and decryption are working
        original_message = 20
        encrypted_message = self.rsa.encrypt(original_message)
        decrypted_message = self.rsa.decrypt(encrypted_message)
        self.assertEqual(original_message, decrypted_message)
        
    def test_prime(self):
        # Ensure that is_prime function is working
        self.assertTrue(self.rsa.is_prime(17))
        self.assertFalse(self.rsa.is_prime(20))

    def test_gcd(self):
        # Ensure that gcd function is working
        self.assertEqual(self.rsa.gcd(48, 18), 6)
        self.assertEqual(self.rsa.gcd(101, 103), 1)


if __name__ == '__main__':
    unittest.main()