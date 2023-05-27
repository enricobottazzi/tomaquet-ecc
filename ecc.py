class FieldElement:

    def __init__(self, num : int, prime : int):
        if num >= prime or num < 0:
            error = 'Num {} not in field range 0 to {}'.format(num, prime-1)
            raise ValueError(error)
        self.num = num
        self.prime = prime
    
    def __repr__(self):
        return 'FieldElement_{}({})'.format(self.prime, self.num)
    
    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime
    
    def __ne__(self, other):
        if other is None:
            return True
        return self.num != other.num or self.prime != other.prime
    
    def __lt__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot compare two numbers in different Fields")
        return self.num < other.num

    def __le__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot compare two numbers in different Fields")
        return self.num <= other.num

    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot add two number in different Fields")
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)

    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot subtract two number in different Fields")
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)
    
    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot multiply two number in different Fields")
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)
    
    def __pow__(self, exponent):
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)
    
    def __truediv__ (self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot divide two number in different Fields")
        other2 = other ** (self.prime - 2)
        return self * other2
    
    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num=num, prime=self.prime)
    
P = 2**256 - 2**32 - 977

class S256Field(FieldElement):

    def __init__(self, num, prime=None):
        super().__init__(num, prime=P)

    def __repr__(self):
        return '{:x}'.format(self.num).zfill(64)

class Point:

    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        if self.x is None and self.y is None:
            return
        if self.y**2 != self.x**3 + a * x + b:
            raise ValueError('({}, {}) is not on the curve'.format(x, y))
        
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y and self.a == other.a and self.b == other.b
    
    def __neq__(self, other):
        return self.x != other.x or self.y != other.y or self.a == other.a or self.b == other.b
    
    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        else:
            return 'Point({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)
        
    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError('Points{}, {} are not on the same curve'.format(self, other))
        
        # Case 1, identity point
        if self.x is None:
            return other
        
        if other.x is None:
            return self
        
        # Case 2, two points are addittive inverse
        if self.x == other.x and self.y != other.y: 
            return self.__class__(None, None, self.a, self.b)
        
        # Case 3, x1 != x2
        if self.x != other.x :
            s = (other.y - self.y) / (other.x - self.x)
            x3 = s**2 - self.x - other.x
            y3 = s*(self.x - x3) - self.y
            return self.__class__(x3, y3, self.a, self.b)
        
        # Case 4, x1 = x2
        if self == other :
            s = (3*self.x**2 + self.a)/(2 * self.y)
            x3 = s**2 - (2 * self.x)
            y3 = s*(self.x - x3) - self.y
            return self.__class__(x3, y3, self.a, self.b)

        # Case 5, x1 = x2 and the tangent line is vertical 
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)
        
    # rmul is need to use the object on the right side of a multiplication operator
    def __rmul__(self, coefficient):
        coef = coefficient
        current = self  # <1>
        result = self.__class__(None, None, self.a, self.b)  # <2>
        while coef:
            if coef & 1:  # <3>
                result += current
            current += current  # <4>
            coef >>= 1  # <5>
        return result
    

A = 0
B = 7
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

class S256Point(Point):
    
    def __init__(self, x, y, a=None, b=None):
        if type(x) == int:
            super().__init__(S256Field(x), S256Field(y), S256Field(A), S256Field(B))
        else: # this is for the case in which we init the point at infinity
            super().__init__(x, y, S256Field(A), S256Field(B))

    def __rmul__(self, coefficient):
        coef = coefficient % N
        return super().__rmul__(coef)
    
    def __repr__(self):
        if self.x is None:
            return 'S256Point(infinity)'
        else:
            return 'S256Point({}, {})'.format(self.x, self.y)


G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
)

from Crypto.Hash import keccak

class KeyPair:
    """Represents a key pair for elliptic curve cryptography."""

    def __init__(self, secret):
        """Initialize the KeyPair with a given secret."""
        # verify that secret is in range [1, n-1]
        if secret < 1 or secret >= N:
            raise ValueError('secret must be an integer in the range [1, n-1]')
        self.secret = secret
        self.point = secret * G

    def private_key(self) -> str:
        """Return the private key in hexadecimal format."""
        return '{:x}'.format(self.secret).zfill(64)
    
    def public_key(self) -> str:
        """Return the public key in hexadecimal format, including the '04' prefix."""
        return '04' + '{:x}'.format(self.point.x.num).zfill(64) + '{:x}'.format(self.point.y.num).zfill(64)
    
    def public_key_no_prefix(self) -> str:
        """Return the public key in hexadecimal format, without the '04' prefix."""
        return '{:x}'.format(self.point.x.num).zfill(64) + '{:x}'.format(self.point.y.num).zfill(64)

    def address(self) -> str:
        """Calculate and return the Ethereum address derived from the public key."""
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(bytes.fromhex(self.public_key_no_prefix()))
        return '0x' + keccak_hash.hexdigest()[-40:]
    
    def generate_shared_secret(self, public_key_other: S256Point) -> S256Point:
        """Generate the shared secret from the public key of the other party."""
        return self.secret * public_key_other
    
import random
from typing import List, Tuple

class ShamirSecretSharing:
    """Object containing to perform Shamir Secret Sharing with a trusted dealer initializing a secret a sharing across N parties.
    Shamir's Secret Sharing is a method for dividing a secret value into multiple shares so that a specified number of shares (the threshold) is required to reconstruct the secret.
    It also contains support to Verifiable Secret Sharing based on Feldman's VSS scheme. 
    """

    def __init__(self, t: int, N: int, secret: FieldElement):
        """Initialize the ShamirSecretSharing object of t out on N threshold with the given secret living in a finite field"""
        assert t <= N
        self.secret = secret
        self.prime = secret.prime
        self.t = t
        self.N = N
    
    @staticmethod
    def generate_coefficients(t, prime) -> List[FieldElement]:
        """Generate t - 1 random coefficients (between 1 and prime-1) for a polynomial of degree 't - 1'.
        f(x) = secret + a1*x + a2*x^2 + ... + at-1*x^t-1
        Returns an array coefficient representing the polynomial.
        """
        degree = t - 1
        coefficients = [FieldElement(random.randint(1, prime-1), prime) for _ in range(degree)]
        return coefficients 
    
    def commit_coefficients(self, coefficients: List[FieldElement], g: FieldElement) -> List[FieldElement]:
        """Generate a homomorphic commitment for the given coefficients from a generator g.
        """
        commitments = []
        commitments.append(g ** self.secret.num)
        for coefficient in coefficients:
            commitments.append(g ** coefficient.num)
        return commitments
    
    def commit_coefficients_ec(self, coefficients: List[FieldElement], g: S256Point) -> List[S256Point]:
        """Generate a homomorphic commitment for the given coefficients from a generator g, where g is a point on the elliptic curve.
        g should be a point that belongs to a prime field p (different from self.prime). The order of g should be self.prime.
        """
        commitments = []
        commitments.append(self.secret.num * g)
        for coefficient in coefficients:
            commitments.append(coefficient.num * g)
        return commitments
    
    def verify_share(self, share: Tuple[FieldElement, FieldElement], commitments: List[FieldElement], g: FieldElement) -> bool:
        """Verify that the user share is a valid share for the given commitment generated by the dealer"""
        i, s_i = share

        left_side = g ** int(s_i.num)
        right_side = commitments[0]
        for j in range(1, len(commitments)):
            right_side *= commitments[j] ** (i.num ** j)
        return left_side == right_side
        
    def verify_share_ec (self, share: Tuple[FieldElement, FieldElement], commitments: List[S256Point], g: S256Point) -> bool:
        """Verify that the user share is a valid share for the given commitment generated by the dealer. 
        Each commitment should be a point on the elliptic curve.
        """
        i, s_i = share
        left_side = s_i.num * g
        right_side = commitments[0]
        for j in range(1, len(commitments)):
            right_side += (i.num ** j) * commitments[j]
        return left_side == right_side

        
    @staticmethod
    def evaluate_polynomial(secret: FieldElement, coefficients: List[FieldElement], x: FieldElement) -> FieldElement:
        """Evaluate the polynomial with the given coefficients at the given x value"""
        result = secret
        for i, coefficient in enumerate(coefficients):
            result += coefficient * (x ** (i + 1))
        return result
    
    def split_secret(self) -> Tuple[List[Tuple[FieldElement, FieldElement]], List[FieldElement]]:
        """Split the secret into N shares, of which T are required to reconstruct the secret. Each share is a tuple (x, f(x)) where x is the ID of the share and f(x) is the evaluation of the polynomial at x.
        The ID should be different than 0, as it would reveal the secret. Remember that the secret is the evaluation of the reconstructed polynomial at x = 0.
        Also no two users should have the same ID.
        """
        coefficients = self.generate_coefficients(self.t, self.prime)
        shares = [(FieldElement(i, self.prime), self.evaluate_polynomial(self.secret, coefficients, FieldElement(i, self.prime))) for i in range(1, self.N + 1)]
        return shares, coefficients
    
    def lagrange_interp(self, x_values: List[FieldElement], y_values: List[FieldElement], x: FieldElement) -> FieldElement:
        """Compute the Lagrange interpolation polynomial evaluated at x given the x and y values of the nodes"""
        sum = FieldElement(0, self.prime)
        for i in range(len(x_values)):
            num, den, product = FieldElement(1, self.prime), FieldElement(1, self.prime), FieldElement(1, self.prime)
            for j in range(len(x_values)):
                if i == j:
                    continue
                num *= (x - x_values[j])
                den *= (x_values[i] - x_values[j])
                product = (num / den)
            sum += product * y_values[i]
        return sum
    
    # As described here => https://crypto.stackexchange.com/questions/70756/does-lagrange-interpolation-work-with-points-in-an-elliptic-curve
    def lagrange_interp_ec(self, x_values: List[int], y_values: List[S256Point], x:int) -> S256Point:
        """Compute the Lagrange interpolation polynomial at x given the x and y values of the nodes where the y values are points on the elliptic curve"""
        sum = S256Point(None, None)
        for i in range(len(x_values)):
            num = 1
            den = 1
            product = 1
            for j in range(len(x_values)):
                if i == j:
                    continue
                num *= (x - x_values[j])
                den *= (x_values[i] - x_values[j])
                product = (num // den)
            sum += int(product) * y_values[i]
        return sum
    
    def recover_secret(self, shares: List[Tuple[FieldElement, FieldElement]]) -> FieldElement:
        """Recover the secret from a set of shares"""
        if len(shares) < self.t:
            raise ValueError("Not enough shares to recover the secret")
 
        x_values = [share[0] for share in shares[:self.t]]
        y_values = [share[1] for share in shares[:self.t]]

        y_values_field_elements = [y for y in y_values if isinstance(y, FieldElement)]
        secret = self.lagrange_interp(x_values, y_values_field_elements, FieldElement(0, self.prime))

        return secret
    
    def recover_secret_ec(self, shares: List[Tuple[FieldElement, S256Point]]) -> S256Point:
        """Recover the secret from a set of shares where the y values are points on the elliptic curve"""
        if len(shares) < self.t:
            raise ValueError("Not enough shares to recover the secret")
 
        x_values = [share[0] for share in shares[:self.t]]
        y_values = [share[1] for share in shares[:self.t]]

        x_values_to_int = [x.num for x in x_values]
        y_values_points = [y for y in y_values if isinstance(y, S256Point)]
        secret = self.lagrange_interp_ec(x_values_to_int, y_values_points, 0)

        return secret
    
class DistributedKeyGeneration:

    def __init__(self, t, N, prime):
        """Initialize the DistributedKeyGeneration object with the given threshold and number of parties and a prime number that represents the finite field in which the secrets lives"""
        self.t = t
        self.N = N
        self.prime = prime
        self.members = []
        # self.public_key = None
    
    def add_member(self, secret : FieldElement):
        """Add a member to the ceremony with the given secret."""
        assert len(self.members) < self.N
        AssertionError("The number of members is already equal to N")
        member = DistributedKeyGenerationMember(self, secret, len(self.members) + 1)
        self.members.append(member)

    def kick_off_ceremony(self):
        """Kick off the ceremony by generating the shares of each member and distributing them to the other members."""
        assert len(self.members) == self.N
        AssertionError("the ceremony is not ready to be kicked off yet, add more members")
        for member in self.members:
            shares = member.split_secret()
            # Now distribute the shares to other members according to the ID (first element of the tuple) of the share
            for share in shares:
                self.members[share[0].num - 1].receive_shares(share)

    #     # # After each member has received the shares, they can compute their private share
    #     # for member in self.members:
    #     #     member.compute_private_share()

    # def compute_public_key (self):
    #     """Compute the public key of the ceremony"""
    #     # assert that the number of members is equal to N
    #     assert len(self.members) == self.N
    #     AssertionError("the ceremony is not ready to compute the public key yet, kick off the ceremony first")
    #     # collect the secret of all members
    #     private_shares = [member.secret for member in self.members]
    #     # compute the public key
    #     self.public_key = sum(private_shares)
    #     return self.public_key
        
class DistributedKeyGenerationMember:


    def __init__(self, setup, secret : FieldElement, index):
        """Initialize the DistributedKeyGenerationMember object with the setup details of the ceremony, the member's secret and the member index"""
        assert secret.prime == setup.prime
        self.t = setup.t 
        self.N = setup.N 
        self.secret = secret
        self.prime = setup.prime
        self.index = index
        self.shares: List[Tuple[FieldElement, FieldElement]] = []

    def split_secret(self) -> List[Tuple[FieldElement, FieldElement]]:
        """Split the secret into N - 1 shares, of which T are required to reconstruct the secret. N - 1 are the number of members in the ceremony that will receive the shares.
        The dealer itself is also a member of the ceremony but does not receive a share (as he already knows the secret).
        Each share is a tuple (x, f(x)) where x is the ID of the share and f(x) is the evaluation of the polynomial at x.
        The ID should be different than 0, as it would reveal the secret. Remember that the secret is the evaluation of the reconstructed polynomial at x = 0.
        Also no two users should have the same ID.
        """
        coefficients = ShamirSecretSharing.generate_coefficients(self.t, self.prime)
        shares = [(FieldElement(i, self.prime), ShamirSecretSharing.evaluate_polynomial(self.secret, coefficients, FieldElement(i, self.prime))) for i in range(1, self.N + 1) if i != self.index]
        return shares
    
    def receive_shares(self, share : Tuple[FieldElement, FieldElement]):
        """Receive shares from another member of the ceremony"""
        self.shares.append(share)
    
    # def compute_private_share(self):
    #     """Compute the private share of the member by summing all received shares"""
    #     # Considering a share inside shares, add together all the second element of the share tuple
    #     self.private_share = sum([share[1] for share in self.shares])

import os
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

class TimeLockPuzzle:

    """
        Class to perform a time lock puzzle based on Rivest, Shamir and Wagner's paper
        based on https://github.com/drummerjolev/time-lock-puzzle
    """

    @staticmethod
    def encrypt(message: bytes, seconds: int, squarings_per_second: int) :

        # hard code safe exponent to use
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        p, q = private_key.private_numbers().p, private_key.private_numbers().q
        n = private_key.public_key().public_numbers().n
        phi_n = (p - 1) * (q - 1)

        # Fernet is an asymmetric encryption protocol using AES
        key = Fernet.generate_key()
        key_int = int.from_bytes(key, sys.byteorder)
        cipher_suite = Fernet(key)

        # encrypt the message using Fernet
        encrypted_message = cipher_suite.encrypt(message)

        # Pick safe, pseudo-random a where 1 < a < n
        a = int.from_bytes(os.urandom(32), sys.byteorder) % n + 1

        # Time lock key encryption
        t = seconds * squarings_per_second
        e = 2**t % phi_n
        b = TimeLockPuzzle.fast_exponentiation(n, a, e)

        encrypted_key = (key_int % n + b) % n
        return p, q, n, a, t, encrypted_key, encrypted_message, key_int

    @staticmethod
    def fast_exponentiation(n: int, g: int, x: int):
        # reverses binary string
        binary = bin(x)[2:][::-1]
        squares = TimeLockPuzzle.successive_squares(g, n, len(binary))
        # keeps positive powers of two
        factors = [tup[1] for tup in zip(binary, squares) if tup[0] == '1']
        acc = 1
        for factor in factors:
            acc = acc * factor % n
        return acc

    @staticmethod
    def successive_squares(base: int, mod: int, length: int):
        table = [base % mod]
        prev = base % mod
        for n in range(1, length):
            squared = prev**2 % mod
            table.append(squared)
            prev = squared
        return table
    
    @staticmethod
    def decrypt(n: int, a: int, t: int, enc_key: int, enc_message: int) -> bytes:
        # Successive squaring to find b
        # We assume this cannot be parallelized
        b = a % n
        for _ in range(t):
            b = b**2 % n
        dec_key = (enc_key - b) % n

        # Retrieve key, decrypt message
        key_bytes = int.to_bytes(dec_key, length=64, byteorder=sys.byteorder)
        cipher_suite = Fernet(key_bytes)
        return cipher_suite.decrypt(enc_message)


import hashlib

class Utils: 

    @staticmethod
    def generate_hash_commitment(x_point : S256Field) -> str:
        """Generate a sha256 hash from a point on the curve"""
        x_point_hex_str = str(x_point)
        byte_data = bytes.fromhex(x_point_hex_str)
        return hashlib.sha256(byte_data).hexdigest()