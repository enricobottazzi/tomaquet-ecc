class FieldElement:

    def __init__(self, num, prime):
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
        self.secret = secret
        self.point = secret * G

    def private_key(self):
        """Return the private key in hexadecimal format."""
        return '{:x}'.format(self.secret).zfill(64)
    
    def public_key(self):
        """Return the public key in hexadecimal format, including the '04' prefix."""
        return '04' + '{:x}'.format(self.point.x.num).zfill(64) + '{:x}'.format(self.point.y.num).zfill(64)
    
    def public_key_no_prefix(self):
        """Return the public key in hexadecimal format, without the '04' prefix."""
        return '{:x}'.format(self.point.x.num).zfill(64) + '{:x}'.format(self.point.y.num).zfill(64)

    def address(self):
        """Calculate and return the Ethereum address derived from the public key."""
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(bytes.fromhex(self.public_key_no_prefix()))
        return '0x' + keccak_hash.hexdigest()[-40:]
    
import random

class ShamirSecretSharing:
    """Object containing to perform Shamir Secret Sharing.
    Shamir's Secret Sharing is a method for dividing a secret value into multiple shares so that a specified number of shares (the threshold) is required to reconstruct the secret. 
    """

    def __init__(self, t, N, secret):
        """Initialize the ShamirSecretSharing object of t out on N threshold with a given secret, t, N and prime."""
        # assert that t is smaller than N
        assert t < N
        self.secret = secret
        self.t = t
        self.prime = P
        self.N = N
    
    # Pick t-1 random coefficients for a polynomial of degree t-1. f(x) = secret + a1*x + a2*x^2 + ... + at-1*x^t-1
    def generate_coefficients(self):
        """Generate random coefficients (between 1 and prime-1) for a polynomial of degree 'degree'.
        Returns an array coefficient representing the polynomial.
        """
        degree = self.t - 1
        coefficients = [random.randint(1, self.prime - 1) for i in range(degree)] 
        return coefficients 
    
    # Evaluate the polynomial at the given x value. The x is the ID of the share.
    def evaluate_polynomial(self, coefficients, x):
        """Evaluate the polynomial with the given coefficients at the given x value"""
        result = self.secret
        for i, coefficient in enumerate(coefficients):
            result = (result + coefficient * (x ** (i + 1))) % self.prime
        return result
    
    # Each user will be given a share, which is a tuple (x, f(x)) where x is the ID of the share and f(x) is the evaluation of the polynomial at x.
    # Note that ID should be different than 0, as it would reveal the secret. Remember that the secret is the evaluation of the reconstructed polynomial at x = 0.
    # Also no two users should have the same ID.
    def split_secret(self):
        """Split the secret into N shares, of which T are required to reconstruct the secret."""
        coefficients = self.generate_coefficients()
        shares = [(i, self.evaluate_polynomial(coefficients, i)) for i in range(1, self.N + 1)]
        return shares
    
    def generate_pub_commitments(self, shares):
        """Generate the public commitments such that each user can verify that the share is valid."""
        commitments = [(i, share[1] * G) for i, share in shares]
        pub_key = self.secret * G
        # note that these values are public but both the shares and the secret are hidden in the exponentiation 
        return commitments, pub_key

    # Given a polynomial of degree t-1, we can reconstruct the polynomial from t points using Lagrange interpolation. Note that with fewer than t points, the polynomial cann't be reconstructed.
    # The result is the evaluation of the reconstructed polynomial at x = 0
    def lagrange_interpolation(self, x_values, y_values):
        secret = 0
        for i in range(len(x_values)):
            product = 1
            for j in range(len(x_values)):
                if i == j:
                    continue
                product = (product * (0 - x_values[j]) * pow(x_values[i] - x_values[j], self.prime - 2, self.prime)) % self.prime
            secret = (product * y_values[i] + secret) % self.prime
        return secret
    
    def recover_secret(self, shares):
        """Recover the secret from a set of shares"""
        if len(shares) < self.t:
            raise ValueError("Not enough shares to recover the secret")
 
        x_values, y_values = zip(*shares[:self.t])
        secret = self.lagrange_interpolation(x_values, y_values)
        return secret

        
from unittest import TestCase

class ECCTest(TestCase): 

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
        mul_secret = scalar * secret % P
        mul_shares = [(ID, scalar * share % P) for ID, share in shares]
        mul_recovered_secret = sss.recover_secret(mul_shares)
        assert mul_recovered_secret == mul_secret
