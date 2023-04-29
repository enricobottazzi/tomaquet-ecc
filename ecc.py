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
        self.N = N
    
    # Pick t-1 random coefficients for a polynomial of degree t-1. f(x) = secret + a1*x + a2*x^2 + ... + at-1*x^t-1
    def generate_coefficients(self):
        """Generate random coefficients (between 1 and prime-1) for a polynomial of degree 'degree'.
        Returns an array coefficient representing the polynomial.
        """
        degree = self.t - 1
        coefficients = [random.randint(1, 1000) for i in range(degree)] 
        return coefficients 
    
    # Evaluate the polynomial at the given x value. The x is the ID of the share.
    def evaluate_polynomial(self, coefficients, x):
        """Evaluate the polynomial with the given coefficients at the given x value"""
        result = self.secret
        for i, coefficient in enumerate(coefficients):
            result = (result + coefficient * (x ** (i + 1)))
        return result
    
    # Each user will be given a share, which is a tuple (x, f(x)) where x is the ID of the share and f(x) is the evaluation of the polynomial at x.
    # Note that ID should be different than 0, as it would reveal the secret. Remember that the secret is the evaluation of the reconstructed polynomial at x = 0.
    # Also no two users should have the same ID.
    def split_secret(self):
        """Split the secret into N shares, of which T are required to reconstruct the secret."""
        coefficients = self.generate_coefficients()
        shares = [(i, self.evaluate_polynomial(coefficients, i)) for i in range(1, self.N + 1)]
        return shares

    
    def lagrange_interp(self, x_values, y_values, x):
        """Compute the Lagrange interpolation polynomial at x given the x and y values of the nodes"""
        sum = 0
        for i in range(len(x_values)):
            num = 1
            den = 1
            product = 1
            for j in range(len(x_values)):
                if i == j:
                    continue
                num *= (x - x_values[j])
                den *= (x_values[i] - x_values[j])
                product = (num / den)
            sum += product * y_values[i]
        return sum
    
    def lagrange_interp_ecc(self, x_values, y_values, x):
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
                product = (num / den)
            sum += int(product) * y_values[i]
        return sum
    
    def recover_secret(self, shares):
        """Recover the secret from a set of shares"""
        if len(shares) < self.t:
            raise ValueError("Not enough shares to recover the secret")
 
        x_values, y_values = zip(*shares[:self.t])

        if isinstance(y_values[0], S256Point):
            secret = self.lagrange_interp_ecc(x_values, y_values, 0)
        else:
            secret = self.lagrange_interp(x_values, y_values, 0)
        return secret

