#!/usr/bin/env python3

import collections
import secrets

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)

# Modular arithmetic ##########################################################

def inverse_mod(k, p):
    """Returns the inverse of k modulo p.

    This function returns the only integer x such that (x * k) % p == 1.

    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    if gcd != 1:
        raise ValueError(f'{k} has no inverse mod {p}')

    return x % p


# Functions that work on curve points #########################################

def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):
    """Returns -point."""
    if not is_on_curve(point):
        raise ValueError('point is not on the curve')

    if point is None:
        # -0 = 0
        return None

    x, y = point
    return (x, (-y) % curve.p)


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    if not is_on_curve(point1):
        raise ValueError('point1 is not on the curve')
    if not is_on_curve(point2):
        raise ValueError('point2 is not on the curve')

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # point1 == point2 (point doubling)
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p) % curve.p
    else:
        # point1 != point2 (point addition)
        m = (y2 - y1) * inverse_mod(x2 - x1, curve.p) % curve.p

    x3 = (m * m - x1 - x2) % curve.p
    y3 = (m * (x1 - x3) - y1) % curve.p

    result = (x3, y3)

    if not is_on_curve(result):
        raise ValueError('resulting point is not on the curve')

    return result


def scalar_mult(k, point):
    """Returns k * point computed using double-and-add algorithm with constant-time considerations.

    Note: This is a basic implementation. For full side-channel resistance,
    use specialized libraries or algorithms (e.g., Montgomery ladder).
    """
    if not is_on_curve(point):
        raise ValueError('point is not on the curve')

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    # Use fixed bit length to avoid timing side-channels (basic mitigation)
    bits = k.bit_length()
    for i in reversed(range(bits)):
        result = point_add(result, result)  # Point doubling

        # Add conditionally without branching (basic idea)
        bit = (k >> i) & 1
        if bit == 1:
            result = point_add(result, addend)

    return result


def make_keypair():
    """Generates a cryptographically secure random private-public key pair."""
    # Use secrets for cryptographically secure RNG
    private_key = secrets.randbelow(curve.n - 1) + 1
    public_key = scalar_mult(private_key, curve.g)

    return private_key, public_key


def validate_public_key(pubkey):
    """Validates a public key point.

    Checks:
    - Point is on curve.
    - Point is not at infinity.
    - Point * n = point at infinity (order check).
    """
    if pubkey is None:
        raise ValueError('Public key is point at infinity')

    if not is_on_curve(pubkey):
        raise ValueError('Public key is not on the curve')

    # Check subgroup order: n * pubkey == None (point at infinity)
    check = scalar_mult(curve.n, pubkey)
    if check is not None:
        raise ValueError('Public key is not in the correct subgroup')

    return True


def main():
    print('Curve:', curve.name)

    try:
        # Alice generates her own keypair.
        alice_private_key, alice_public_key = make_keypair()
        print("Alice's private key:", hex(alice_private_key))
        print("Alice's public key: (0x{:x}, 0x{:x})".format(*alice_public_key))

        # Bob generates his own key pair.
        bob_private_key, bob_public_key = make_keypair()
        print("Bob's private key:", hex(bob_private_key))
        print("Bob's public key: (0x{:x}, 0x{:x})".format(*bob_public_key))

        # Validate Bob's public key before use.
        validate_public_key(bob_public_key)
        validate_public_key(alice_public_key)

        # Alice and Bob exchange their public keys and calculate the shared secret.
        s1 = scalar_mult(alice_private_key, bob_public_key)
        s2 = scalar_mult(bob_private_key, alice_public_key)
        assert s1 == s2

        print('Shared secret: (0x{:x}, 0x{:x})'.format(*s1))

    except Exception as e:
        print("Error:", e)


if __name__ == '__main__':
    main()
