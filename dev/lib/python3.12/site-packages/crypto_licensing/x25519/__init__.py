#
# Crypto-licensing -- Cryptographically signed licensing, w/ Cryptocurrency payments
#
# Copyright (c) 2022, Dominion Research & Development Corp.
#
# Crypto-licensing is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.  It is also available under alternative (eg. Commercial)
# licenses, at your option.  See the LICENSE file at the top of the source tree.
#
# It is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#

import hashlib
import random


__all__ = [
    'curve25519', 'curve25519_key', 'ed25519_to_curve25519_key', 'ECDH',
]


##########################################################
#
# Curve25519 reference implementation by Matthew Dempsky, from:
# http://cr.yp.to/highspeed/naclcrypto-20090310.pdf

P = 2 ** 255 - 19
A = 486662
G = 9

def expmod(b, e, m):
   if e == 0: return 1
   t = expmod(b, e // 2, m) ** 2 % m
   if e & 1: t = (t * b) % m
   return t

def inv(x):
    return expmod(x, P - 2, P)

def add(n, m, d):
    (xn, zn) = n
    (xm, zm) = m 
    (xd, zd) = d
    x = 4 * (xm * xn - zm * zn) ** 2 * zd
    z = 4 * (xm * zn - zm * xn) ** 2 * xd
    return (x % P, z % P)

def double(n):
    (xn, zn) = n
    x = (xn ** 2 - zn ** 2) ** 2
    z = 4 * xn * zn * (xn ** 2 + A * xn * zn + zn ** 2)
    return (x % P, z % P)

def curve25519( n: int, base: int = G ) -> tuple[int, int]:
    one = (base,1)
    two = double(one)
    # f(m) evaluates to a tuple
    # containing the mth multiple and the
    # (m+1)th multiple of base.
    def f(m):
        if m == 1: return (one, two)
        (pm, pm1) = f(m // 2)
        if (m & 1):
            return (add(pm, pm1, one), double(pm1))
        return (double(pm), add(pm, pm1, one))
    ((x,z), _) = f(n)
    return (x * inv(z)) % P

def H( m: bytes ) -> bytes:
    return hashlib.sha512(m).digest()

def curve25519_key( n: int = 0 ) -> int:
    """An curve25519 key as an integer"""
    n = n or random.randint(0,P)
    n &= ~7
    n &= ~(128 << 8 * 31)
    n |= 64 << 8 * 31
    return n

def bytes_to_int(b: bytes) -> int:
    """Convert bytes to integer"""
    return sum( byte << (8 * i) for i,byte in enumerate( b ))

def int_to_bytes(n, length=32):
    """Convert integer to fixed-length bytes"""
    return bytes( (n >> (8 * i)) & 0xff for i in range( length ))
        
def ed25519_to_curve25519_key( sk: bytes ) -> int:
    """Converts a Ed25519 signing key as bytes to a curve25519 key as an integer"""
    return curve25519_key( bytes_to_int( H( sk )))

class ECDH:
    """Computes intermediate secrets for sharing, and the final shared_secret when an intermediate
    has been receive the includes all other desired parties' Ed25519 keys, using X25519 keys derived
    from the supplied Ed25519 key.

    """
    def __init__(self, ed25519_keypair, desired: set[ bytes ] ):
        """Initialize with provided Ed25519 private key bytes.  Add our public key to the desired
        set, which is assumed to contain all other parties' Ed25519 public keys participating in the
        X25519 shared secret calculation.

        """

        # Store original Ed25519 private key
        self.ed25519_public = ed25519_keypair.vk
        self.ed25519_private = ed25519_keypair.sk

        # Convert to X25519 private key and compute X25519 public key
        self.x25519_private = ed25519_to_curve25519_key( self.ed25519_private )
        self.x25519_public = curve25519( self.x25519_private )

        desired |= {self.ed25519_public}
        self.desired = desired
        self.shared_secret = None

    def initial_intermediate_value(self):
        """Initial intermediate value is private key . G, which is the X25519 public key."""
        return self.x25519_public, {self.ed25519_public}

    def compute_intermediate_value(self, received_value: int, included: set[ int ]):
        """Compute intermediate value using X25519; add ours unless already included."""
        if self.x25519_public not in included:
            return curve25519(self.x25519_private, received_value), included | {self.ed25519_public}
        return received_value, included
    
    def compute_final_secret(self, received_value: int, included: set[ int ] ):
        """Compute final shared secret, from value with all other desired keys already included."""
        assert self.ed25519_public not in included and self.ed25519_public not in included and included | {self.ed25519_public} == self.desired, \
            f"Intermediate value is missing keys: {', '.join( vk.hex() for vk in (self.desired - included)) or None}" \
            f"; should only have been missing: {self.ed25519_public.hex()}"
        self.shared_secret = curve25519(self.x25519_private, received_value)
        return self.shared_secret, self.desired
