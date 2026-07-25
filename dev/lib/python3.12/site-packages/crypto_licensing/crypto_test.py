
#
# Tests for the various compatible implementations of ed25519 signatures
# From: https://ed25519.cr.yp.to/python/sign.py
# License: Public Domain
# Modified for compatibility with ed25519ll signature interface, and pytest
#

import binascii
import logging
import os
import random

from .misc import timer

log				= logging.getLogger( "crypto_test" )

ed25519_mods = []
try:
    from . import ed25519
    ed25519.crypto_sign
except Exception as exc:
    log.warning( "Could not load .ed25519 (best available): {exc}".format( exc=exc ))
else:
    ed25519_mods.append( ("ed25519 (best available)", ed25519 ) )

try:  # Python package from Pypi or https://github.com/dholth/ed25519ll
    import ed25519ll
    ed25519ll.crypto_sign
except Exception as exc:
    log.warning( "Could not load ed25519ll from Pypi: {exc}".format( exc=exc ))
else:
    ed25519_mods.append( ("ed25519ll from Pypi", ed25519ll) )

try:  # The Python-only bindings from https://github.com/dholth/ed25519ll
    from . import ed25519ll_pyonly
    ed25519ll_pyonly.crypto_sign
except Exception as exc:
    log.warning( "Could not load .ed25519ll_pyonly: {exc}".format( exc=exc ))
else:
    ed25519_mods.append( ("Python-only from dholth/ed25519ll", ed25519ll_pyonly) )

try:  # https://ed25519.cr.yp.to/python/ed25519.py (w/ Python3 udpates)
    from . import ed25519_djb
    ed25519_djb.crypto_sign
except Exception as exc:
    log.warning( "Could not load .ed25519ll_djb: {exc}".format( exc=exc ))
else:
    ed25519_mods.append( ("Daniel J. Bernstein's Reference", ed25519_djb) )

assert 2 <= len(ed25519_mods) <= 4, \
    "Incorrect number of ed25519 implementations found"


# examples of inputs: see sign.input
# should produce no output: python sign.py < sign.input

# warning: currently 37 seconds/line on a fast machine

# fields on each input line: sk, pk, m, sm
# each field hex
# each field colon-terminated
# sk includes pk at end
# sm includes m at end

try:  # pragma nocover
    unicode
    PY3 = False

    def asints(s):
        """Convert a byte string to a sequence of ints"""
        return ( ord(c) for c in s )

    def asbytes(b):
        """Convert array of integers to byte string"""
        return ''.join(chr(x) for x in b)

    def joinbytes(b):
        """Convert array of bytes to byte string"""
        return ''.join(b)
except NameError:  # pragma nocover
    PY3 = True
    asints = lambda s: s  # noqa: E731
    asbytes = bytes
    joinbytes = bytes


def test_ed25519():
    for description,ed in ed25519_mods:
        log.detail("\n\nTesting: {}\n".format(description))
        with open( os.path.join( os.path.dirname( __file__ ), "crypto_test.input" )) as cases:
            beg = timer()
            cnt = 0
            for line in cases:
                if not line:
                    continue
                x		= line.split( ':' )
                # 32-byte sk; x[0] includes 256-bit (32-byte) secret + public (verifying) keys
                sk		= binascii.unhexlify( x[0] )[:32]
                #print("Using Secret Key:   {!r}".format( binascii.hexlify( sk )))

                #pk = ed.publickey(sk)
                keypair		= ed.crypto_sign_keypair( sk )
                pk		= keypair.vk		# deduce public key (validated below)
                #print("Deduced Public Key: {!r}".format( binascii.hexlify( pk )))

                m		= binascii.unhexlify( x[2] )
                #print("Signing Message:    {!r}".format( binascii.hexlify( m )))

                #s = ed.signature(m,sk,pk)
                signed		= ed.crypto_sign( m, sk+pk )
                s		= signed[:ed.SIGNATUREBYTES]  # obtain signature from front of signed message
                #print("Checking Signature  {!r}".format( binascii.hexlify( s )))

                #if hasattr(ed25519, 'checkvalid'):
                #    ed.checkvalid(s,m,pk)
                ed.crypto_sign_open(s+m, pk)

                forgedsuccess	= 0
                # flip random bit in signature or message
                forgederror	= random.randrange(len(signed))
                forgedsm	= asbytes( c ^ ( 1 << random.randrange(8)
                                                 if i == forgederror
                                                 else 0 )
                                           for i,c in enumerate( asints( signed )))
                try:
                    fs,fm	= forgedsm[:64],forgedsm[64:]
                    #ed.checkvalid(fs,fm,pk)
                    ed.crypto_sign_open( fs+fm, pk )
                    forgedsuccess = 1
                except Exception:
                    pass
                assert not forgedsuccess

                assert x[0] == binascii.hexlify( sk + pk ).decode( 'utf-8' ), \
                  "\nExpected: {!r},\nGot:     {!r}".format( x[0], binascii.hexlify( sk + pk ))
                assert x[1] == binascii.hexlify( pk ).decode( 'utf-8' )
                assert x[3] == binascii.hexlify( s + m ).decode( 'utf-8' )

                cnt	       += 1
                end		= timer()
                dur		= end - beg
                if dur > 5.0:
                    break

            log.normal("\n{dsc}: Completed {cnt} signatures/checks in {dur}s, or {per:.5}/s".format(
                dsc=description, cnt=cnt, dur=dur, per=cnt/dur ))
