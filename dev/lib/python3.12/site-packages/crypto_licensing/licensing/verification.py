# -*- coding: utf-8 -*-

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

import codecs
import copy
import datetime
import hashlib
import json
import logging
import os
import struct
import sys
import traceback
import uuid

from functools		import wraps
from enum		import Enum

import dns.name

from . 			import doh
from .defaults		import (
    DISTRIBUTION, LICPATTERN, LICEXTENSION, KEYPATTERN, KEYEXTENSION,
)
from ..misc		import (
    type_str_base, type_num_base, urlencode,
    parse_datetime, parse_seconds, Timestamp, Duration,
    config_open_deduced, ConfigFoundError,
    token_bytes, is_mapping, is_listlike,
)

# Get Ed25519 support. Try a globally installed ed25519ll possibly with a CTypes binding, Otherwise,
# try our local Python-only ed25519ll derivation, or fall back to the very slow D.J.Bernstein Python
# reference implementation
from .. import ed25519

# Optionally, we can provide ChaCha20Poly1305 to support KeypairEncrypted, either from pycryptodome
# or chacha20poly1305.  If not available, ChaCha20Poly1305 is None.
try:
    from Crypto.Cipher import ChaCha20_Poly1305

    class ChaCha20Poly1305:
        """ChaCha20-Poly1305 AEAD cipher using pycryptodome.

        Provides encrypt/decrypt methods that take a nonce parameter, compatible with
        the original chacha20poly1305 module API.
        """
        def __init__(self, key):
            self.key = key

        def encrypt(self, nonce, plaintext):
            """Encrypt plaintext with nonce, returning ciphertext with authentication tag appended."""
            cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(bytes(plaintext))
            return ciphertext + tag

        def decrypt(self, nonce, ciphertext):
            """Decrypt ciphertext (with appended tag) using nonce, verifying authentication."""
            cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
            # ChaCha20-Poly1305 uses a 16-byte authentication tag
            actual_ciphertext = bytes(ciphertext[:-16])
            tag = bytes(ciphertext[-16:])
            return cipher.decrypt_and_verify(actual_ciphertext, tag)
except ImportError:
    try:
        from chacha20poly1305 import ChaCha20Poly1305
    except ImportError:
        ChaCha20Poly1304 = None


__author__                      = "Perry Kundert"
__email__                       = "perry@dominionrnd.com"
__copyright__                   = "Copyright (c) 2022 Dominion Research & Development Corp."
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"


log				= logging.getLogger( "licensing" )


class LicensingError( Exception ):
    pass


class LicenseNotFound( LicensingError ):
    pass


class LicenseIncompatibility( LicensingError ):
    """Something is wrong with the License, or supporting infrastructure."""
    pass


class LicenseDuplicated( LicenseIncompatibility ):
    """A duplicate but incompatible License was found."""
    pass


class LicenseDisjoint( LicenseIncompatibility ):
    """When combining Licenses, we may want to take special action when it is detected that the
    Grants containing Timespans that are disjoint, eg. use the most recent Grant.

    """
    pass


class NotLicensed( LicensingError ):
    pass


class RegistrationError( LicensingError ):
    pass


class NotRegistered( RegistrationError ):
    pass


class DKIMError( LicensingError ):
    pass


def DKIM_pubkey( dkim, v="DKIM1", k="Ed25519" ):
    """Return a validated base-64 decoded DKIM v1 Ed25519 pubkey from the supplied DKIM TXT
    record, or raise a DKIMError."""
    log.debug("Parsing DKIM record: {dkim!r}".format( dkim=dkim ))
    try:
        dkim_valid		= dict(
            v	= lambda v: v.upper(),
            k	= lambda k: k.upper(),
            p	= lambda p: into_bytes( p.strip(), ('base64',) ),
        )
        dkim_kvs		= dict(
            kv.strip().split( '=', 1 )
            for kv in dkim.split( ';' )
        )
        dkim_rec		= dict(
            (k.strip().lower(), dkim_valid.get( k.strip().lower(), lambda x: x )( v.strip() ))
            for k,v in dkim_kvs.items()
        )
        assert set( dkim_valid.keys() ) <= set( dkim_rec.keys() ), \
            "DKIM record missing key {}".format( ', '.join( set( dkim_valid.keys() ) - set( dkim_rec.keys() )))
        assert dkim_rec['v'] == dkim_valid['v']( v ), \
            "Failed to find {!r} record; instead found record of type/version {!r}".format( v, dkim_rec['v'] )
        assert dkim_rec['k'] == dkim_valid['k']( k ), \
            "Failed to find {!r} public key; instead was of type {!r}".format( k, dkim_rec['k'] )
    except Exception as exc:
        raise DKIMError(
            "Failed to locate {k} public key in TXT {v} record {dkim}: {exc}".format(
                k	= k,
                v	= v,
                dkim	= dkim,
                exc	= exc,
            )
        ) from exc
    return dkim_rec['p']


def domainkey_service( product ):
    """Convert a UTF-8 product name into a ASCII DNS Domainkey service name, with
    replacement for some symbols invalid in DNS names (TODO: incomplete).

        >>> domainkey_service( "Something Awesome v1.0" )
        'something-awesome-v1-0'

    Retains None, if supplied.
    """
    author_service		= product
    if author_service:
        author_service		= domainkey_service.idna_encoder( author_service )[0]
        if sys.version_info[0] >= 3:
            author_service	= author_service.decode( 'ASCII' )
        author_service		= author_service.translate( domainkey_service.dns_trans )
        author_service		= author_service.lower()
    return author_service
try:      # noqa: E305
    domainkey_service.dns_trans	= str.maketrans( ' ._/', '----' )
except AttributeError:   # Python2
    import string
    domainkey_service.dns_trans	= string.maketrans( ' ._/', '----' )
domainkey_service.idna_encoder	= codecs.getencoder( 'idna' )
assert "a/b.c_d e".translate( domainkey_service.dns_trans ) == 'a-b-c-d-e'


def into_hex( binary, encoding='ASCII' ):
    return into_text( binary, 'hex', encoding )


def into_b64( binary, encoding='ASCII' ):
    return into_text( binary, 'base64', encoding )


def into_text( binary, decoding='hex', encoding='ASCII' ):
    """Convert binary bytes data to the specified decoding, (by default encoded to ASCII text), across
    most versions of Python 2/3.  If no encoding, resultant decoding symbols remains as un-encoded
    bytes.

    A supplied None remains None.

    """
    if binary is not None:
        if isinstance( binary, bytearray ):
            binary		= bytes( binary )
        assert isinstance( binary, bytes ), \
            "Cannot convert to {}: {!r}".format( decoding, binary )
        binary			= codecs.getencoder( decoding )( binary )[0]
        binary			= binary.replace( b'\n', b'' )  # some decodings contain line-breaks
        if encoding is not None:
            return binary.decode( encoding )
        return binary


def into_bytes( text, decodings=('hex', 'base64'), ignore_invalid=None ):
    """Try to decode base-64 or hex bytes from the provided ASCII text, pass thru binary data as bytes.
    Must work in Python 2, which is non-deterministic; a str may contain bytes or text.

    So, assume ASCII encoding, start with the most strict (least valid symbols) decoding codec
    first.  Then, try as simple bytes.

    """
    if not text:
        return None
    if isinstance( text, bytearray ):
        return bytes( text )
    # First, see if the text looks like hex- or base64-decoded UTF-8-encoded ASCII
    encoding,is_ascii		= 'UTF-8',lambda c: 32 <= c <= 127
    try:
        # Python3 'bytes' doesn't have .encode (so will skip this code), and Python2 non-ASCII
        # binary data will raise an AssertionError.
        text_enc		= text.encode( encoding )
        assert all( is_ascii( c ) for c in bytearray( text_enc )), \
            "Non-ASCII symbols found: {!r}".format( text_enc )
        for c in decodings:
            try:
                binary		= codecs.getdecoder( c )( text_enc )[0]
                #log.debug( "Decoding {} {} bytes from: {!r}".format( len( binary ), c, text_enc ))
                return binary
            except Exception:
                pass
    except Exception:
        pass
    # Finally, check if the text is already bytes (*possibly* bytes in Python2, as str ===
    # bytes; so this cannot be done before the decoding attempts, above)
    if isinstance( text, bytes ):
        #log.debug( "Passthru {} {} bytes from: {!r}".format( len( text ), 'native', text ))
        return text
    if not ignore_invalid:
        raise RuntimeError( "Could not encode as {}, decode as {} or native bytes: {!r}".format(
            encoding, ', '.join( decodings ), text ))


def into_keys( keypair, verify=False ):
    """Return whatever Ed25519 (public, signing) keys are available in the provided unencrypted Keypair
    (something w/ vk and sk attributes) or 32/64-byte key material.  This destructuring ordering is
    consistent with the namedtuple('Keypair', ('vk', 'sk')).

    Supports deserialization of keys from hex or base-64 encode public (32-byte) or secret/signing
    (64-byte) data.  To avoid nondeterminism, we will assume that all Ed25519 key material is encoded in
    base64 (never hex).

    """
    try:
        # May be a Keypair namedtuple
        if verify:
            keypair_verify	= ed25519.crypto_sign_keypair( seed=keypair.sk )
            assert keypair_verify.vk == keypair.vk, \
                "Invalid Ed25519 Keypair; public key: {} doesn't match derived: {}".format(
                    into_b64( keypair.vk ),
                    into_b64( keypair_verify.vk ),
                )
        return keypair.vk, keypair.sk
    except AttributeError:
        pass
    # Not a Keypair.  First, see if it's a serialized public/private key.
    deserialized		= into_bytes( keypair, ('base64',), ignore_invalid=True )
    if deserialized:
        keypair			= deserialized
    # Finally, see if we've recovered a signing or public key
    if isinstance( keypair, bytes ):
        if len( keypair ) == 64:
            # Must be a 64-byte signing key, which also contains the public key.  Can verify.
            if verify:
                keypair_verify	= ed25519.crypto_sign_keypair( seed=keypair[0:32] )
                assert keypair_verify.vk == keypair[32:64], \
                    "Invalid Ed25519 Keypair; public key: {} doesn't match derived: {}".format(
                        into_b64( keypair[32:64] ),
                        into_b64( keypair_verify.vk ),
                )
            return keypair[32:64], keypair[0:64]
        elif len( keypair ) == 32:
            # Can only contain a 32-byte public key.  No way to confirm.
            return keypair[:32], None
    # Unknown key material.
    return None, None


def into_str( maybe ):
    if maybe is not None:
        return str( maybe )


def into_str_UTC( ts, tzinfo=Timestamp.UTC ):
    if ts is not None:
        return ts.render( tzinfo=tzinfo, ms=False, tzdetail=True )


def into_str_LOC( ts ):
    return into_str_UTC( ts, tzinfo=Timestamp.LOC )


def into_JSON( thing, indent=None, default=None, prefix=None ):
    """Convert thing to JSON, optionally prefixing every line."""
    def endict( x ):
        try:
            return dict( x )
        except Exception as exc:
            if default:
                return default( x )
            log.warning("Failed to JSON serialize {!r}: {}".format( x, exc ))
            raise
    # Unfortunately, Python2 json.dumps w/ indent emits trailing whitespace after "," making
    # tests fail.  Make the JSON separators whitespace-free, so the only difference between the
    # signed serialization and an pretty-printed indented serialization is the presence of
    # whitespace.
    separators			= (',', ':')
    text			= json.dumps(
        thing, sort_keys=True, indent=indent, separators=separators, default=endict )
    if prefix and text:
        text			= '\n'.join( prefix + line for line in text.splitlines() )
    return text


def into_boolean( val, truthy=(), falsey=() ):
    """Check if the provided numeric or str val content is truthy or falsey; additional tuples of
    truthy/falsey lowercase values may be provided.  The empty/whitespace string is Falsey."""
    if isinstance( val, (int,float,bool)):
        return bool( val )
    assert isinstance( val, type_str_base )
    if val.strip().lower() in ( 't', 'true', 'y', 'yes' ) + truthy:
        return True
    elif val.strip().lower() in ( 'f', 'false', 'n', 'no', '' ) + falsey:
        return False
    raise ValueError( val )


def into_Timestamp( ts ):
    """Convert to a Timestamp, retaining None.

    """
    if ts is not None:
        if isinstance( ts, type_str_base ):
            ts			= parse_datetime( ts )
        if isinstance( ts, datetime.datetime ):
            ts			= Timestamp( ts )
        assert isinstance( ts, Timestamp )
    return ts


def into_Duration( dur ):
    """Convert to a duration, retaining None"""
    if dur is not None:
        if not isinstance( dur, Duration ):
            dur			= parse_seconds( dur )
            assert isinstance( dur, (int, float) )
            dur			= Duration( dur )
    return dur


def into_Timespan( timespan ):
    """Convert to a Timespan, retaining None.  Expects a Timespan, or a JSON string, object or
    mapping or sequence containing start, length."""
    if timespan is not None:
        if not isinstance( timespan, Timespan ):
            if isinstance( timespan, type_str_base ):
                timespan	= json.loads( timespan )
            if hasattr( timespan, 'start' ) and hasattr( timespan, 'length' ):
                timespan	= dict( start = timespan.start, length = timespan.length )
            if is_mapping( timespan ) and set( ('start', 'length') ) <= set( timespan.keys() ):
                timespan	= dict( start = timespan['start'], length = timespan['length'] )
            # Finally, must be dict or sequence for constructing dict w/ start, length
            timespan		= Timespan( **dict( timespan ))
    return timespan


def maybe_Timespan( timespan ):
    """See if something may be a Timespan; return passed-thru None, or Exception on failure.

    """
    try:
        timespan		= into_Timespan( timespan )
    except Exception as exc:
        timespan		= exc
    return timespan


def into_Grant( grant, _from=None ):
    """Convert to a Grant, retaining None.  An empty Grant won't be included in serialize."""
    if grant is not None:
        if not isinstance( grant, Grant ):
            if isinstance( grant, type_str_base ):
                grant		= json.loads( grant )
            grant		= Grant( _from=_from, **dict( grant ))
    return grant


def into_UUIDv4( machine ):
    if machine is not None:
        if not isinstance( machine, uuid.UUID ):
            machine		= uuid.UUID( machine )
        assert machine.version == 4
    return machine


def machine_UUIDv4( machine_id_path=None ):
    """Identify the machine-id as an RFC 4122 UUID v4. On Linux systems w/ systemd, get from
    /etc/machine-id, as a UUID v4: https://www.man7.org/linux/man-pages/man5/machine-id.5.html.
    On MacOS and Windows, use uuid.getnode(), which derives from host-specific data (eg. MAC
    addresses, serial number, ...).

    This UUID should be reasonably unique across hosts, but is not guaranteed to be.

    TODO: Include root disk UUID?
    """
    if machine_id_path is None:
        machine_id_path		= "/etc/machine-id"
    try:
        with open( machine_id_path, 'r' ) as m_id:
            machine_id		= m_id.read().strip()
    except Exception:
        # Node number is typically a much shorter integer; fill to required UUID length.
        machine_id		= "{:0>32}".format( hex( uuid.getnode())[2:] )
    try:
        machine_id		= into_bytes( machine_id, ('hex', ) )
        assert len( machine_id ) == 16
    except Exception as exc:
        raise RuntimeError( "Invalid Machine ID found: {!r}: {}".format( machine_id, exc )) from exc
    machine_id			= bytearray( machine_id )
    machine_id[6]	       &= 0x0F
    machine_id[6]	       |= 0x40
    machine_id[8]	       &= 0x3F
    machine_id[8]	       |= 0x80
    machine_id			= bytes( machine_id )
    return uuid.UUID( into_hex( machine_id ))


def domainkey( product, domain, service=None, pubkey=None ):
    """Compute and return the DNS path for the given product and domain.  Optionally, returns the
    appropriate DKIM TXT RR record containing the agent's public key (base-64 encoded), as per the
    RFC: https://www.rfc-editor.org/rfc/rfc6376.html

        >>> from .verification import authoring, domainkey
        >>> path, dkim_rr = domainkey( "Some Product", "example.com" )
        >>> path
        'some-product.crypto-licensing._domainkey.example.com.'
        >>> dkim_rr

        # An Awesome, Inc. product
        >>> keypair = authoring( seed=b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' )
        >>> path, dkim_rr = domainkey( "Something Awesome v1.0", "awesome-inc.com", pubkey=keypair )
        >>> path
        'something-awesome-v1-0.crypto-licensing._domainkey.awesome-inc.com.'
        >>> dkim_rr
        'v=DKIM1; k=ed25519; p=25lf4lFp0UHKubu6krqgH58uHs599MsqwFGQ83/MH50='
    """
    if service is None:
        service			= domainkey_service( product )
    if not ( service and domain ):
        raise DKIMError( "A service and domain is required to deduce the DKIM DNS path" )
    domain_name			= dns.name.from_text( domain )
    service_name		= dns.name.Name( [service, DISTRIBUTION, '_domainkey'] )
    path_name			= service_name + domain_name
    path			= path_name.to_text()

    dkim			= None
    if pubkey:
        pubkey,_		= into_keys( pubkey )
        dkim			= '; '.join( "{k}={v}".format(k=k, v=v) for k,v in (
            ('v', 'DKIM1'),
            ('k', 'ed25519'),
            ('p', into_b64( pubkey )),
        ))

    return (path, dkim)


class Serializable( object ):
    """A base-class that provides a deterministic Unicode JSON serialization of every __slots__
    and/or __dict__ attribute, and a consistent dict representation of the same serialized data.
    Access attributes directly to obtain underlying types.

    Hidden attributes starting with _... are never included in serialization; the base Serializable
    has an _path, which identifies a filesystem path where the Serializable has been stored.

    Uses __slots__ in derived classes to identify serialized attributes; traverses the class
    hierarchy's MRO to identify all attributes to serialize.  Output serialization is always in
    attribute-name sorted order.

    If an attribute requires special serialization handling (other than simple conversion to 'str'),
    then include it in the class' serializers dict, eg:

        serializers		= dict( special = into_hex )

    It is expected that derived class' constructors will deserialize when presented with keywords
    representing all keys.

    Optionally indicate where the data was '_from', be it a file Path, or a License, for example.
    The ultimate user of the Serializable data may verify the provenance of the data.

    """

    __slots__			= ('_from', )
    serializers			= {}

    def __init__( self, _from=None ):
        self._from		= _from

    def save( self, f, **kwds ):
        """Writes the serialization to the specified open <file> f, remembering the <file>.path"""
        kwds.setdefault( 'indent', 4 )
        kwds.setdefault( 'encoding', 'UTF-8' )
        ser			= self.serialize( **kwds )
        log.debug( "Saving {} bytes to {}".format( len( ser ), f.name ))
        f.write( ser )
        f.flush()
        self._from		= f.name
        return self._from

    def vars( self ):
        """Returns all key/value pairs defined for the object, either from __slots__ and/or __dict__
        (except hidden _...)."""
        for cls in type( self ).__mro__:
            try:
                vars_seq	= tuple( cls.__slots__ )  # Having a key defined but not instantiated isn't valid.
                if '__dict__' in vars_seq:
                    vars_seq   += tuple( self.__dict__ )
            except AttributeError:
                try:
                    vars_seq	= self.__dict__
                except AttributeError as exc:
                    vars_seq	= ()
                    if cls is not object:  # Only the base object() is allowed to have neither __slots__ nor __dict__
                        log.error( "vars for base {cls!r} instance {self!r} has neither __slots__ nor __dict__: {exc}".format(
                            cls=cls, self=self,
                            exc=''.join( traceback.format_exception( *sys.exc_info() )) if log.isEnabledFor( logging.TRACE ) else exc ))
                        raise
            for key in vars_seq:
                if key[0] == '_':  # ignore hidden _... vars, eg. _from.
                    continue
                yield key, getattr( self, key )

    def __copy__( self ):
        """Create a new object by copying an existing object, taking __slots__ into account.

        """
        result			= self.__class__.__new__( self.__class__ )

        for key,val in self.vars():
            setattr( result, key, copy.copy( val ))

        return result

    def keys( self, every=False ):
        """Yields the Serializable object's relevant (not absent/None/.empty()) keys.

        For many uses (eg. conversion to dict), the default behaviour of ignoring keys with values
        of None (or a Truthy .empty() method) is appropriate.  However, if you want all keys
        regardless of content, specify every=True.

        """
        def suppressed( key, val ):
            if self.serializer( key ) is False:		# Explicitly suppressed from serialization
                return True
            if val is None:				# Values of None are suppressed
                return True
            empty		= getattr( val, 'empty', None )
            if empty is not None and hasattr( empty, '__call__' ) and empty():
                return True
            return False

        for key,val in self.vars():
            if every or not suppressed( key, val ):
                yield key

    def __contains__( self, key ):
        """Checks if key is in the Serializable container (__slots__ or __dict__), without ignoring
        "suppressed" (.empty()/None/no-serializer) keys.  In other words -- may include keys that
        are suppressed in the standard serialization.

        """
        if key in self.keys( every=True ):
            return True
        return False

    def serializer( self, key ):
        """Finds any custom serialization formatter specified for the given attribute, defaults to None.

        """
        for cls in type( self ).__mro__:
            try:
                return cls.serializers[key]
            except (AttributeError, KeyError):
                pass

    def __getitem__( self, key ):
        """Returns the serialization of the requested key, passing thru values without a serializer.
        We don't use our own __contains__, because this may be overridden in derive Serialized
        classes to represent the semantics of that object type (eg. a Timespan, ...).

        """
        if key in self.keys( every=True ):
            try:
                serialize	= self.serializer( key )  # (no Exceptions)
                value		= getattr( self, key )    # IndexError
                if serialize:
                    return serialize( value )             # conversion failure Exceptions
                return value
            except Exception as exc:
                log.debug( "Failed to convert {class_name}.{key} with {serialize!r}: {exc}".format(
                    class_name = self.__class__.__name__, key=key, serialize=serialize, exc=exc ))
                raise
        raise IndexError( "{} not found in keys: {}".format( key, ', '.join( self.keys( every=True ))))

    def get( self, key, default=None ):
        try:
            return self.__getitem__( key )
        except (KeyError, IndexError):
            return default

    def __setitem__( self, key, value ):
        if key in set( dir( self )) - set( self.keys( every=True )):
            raise IndexError( "{} is not a valid {} keys".format( key, self.__class__.__name__ ))  # Hidden _... or predefined
        setattr( self, key, value )

    set				= __setitem__

    def setdefault( self, key, default ):
        if key not in self:
            self[key]           = default
        return self[key]

    def __str__( self ):
        return self.JSON()

    def __repr__( self ):
        return '<' + self.__class__.__name__ + (
            " (from {})".format( repr( self._from ))
            if self._from or log.isEnabledFor( logging.DEBUG )
            else ""
        ) + '>'

    def JSON( self, indent=4, default=None, prefix=None ):
        """Return the default readable JSON representation of the present object."""
        return into_JSON( self, indent=indent, default=default, prefix=prefix )

    def serialize( self, indent=None, encoding='UTF-8', default=None, prefix=None ):
        """Return a binary 'bytes' serialization of the present object.  Serialize to JSON, assuming
        any complex sub-objects (eg. License, LicenseSigned) have a sensible dict representation.

        The default serialization (ie. with indent=None, encoding to UTF-8) will be the one used to
        create the digest.

        If there are objects to be serialized that require special handling, they must not have a
        'dict' interface (be convertible to a dict), and then a default may be supplied to serialize
        them (eg. str).

        An optional prefix string may be prepended to each line.

        """
        stream			= self.JSON( indent=indent, default=default, prefix=prefix )
        if encoding:
            stream		= stream.encode( encoding )
        return stream

    def sign( self, sigkey, pubkey=None ):
        """Sign our default serialization, and (optionally) confirm that the supplied public key
        (which will be used to check the signature) is correct, by re-deriving the public key.

        """
        vk, sk			= into_keys( sigkey )
        assert sk, \
            "Invalid ed25519 signing key provided"
        if pubkey:
            # Re-derive and confirm supplied public key matches supplied signing key
            keypair		= ed25519.crypto_sign_keypair( sk[:32] )
            assert keypair.vk == pubkey, \
                "Mismatched ed25519 signing vs. public keys {!r} vs. {!r}".format(
                    into_b64( keypair.vk ), into_b64( pubkey ))
        signed			= ed25519.crypto_sign( self.serialize(), sk )
        signature		= signed[:64]
        return signature

    def verify( self, pubkey, signature ):
        """Check that the supplied signature matches this serialized payload, and return the verified
        payload bytes.

        """
        pubkey, _		= into_keys( pubkey )
        signature		= into_bytes( signature, ('base64',) )
        assert pubkey and signature, \
            "Missing required {}".format(
                ', '.join( () if pubkey else ('public key',)
                           + () if signature else ('signature',) ))
        serialization		= self.serialize()
        try:
            verified		= ed25519.crypto_sign_open( signature + serialization, pubkey )
            return verified
        except Exception:
            log.debug( f"License serialization w/ signature {into_b64( signature )} not signed by pubkey: {into_b64( pubkey )}: {serialization}" )
            raise

    def digest( self, encoding=None, decoding=None ):
        """The SHA-256 hash of the serialization, as 32 bytes.  Optionally, encode w/ a named codec,
        eg.  "hex" or "base64".  Often, these will require a subsequent .decode( 'ASCII' ) to become
        a non-binary str.

        """
        binary			= hashlib.sha256( self.serialize() ).digest()
        if encoding is not None:
            binary		= codecs.getencoder( encoding )( binary )[0].replace(b'\n', b'')
            if decoding is not None:
                return binary.decode( decoding )
        return binary

    def __eq__( self, other ):
        """Serializable things should produce the same digest if equal.  There may be simpler or
        better equality tests, but this is the semantic for Serializable things or their hashes.

        For reasoning, see:
            https://stackoverflow.com/questions/390250/elegant-ways-to-support-equivalence-equality-in-python-classes

        """
        local_hash		= self.digest()
        if isinstance( other, Serializable ):
            other_hash		= other.digest()
        elif isinstance( other, bytes ) and len( other ) == len( local_hash ):
            other_hash		= other
        else:
            return NotImplemented
        return local_hash == other_hash

    def __ne__( self, other ):
        """Unnecessary under Python3, but needed for Python 2"""
        eq			= self.__eq__( other )
        if eq is NotImplemented:
            return NotImplemented
        return not eq

    def __hash__( self ):
        """Returns a 64-bit signed integer representing the first 8 bytes of the digest"""
        return struct.Struct('<q').unpack( self.digest()[:8] )[0]

    def hexdigest( self ):
        """The SHA-256 hash of the serialization, as a 256-bit (32 byte, 64 character) hex string."""
        return self.digest( 'hex', 'ASCII' )

    def b64digest( self ):
        return self.digest( 'base64', 'ASCII' )


class IssueRequest( Serializable ):
    __slots__			= (
        'author', 'author_pubkey', 'product',
        'client', 'client_pubkey', 'machine'
    )
    serializers			= dict(
        author_pubkey	= into_b64,
        client_pubkey	= into_b64,
        machine		= into_str,
    )

    def __init__( self, author=None, author_pubkey=None, product=None,
                  client=None, client_pubkey=None, machine=None, **kwds ):
        self.author		= into_str( author )
        self.author_pubkey, _	= into_keys( author_pubkey )
        self.product		= into_str( product )
        self.client		= into_str( client )
        self.client_pubkey, _	= into_keys( client_pubkey )
        self.machine		= into_UUIDv4( machine )
        super( IssueRequest, self ).__init__( **kwds )

    def query( self, sigkey ):
        """Issue query is sorted-key order"""
        qd			= dict( self )
        qd['signature']		= into_b64( self.sign( sigkey=sigkey ))
        return urlencode( sorted( qd.items() ))


def overlap_intersect( start, length, other ):
    """Accepts a start/length, and a Timespan (something w/ start and length), and compute the
    intersecting start/length, and its begin and (if known) ended timestamps.

        start,length,begun,ended = overlap_intersect( start, length, other )

    A start/Timespan w/ None for length is assumed to endure from its start with no time limit.

    """
    other			= into_Timespan( other )
    # Detect the situation where there is no computable overlap, and start, length is defined by one
    # pair or the other.
    if start is None:
        # This license has no defined start time (it is perpetual); other license determines
        assert length is None, "Cannot specify a length without a start timestamp"
        if other.start is None:
            # Neither specifies start at a defined time
            assert other.length is None, "Cannot specify a length without a start timestamp"
            return None,None,None,None
        if other.length is None:
            return other.start,other.length,other.start,None
        return other.start,other.length,other.start,other.start + other.length
    elif other.start is None:
        assert other.length is None, "Cannot specify a length without a start timestamp"
        if length is None:
            return start,length,start,None
        return start,length,start,start + length

    # Both have defined start times; begun defines beginning of potential overlap If the computed
    # ended time is <= begun, then there is no (zero) overlap!
    begun 		= max( start, other.start )
    ended		= None
    if length is None and other.length is None:
        # But neither have duration
        return start,length,begun,None

    # At least one length; ended is computable, as well as the overlap start/length
    if other.length is None:
        ended		= start + length
    elif length is None:
        ended		= other.start + other.length
    else:
        ended		= min( start + length, other.start + other.length )
    start		= begun
    length		= Duration( 0 if ended <= begun else ended - begun )
    return start,length,begun,ended


class Agent( Serializable ):
    """An agent, which may use (via .pubkey) or issue (via .keypair) Licenses.

    Even if an authoring keypair is provided, it is never serialized (so as to not leak private key
    material).

    """
    __slots__			= (
        'name', 'domain', 'product', 'service', 'pubkey', 'keypair',  # order significant (see below)
    )
    serializers			= dict(
        pubkey		= into_b64,
        keypair		= False,		# Supress from default serialization
    )

    def __repr__( self ):
        return (
            '<'
            + self.__class__.__name__
            + '('
            + self.serialize( encoding=None )
            + ')>'
        )

    def __eq__( self, rhs ):
        """Let's define a bit more forgiving definition of equality, since we are going to be
        comparing client-entered data against corporate data.  Agents are considered equal if the
        have the same public key.  Barring that, if the name, domain and product are the same, we'll
        consider them equal.

        """
        if not isinstance( rhs, Agent ):
            return False
        if self.pubkey or rhs.pubkey:
            # Deterministic match: Any Agent has a pubkey; they must match
            return self.pubkey == rhs.pubkey
        # Statistical match: at least 2 / 4 identifying features match
        return sum(
            getattr( self, thing ) == getattr( rhs, thing )
            for thing in self.__slots__[:4]
            if getattr( self, thing ) is not None  # at least one side non-None
        ) >= 2

    def __ne__( self, rhs ):
        return not self.__eq__( rhs )

    def __init__(
        self,
        name,
        domain		= None,			# Needed for DKIM if no pubkey provided, or confirm is True
        product		= None,
        service		= None,			# Normally, derived from product name
        keypair		= None,			# ..or from a full ed25519.Keypair/KeypairPlaintext provided
        pubkey		= None,			# Normally, obtained from domain's DKIM1 TXT RR
        confirm		= None,			# Lookup and/or confirm the public key via DKIM1?
        **kwds
    ):
        """Obtain the Agent's public key; either given through the API, or obtained from their
        domain's DKIM entry.

        The default 'confirm' behavior is to locate the Agent public key via domain/service if not
        provided.  If True, we will always check to confirm it.  If False, we will never check, nor
        even try to obtain the public key if missing.

        If a full authoring Keypair is provided, we'll store it and obtain (and confirm, if desired)
        the pubkey from that.

        """
        assert ( pubkey or keypair ) or ( domain and ( product or service )), \
            "Either a pubkey/keypair or a domain + service/product must be provided"
        self.name		= name
        self.domain		= domain
        self.product		= product
        self.service		= service  # Likely deduced, w/ domainkey_service( product )
        self.keypair		= keypair and KeypairPlaintext( keypair )
        self.pubkey,_		= into_keys( pubkey or self.keypair )
        super( Agent, self ).__init__( **kwds )

        # Now pubkey_query has all the details it requires to do a DKIM lookup, if necessary
        if confirm is not False:
            self.pubkey_confirm( confirm=confirm )

    @property
    def servicekey( self ):
        """Return the service, deducing from the Product (retains None, if both are None).  This is
        used to look up License data for Licenses authored by this Agent, so either .service or
        .product must be supplied, if Licenses are to be authored.

        """
        if self.service is None:
            return domainkey_service( self.product )
        return self.service

    @property
    def domainkey( self ):
        """Return the DKIM domain name, and the computed DKIM TXT record (if pubkey known)"""
        return domainkey( self.product, self.domain, service=self.service, pubkey=self.pubkey )

    def pubkey_confirm( self, confirm=None ):
        """Obtain (and/or confirm, if desired) public key via DKIM1"""
        if self.pubkey is None or confirm is True:
            avkey 		= self.pubkey_query()
            if self.pubkey is None:
                self.pubkey	= avkey
            if avkey != self.pubkey:
                raise LicenseIncompatibility(
                    "Agent for {auth}'s {prod!r}: public key from DKIM {found} != {claim}".format(
                        auth	= self.name,
                        prod	= self.product,
                        found	= into_b64( avkey ),
                        claim	= into_b64( self.pubkey ),
                    ))

    def pubkey_query( self ):
        """Obtain the agent's public key.  This was either provided at License construction time, or
        can be obtained from a DNS TXT "DKIM" record.

        Query the DKIM record for an author public key.  May be split into multiple strings:

        Use DNS-over-HTTPS, to ensure we receive a valid TXT record for the specified domain:

            >>> from . import doh
            >>> results = doh.query( 'dominion.crypto-licensing._domainkey.dominionrnd.com', 'TXT' )
            >>> assert results[0]['data'] == 'v=DKIM1; k=ed25519; p=5cijeUNWyR1mvbIJpqNmUJ6V4Od7vPEgVWOEjxiim8w='

        We used to do this, but it was insecure, because anyone could implement their own
        DNS resolver yielding any TXT they wished:

            r = dns.resolver.query('default._domainkey.justicewall.com', 'TXT')
            for i in r:
            ...  i.to_text()
            ...
            '"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9...Btx" "aPXTN/aI+cvS8...4KHoQqhS7IwIDAQAB;"'

        Fortunately, the Python AST for string literals handles this quite nicely:

            ast.literal_eval('"abc" "123"')
            'abc123'

        """
        dkim_path, _dkim_rr	= self.domainkey
        log.debug("Querying {domain} service {service} for DKIM public key: {dkim_path}".format(
            domain=self.domain, service=self.servicekey, dkim_path=dkim_path
        ))
        records			= doh.query( dkim_path, 'TXT' )
        assert len( records ) == 1, \
            "Failed to obtain a single TXT record from {dkim_path}".format( dkim_path=dkim_path )
        dkim			= records[0]["data"]
        pubkey			= DKIM_pubkey( dkim )
        log.info( "Found Ed25519 pubkey via DKIM from {dkim_path}: {pubkey}".format(
            dkim_path	= dkim_path,
            pubkey	= into_b64( pubkey )
        ))
        return pubkey


class Timespan( Serializable ):
    """A time period, w/ a start and optionally a length.  An "empty" (0 length) Timespan may result
    from a failed intersection.

    """
    __slots__			= (
        'start', 'length'
    )
    serializers			= dict(
        start		= into_str_UTC,
        length		= into_str,
    )

    @property
    def end( self ):
        return None if self.start is None or self.length is None else self.start + self.length

    def empty( self ):
        return self.length == 0  # Note: None != 0, in both Python 2 and 3

    def __nonzero__( self ):
        return not self.empty()
    __bool__			= __nonzero__  # Python3

    def __repr__( self ):
        return (
            '<'
            + (
                (
                    repr( self.start )
                    + ' - '
                    + repr( self.end )
                    + ' = '
                ) if log.isEnabledFor( logging.DEBUG ) else ''
            )
            + self.__class__.__name__
            + '(' + repr(str( self.start ))
            + ',' + repr(str( self.length ))
            + ')>'
        )

    def __init__(
        self,
        start		= None,
        length		= None,
        **kwds
    ):
        """A License usually has a timespan of a start timestamp and (optional) duration length.
        These cannot exceed the timespan of any License dependencies.  First, get any supplied start
        time as a timestamp, and any duration length as a number of seconds.

        A Timespan with a None start is assumed to be perpetual, and with a None length is assumed
        to be perpetual from that start time.

        """
        self.start		= into_Timestamp( start )
        self.length		= into_Duration( length )
        super( Timespan, self ).__init__( **kwds )

        assert self.length is None or self.start is not None, \
            "Invalid Timespan; must have a start time if length specified"

    def __contains__( self, other ):
        """True iff we fully encompasses the other Timespan.

        If 'other in self' is False, we know (at least) that self.start is not None, because the
        full perpetual (no start or length) Timespan contains any other Timespan.

        If 'other in self' and 'self in other' are both False, we know that both .start are
        non-None, and at least one .length is non-None -- so at least self.end or other.end is
        finite.

        """
        return self.start is None or (
            other.start is not None and other.start >= self.start and (
                self.end is None or (
                    other.end is not None and other.end <= self.end
                )
            )
        )

    def intersection( self, *others ):
        start			= self.start
        length			= self.length
        for other in others:
            start,length,begun,ended = overlap_intersect( start, length, other )
            if length is not None and length.total_seconds() == 0:
                # We've reached a point where there is no overlap with some other Timespan, and our
                # intersection is empty.  Return an empty Timespan (start time irrelevant, but
                # cannot be None)
                return Timespan( start, 0 )
        return Timespan( start, length )

    def adjacent( self, other ):
        if other in self:
            return True
        if self in other:
            return True
        assert self.end is not None or other.end is not None, \
            "Either {} or {} should have been non-perpetual".format( repr( self ), repr( other ))
        if self.length is not None and other.start <= self.end <= other.end:
            return True
        if other.length is not None and self.start <= other.end <= self.end:
            return True
        return False

    def union( self, *others ):
        """Successively check for intersection or adjacency, expanding if possible, until there is
        no intersection or adjacency with any remaining Timespan.  Each time we integrate another
        Timespan, we have to recompute its union with all other Timespans, because they now may be
        adjacent.

        """
        for i,other in enumerate( others ):
            if self.adjacent( other ):
                break
        else:
            # We completed without incorporating at detecting one intersecting/adjacent Timespan.  Done.
            log.debug( "union: {} doesn't adjoin {}".format( repr( self ), ', '.join( map( repr, others ))))
            return self
        # We broke out of the loop, after detecting an overlap/intersection with the i'th Timespan;
        # compute the (now larger) union with the remaining others.
        if len( others ) > 1:
            return ( self + other ).union( *( others[:i] + others[i+1:] ))
        return ( self + other )

    def __add__( self, other ):
        """Add a Timespan, or something with a .start/.length or ['start'],['length'].  May result in
        no change if there is no intersection/adjacency -- you can't "add" a disjoint Timespan!"""
        other			= into_Timespan( other )
        if other in self:
            return self
        if self in other:
            return other
        if self.length is not None and self.start <= other.start <= self.end:
            if other.length is None:
                return Timespan( self.start, None )
            else:
                return Timespan( self.start, other.end - self.start )
        elif other.length is not None and other.start <= self.start <= other.end:
            if self.length is None:
                return Timespan( other.start, None )
            else:
                return Timespan( other.start, self.end - other.start )
        else:
            log.debug( "{} + {} doesn't overlap".format( repr( self ), repr( other )))
        # Not overlapping/adjacent; no change
        return self


class Grant( Serializable ):
    """The key/value capabilities granted by something like a License.  The first level names
    (typically something related to the product name) usually specify a dict of key/value pairs, and
    all must be serializable to JSON.  The values may themselves be Grants.  Specifically, the first
    layer Grant is usually comprised of a couple of "global" values (eg. { "timespan": <Timespan>,
    "machine": <UUID> }, and the remaining values will themselves be Grants, eg. w/ a ._from
    indicating which LicenseSigned dependency they were initially from.

    The Granted option names cannot be trusted; any License may carry a Grant of any option name
    whatsoever.  So, the License itself must be validated as being issued by an expected author,
    before its Grant of options can be trusted.  When a sub-License modifies a Grant (ie. issues a
    subset of the granted capability to a licensee), it modifies the Grant, but retains the original
    source License in _from.  So, when the grants() are finally delivered to the caller, they can
    confirm that the top-level key (eg. "cpppo-test" = Grant( "Hz" = 100 ),_from=<LicenseSigned>)
    actual came from the expected author (ie. has the correct pubkey).

    Also, some License options granted in sub-Licenses may "accumulate", while others only accrue
    to the direct client of the License.  Each License author must decide this; only their code
    that validates their License knows the semantics of their Grant options.

    We'll use a __dict__ instead of __slots__ to hold the unknown option key/dict pairs.

    Two Licenses containing grants from same Grant group (say, 'cpppo-test') "combine" if they are
    loaded in parallel, but "refine" if they are dependencies.  For example, if I load two Licenses
    with Grant.cpppo-test["Hz"] of 1,000 and 200 respectively, I end up with a total Grant of 1,200
    "Hz".  However, if a License contains a Grant of 200, and has a License in its dependencies that
    grants() 1,000, I receive only the 200 (and it must be <= the dependencies' value).

    The Grant &= Grant operator "refines", the Grant |= Grant "combines".

    Note that combining Timespans between two licenses along with other features may grant
    unexpected results -- extending the time duration of the features granted in one license, into
    to the time duration of another license carrying different features.

    """
    def __init__( self, *args, **kwds ):
        _from			= kwds.pop( '_from', None )  # Python 2 doesn't support mixing keyword args and **kwds
        if args:
            assert len( args ) == 1 and isinstance( args[0], (type_str_base, dict) ) and not kwds, \
                "Grant option cannot be defined w/ multiple or non-str args both args: {args!r} and/or kwds: {kwds!r}".format(
                    args=args, kwds=kwds )
            if isinstance( args[0], type_str_base ):
                kwds		= json.loads( args[0] )
            else:
                kwds		= args[0]
        option			= dict( kwds )
        # Ensure that options only has first-level keys w/ /dicts (actually, the Mapping API),
        # unless _from is provided (indicating this is a sub-Grant).  In other words, an "anonymous"
        # Grant can only contain Grants/dicts.  Anything that specifies a ._from may contain
        # arbitrary key/value pairs; otherwise, .
        if _from is None:
            assert all(
                is_mapping( v ) or isinstance( v, Grant )
                for v in option.values()
            ), "Found non-dict/Grant option(s): {keys}".format(
                keys		= ', '.join(
                    k for k,v in option.items()
                    if not ( is_mapping( v ) or isinstance( v, Grant ))
                )
            )
        self.__dict__.update( option )
        super( Grant, self ).__init__( _from=_from )
        log.debug( "Created {!r}: {}".format( self, self ))

    def empty( self ):
        """Detects if empty, and avoid serialization if so.  This allows someone to accidentally
        define an empty Grant, without changing the signature vs. the same License w/ no Grant.
        Must ignore "hidden" _...  and (in turn) empty keys, so use .keys() So, a Grant containing
        empty Grants and/or keys with value None will be empty.

        """
        for _ in self.keys():
            return False
        return True

    def grants( self, once=None ):
        return self

    def items( self ):
        return self.__dict__.items()

    class Merging( Enum ):
        REFINING	= 0
        COMBINED	= 1

    def merge( self, group, key, value, style=Merging.REFINING ):
        """When a Grant group's key (eg. grant['cpppo-test']['Hz']) is presented with a new value in
        some sub-License, this must be consistent with (a strict subset of) any existing Grant from
        any License dependencies: you can't provide a sub-Licensee with "more" than your License
        dependencies provide.

        For example, if ['cpppo-test']['Hz'] is granted a 10 Hz I/O (poll rate) by Dominion Research
        & Development Corp., the value assigned to the current Grant['cpppo-test']['Hz'] must be <=
        10.

        Typically, a Grant group key w/ no value (ie. None) indicates no constraint, so we don't
        allow replacing a Grant constraint w/ None, in either REFINING or COMBINED; it will simply pass
        the existing limit through -- we won't allow a restrictive Grant to be replaced by an
        undefined/unrestricted Grant.

        Grants completely disjoint in time cannot be COMBINEd; any Timespans presented must overlap,
        and the *intersection* is kept.  This is because we are combining the capabilities of both
        sub-Licenses: the combined capability is only valid for the intersection of the License
        dependencies' combination!

        In other words, if you have 100 "Hz" from Jan 1 to July 31, and 200 "Hz" from May 1 to Dec
        31, if you chose to combine those sub-Licenses, the combined Grant will be 100 "Hz" from May
        1 to July 31.

        Returns the {REFINING,COMBINED}d value, confirmed to be a subset (or accumulation) of any
        current value; None indicates there is no restriction, and should only be possible if both
        the current and value are None.

        """
        current			= self.get( group, {} ).get( key )
        result			= value
        # If a non-None current for this Grant group's value is already present, do some basic
        # validation.  Trying to replace a non-None (restrictive) current w/ a value of None
        # (unrestricted) is not allowed.
        if isinstance( current, type_num_base ):
            if style is Grant.Merging.REFINING:
                if value is None or value > current:
                    raise LicenseIncompatibility( "License Grant.{group}[{key!r}] of {value!r} exceeds limit: {current!r}".format(
                        group=group, key=key, value=value, current=current ))
            else:
                result		= current + ( value or 0 )
        elif isinstance( current, type_str_base ):
            current_set		= set( current if is_listlike( current ) else (current,) )
            if style is Grant.Merging.REFINING:
                if value is None or value not in current_set:
                    raise LicenseIncompatibility( "License Grant.{group}[{key!r}] of {value!r} doesn't match: {current!r}".format(
                        group=group, key=key, value=value, current=current_set ))
            else:
                if value is not None:
                    current_set.add( value )
                result		= list( current_set )
                if len( result ) == 1:
                    result,	= result
        elif isinstance( current, Timespan ) or isinstance( maybe_Timespan( value ), Timespan ):
            # Either the current or new value is a Timespan.  Let's see if the value is within the
            # provided current Timespan.  If two Grants are disjoint, raises exception
            current		= into_Timespan( current )      # May be None (no restriction)
            result = value	= into_Timespan( value )        # ''
            if style is Grant.Merging.REFINING:
                if ( Timespan() if value is None else value ) not in ( Timespan() if current is None else current ):
                    raise LicenseIncompatibility( "License Grant.{group}[{key!r}] of {value!r} is not within: {current!r}".format(
                        group=group, key=key, value=value, current=current ))
            else:
                intersect	= ( Timespan() if current is None else current ).intersection( Timespan() if value is None else value )
                if not intersect:
                    raise LicenseDisjoint( "License Grant.{group}[{key!r}] of {value!r} do not overlap: {current!r}".format(
                        group=group, key=key, value=value, current=current ))
                result		= intersect
        elif current is not None:
            raise LicenseIncompatibility( "License Grant.{group}[{key!r}] of {value!r} not comparable to: {current!r}".format(
                group=group, key=key, value=value, current=current ))

        # The provided value is a valid refinement (ie. subset) or combination of the current value
        log.info( "{style} Grant {group}'s {key} = {current!r} w/ {value!r} ==> {result!r}".format(
            style=style, group=group, key=key, current=current, value=value, result=result ))
        return result

    def _integrate( self, rhs_grant, style ):
        """Grant &/| Grant REFINING or COMBINED the current Grant, w/ the keys/Grants carried by the
        given grant -- which must typically specify a "subset" (&=) or "union" (|=) of the
        capabilities granted by the current Grant.  If each granted capability (key) is a valid
        refinement, then the current Grant assumes the refined value.

        An existing Grant with its heritage will be retained; the refinement applied

        If a completely new group is being added -- a previously unknown Grant -- then, we will also
        copy the source Grant._from heritage.  In the case of Grants from Licenses, this will be the
        authoring Agent from the License that originally authored the Grant.

        If the provided Grant is under an already known group key in the present Grant, and they are
        both Grants -- then we will ensure that the _from is identical.

        """
        assert isinstance( rhs_grant, Grant ), \
            "Expected to {style} against a Grant, not a {name}".format( style=style, name=rhs_grant.__class__.__name__ )
        for group,rhs_group_grant in rhs_grant.items():
            assert isinstance( rhs_group_grant, Grant ), \
                "Expected to {style} another Grant group {group}, not a {name}{extra}".format(
                    style=style, group=group, name=rhs_group_grant.__class__.__name__,
                    extra="; {} in {}".format( repr( rhs_group_grant ), repr( rhs_grant )) if log.isEnabledFor( logging.DEBUG ) else "" )
            if group in self.keys( every=True ):
                # An existing group key; only if no heritage is known do we assume the authorship of
                # the supplied refining Grant.
                lhs_group_grant	= self[group]
                if lhs_group_grant._from != rhs_group_grant._from:
                    if style is Grant.Merging.COMBINED:
                        # When License.grants() are COMBINED, the Grants must come from the same author
                        raise LicenseIncompatibility( "License Grant group {group}'s author {lhs_auth!r} incompatible with {rhs_auth!r}".format(
                            group=group, lhs_auth=lhs_group_grant._from, rhs_auth=rhs_group_grant._from ))
                    if lhs_group_grant._from is None:
                        log.info( "Inherits {} {!r}: {} author to that of {!r}: {}".format(
                            group, lhs_group_grant, lhs_group_grant, rhs_group_grant, rhs_group_grant ))
                        lhs_group_grant._from = rhs_group_grant._from
            else:
                # A completely new group key; assume the heritage of the supplied Grant
                lhs_group_grant = self[group] = Grant( _from=rhs_group_grant._from )
                log.info( "Creating {} {!r}: {} author w/ that of {!r}: {}".format(
                    group, lhs_group_grant, lhs_group_grant, rhs_group_grant, rhs_group_grant ))
            for key,value in rhs_group_grant.items():
                update		= self.merge( group=group, key=key, value=value, style=style )
                if update is not None:
                    lhs_group_grant[key] = update

    def __iand__( self, rhs_grant ):
        self._integrate( rhs_grant, style=Grant.Merging.REFINING )
        log.debug( "After Grant &= {}:\n{}".format(
            ', '.join( "{} = {} = {}".format( key, repr( rhs ), rhs_grant[key] ) for key,rhs in rhs_grant.items() ),
            '\n'.join( "{} = {} = {}".format( key, repr( lhs ), self[key] ) for key,lhs in self.items() )))
        return self

    def __ior__( self, rhs_grant ):
        self._integrate( rhs_grant, style=Grant.Merging.COMBINED )
        log.debug( "After Grant |= {}:\n{}".format(
            ', '.join( "{} = {} = {}".format( key, repr( rhs ), rhs_grant[key] ) for key,rhs in rhs_grant.items() ),
            '\n'.join( "{} = {} = {}".format( key, repr( lhs ), self[key] ) for key,lhs in self.items() )))
        return self

    def __le__( self, rhs_grant ):
        """Detect if this Grant is a subset of another.  If it has additional keys, or has a Grant
        that couldn't be satisfied by our Grant, then we are considered "not a subset".

        We can only compare Grants consisting of group:Grant pairs using this operator; A Grant may
        contain either group: Grant pairs, or key: value pairs.  Ensure Grant's _from are compatible
        and values are a subset, then compare each group:Grant's key:value pairs for compatibilityf

        For key/value pairs, use merge( ..., REFINING), which does not alter the Grant, but ensures
        that the target Grant's key/value are a superset of the given Grant's key/value; in effect,
        that this Grant is a subset of the target Grant.

        """
        try:
            if miss_groups     := set( self.keys( every=True )) - set( rhs_grant.keys( every=True )):
                raise LicenseDisjoint( "Grant group(s) {} do not overlap".format( ', '.join( miss_groups )))
            if self._from != rhs_grant._from:
                raise LicenseIncompatibility( "License Grant {lhs_auth!r} incompatible with {rhs_auth!r}".format(
                    lhs_auth=self._from, rhs_auth=rhs_grant._from ))
            for group,lhs_group_grant in self.items():
                rhs_group_grant	= rhs_grant[group]
                assert isinstance( lhs_group_grant, Grant ) and isinstance( rhs_group_grant, Grant ), \
                    "Only {group} Grants may be compared for subset, not {lhs_type} vs {rhs_type}".format(
                        group=group, lhs_type=type(lhs_group_grant), rhs_type=type(rhs_grant) )
                if miss_keys   := set( lhs_group_grant.keys( every=True )) - set( rhs_group_grant.keys( every=True )):
                    raise LicenseDisjoint( "Grant {} keys {} do not overlap".format(
                        group, ', '.join( miss_keys )))
                for key,value in lhs_group_grant.items():
                    # Verify RHS value is a subset of LHS value, or raise LicenseIncompatibility
                    subset	= rhs_grant.merge( group=group, key=key, value=value, style=Grant.Merging.REFINING )
                    log.info( "Grant group {}'s key {} subset {} <= {} ==> {}".format(
                              group, key, value, lhs_group_grant[key], subset ))
        except LicenseIncompatibility as exc:
            log.info( "Grant {} is not a subset of {}: {}".format( self, rhs_grant, exc ))
            return False
        log.debug( "Grant {} is a subset of {}".format( self, rhs_grant ))
        return True


class License( Serializable ):
    """Represents the details of a Licence from an author to a client (could be any client, if no
    client or client.pubkey provided).  Cannot be constructed unless the supplied License details
    are valid with respect to the License dependencies it 'has', and grants capabilities 'for'
    certain machine, period or other "keys".


    {
        "author": {
           "domain":"dominionrnd.com",
           "name":"Dominion Research & Development Corp.",
           "product":"Cpppo Test",
           "pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk="
        }
        "client":{
            "name":"Awesome, Inc.",
            "pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ="
        },
        "dependencies":[
            {
                "license":{...},
                "signature":"9Dba....kLCg=="
            },
            ...
        ],
        "timespan":{
            "start": "2021-01-01 00:00:00+00:00"
            "length": "1y"
        },
        "machine":"00010203-0405-4607-8809-0a0b0c0d0e0f",
        "grant":{
            "cpppo-test":{
                "Hz":1000,
            }
        }
    }

    Verifying a License
    -------------------

    A signed license is a claim by an Author that the License is valid; it is up to a recipient to
    check that the License also actually satisfies the constraints of any License dependencies.  A
    nefarious Author could create a License and properly sign it -- but not satisfy the License
    constraints.  License.verify(confirm=True) will do this, as well as (optionally) retrieve and
    verify from DNS the public keys of the (claimed) signed License dependencies.

    Checking your License
    ---------------------

    Each module that uses crypto_licensing.licensing checks that the final product's License or its
    parents contains valid license(s) for itself, somewhere within the License dependencies tree.

    All start times are expressed in the UTC timezone; if we used the local timezone (as computed
    using get_localzone, wrapped to respect any TZ environment variable, and made available as
    timestamp.LOC), then serializations (and hence signatures and signature tests) would be
    inconsistent.

    Licenses for products are signed by the author using their signing key.  The corresponding
    public key is expected to be found in a DKIM entry; eg. for Dominion's Cpppo (test) product:

        cpppo-test.crypto-licensing._domainkey.dominionrnd.com. 300 IN \
            TXT "v=DKIM1; k=ed25519; p=qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk="

    TODO:

    License Grant Validation
    ------------------------

    The core purpose of crypto-licensing is to verify the integrity of License grants/constraints at
    License issuance time, and (later) at License utilization time(s).  Only the License Author can
    know the full semantics of their unique License grants/constraints, and the outstanding valid
    Licenses that have been issued.  These must therefore be expressed in a way that is useful to
    the Python crypto_licensing.licensing server (Python), and to the crypto_licensing runtime
    client (also Python).

    Sub-Licensing
    -------------

    When an Author grants a licensee permission to (in turn) author Licenses, there is no way to
    ensure that they actually abide by the constraints granted them.  If they are given permission
    to author (say) 10 machine-IDs, nothing prevents them from signing and issuing 100 instead.
    Even if you issue the Licenses directly with a crypto_licensing.license server under your
    control, nothing prevents the client from running 100 machines with the same machine-ID.

    Any software-based licensing scheme suffers from the same risks; once software is deployed,
    there are no limits on the modifications that a recipient can perform on the software.  TPM
    modules can be used to ensure a full stack of software (from boot loader through the OS) is not
    tampered with, but this Licensing is beyond the scope of that controlled stack.

    Therefore, the purpose of checking Licenses is not to *prevent* unlicensed usage by malevolent
    non-clients -- it is to *enable* licensed usage by your friendly clients.  They need your help,
    via License verification, to do this.

    They want to pay you for your services, and crypto-licensing helps you to help them do that.

    Grant Validation
    ----------------

    Licenses may carry optional grants/constraints, with functions to validate their values.  These
    may be expressed in terms of all Licenses issued by the Author.  During normal License.verify of
    an installed License, nothing about the pool of issued Licenses is known, so no additional
    verification can be done -- it is assumed that the License Author was satisfied when the License
    was issued (signed).

    However, when an Author is issuing a License and has access to the full pool of issued Licenses,
    all presently issued values of the grant/constraint are known.

    If a lambda is provided it will be passed a proposed value as its second default parameter, with
    the first parameter defaulting to None, or a list containing all present instances of the
    constraint across all currently valid Licenses.  For example, if only 10 machine licenses are
    available, return the provided machine if the number is not exhausted:

        machine = "00010203-0405-4607-8809-0a0b0c0d0e0f"
        machine__verifier = lambda m, ms=None: \
            ( str( m ) \
              if len( str( m ).split( '-' )) == 5 \
              else ValueError( f"{m} doesn't look like a UUID" ) \
            if ms is None or len( ms ) < 10 \
            else ValueError( "No more machine licenses presently available" )

    Alternatively, a None or numeric limit could be distributed across all issued licenses:

        targets = 3
        targets__verifier = lambda n, ns=None: \
            None if n is None else int( n ) \
              if n is None or ns is None or int( n ) + sum( map( int, filter( None, ns ))) <= 100 \
              else ValueError( f"{n} exceeds {100-sum(map(int,filter(None,ns)))} targets available" )

    If an Exception is returned, it will be raised.  Otherwise, the result of the lambda will be
    used as the License' value for the constraint.

    """

    __slots__			= (
        'author',
        'client',
        'dependencies',
        'machine',
        'timespan',
        'grant',
    )
    serializers			= dict(
        start		= into_str_UTC,
        length		= into_str,
        machine		= into_str,
    )

    @property
    def license( self ):
        """For situations where the user might hold either a License or a LicenseSigned..."""
        return self

    @property
    def start( self ):
        return self.timespan and self.timespan.start

    @property
    def length( self ):
        return self.timespan and self.timespan.length

    def grants( self, once=None ):
        """Compute and return the full License Grant accumulated by this licence and all of its
        License dependencies.  This is what rolls up a tree of License dependencies into a top-level
        set of Grant groups/keys.  Higher-level License Grants must comply with any Grants by
        License dependencies.

        The "first mention" of a certain Grant group deepest in the dependencies tree specifies that
        group's Grant._from to the License.author's Ed25519 pubkey.  This should be validated by
        whomever checks the Grant's groups' keys.  If _from is absent, then the group was added
        manually to a Grant.

        Any particular unique License's Grant may only be used once; We'll use the License.digest()
        to determine this.

        """
        if once is None:
            once		= set()
        res_grants		= Grant()

        # If this is a duplicate (this exact License has already been seen somewhere
        # else in the heirarchy), we don't want to duplicate the Grants, so make it empty.
        digest		= self.digest()
        if digest not in once:
            once.add( digest )
        else:
            log.info( "License for {auth}'s {prod!r} already granted (duplicate from {_from})".format(
                auth	= self.author.name,
                prod	= self.author.product,
                _from	= self._from,
            ))
            return res_grants

        # Each of our License dependencies carry Grants that we can accumulate; for example, if we
        # have two distinct Licenses for a product that each grant us a certain amount of a
        # capability, we can combine them.
        for lic in self.dependencies or []:
            res_grants	      |= lic.grants( once=once )  # will be Grant() if lic.digest() already in seen

        # Now we've accumulated the full suite of merged known Grants from sub-Licenses; this may
        # include Grants w/ the same group name as our License's service name (either by accident,
        # or by someone trying to forge a Grant of our product's features).  So, any new ones
        # (unique to our self.grant) must be designated as Grant._from this authoring Agent.  The
        # convention is to use our author Agent.service (or domainkey_service( Agent.product ) as
        # our Grant group name; if not defined, provide an empty Grant w/ ._from = author
        our_grant		= Grant() if self.grant is None else self.grant
        service			= self.author.service or domainkey_service( self.author.product )
        if service and service not in our_grant.keys( every=True ):
            our_grant[service]	= {}
            log.info( "License for {auth}'s {prod!r} defaulting to empty Grant group {service!r}".format(
                auth	= self.author.name,
                prod	= self.author.product,
                service	= service
            ))
        # Now, convert all remaining self-originated Grant group dicts to Grants w/ ._from = author
        for orig in our_grant.keys( every=True ):
            if isinstance( our_grant[orig], Grant ):
                our_grant[orig]._from	= self.author
            else:
                our_grant[orig]	= Grant( _from = self.author, **( our_grant[orig] or {} ))
        log.info( "License for {auth}'s {prod!r} originating Grant groups {originating}".format(
            auth	= self.author.name,
            prod	= self.author.product,
            originating	= ', '.join(
                "{}: {}".format( o, repr( our_grant[o] )) if log.isEnabledFor( logging.DEBUG ) else o
                for o in our_grant.keys( every=True )
            ),
        ))

        # Finally, this License is allowed to sub-License a portion of the Grants accumulated.
        res_grants	       &= our_grant
        return res_grants

    def __init__(
        self,
        author,
        client		= None,
        dependencies	= None,				# Any Licenses this License depends on
        machine		= None,
        timespan	= None,
        grant		= None,				# The timespan, machine and options granted
        machine_id_path	= None,
        confirm		= None,				# Validate License' author.pubkey from DNS
        **kwds
    ):
        # Who is authoring this License, and who (if anyone in particular) is this License intended
        # for?  If no client is specified, any agent Keypair may issue a sub-license this license.
        assert author, \
            "Issuing a Licence without an author is incorrect"
        if isinstance( author, type_str_base ):
            author		= json.loads( author )  # Deserialize Agent, if necessary
        self.author		= Agent( **author )

        if isinstance( client, type_str_base ):
            client		= json.loads( client )  # Deserialize Agent, if necessary
        self.client		= Agent( **client ) if client else None

        self.machine		= into_UUIDv4( machine )  # None or machine UUIDv4 (raw or serialized)

        try:
            self.timespan	= into_Timespan( timespan )
        except Exception as exc:
            raise LicenseIncompatibility( "License timespan invalid: {exc}".format( exc=exc )) from exc

        # Remember our License's Grant of capabilities.  Any License may grant anything it wishes;
        # however, the Licensee's software keeps track of the "heritage" of each Grant; if it didn't
        # come from the expected authoring Agent, it probably fail to successfully deliver the
        # claimed capabilities (it's up to the Licensee's software to validate).  First-level Grants
        # may contain only { "key": Grant( {...} ), } Any top-level key's originating from this
        # Grant will be designated as Grant._from with *this* authoring Agent.
        try:
            self.grant		= into_Grant( grant )
        except Exception as exc:
            raise LicenseIncompatibility( "License grant invalid: {exc}".format( exc=exc )) from exc

        # Reconstitute LicenseSigned provenance from any dicts provided
        self.dependencies	= None
        if dependencies is not None:
            self.dependencies	= list(
                prov
                if isinstance( prov, LicenseSigned )
                else LicenseSigned( confirm=confirm, machine_id_path=machine_id_path, **dict( prov ))
                for prov in dependencies
            )
        super( License, self ).__init__( **kwds )

        # Only allow the construction of valid Licenses
        self.verify( confirm=confirm, machine_id_path=machine_id_path )

    def overlap( self, *others ):
        """Compute the overlapping start/length that is within the bounds of this and other license(s).
        If they do not overlap, raises a LicenseIncompatibility Exception.

        Any other thing that doesn't have a .product, .author defaults to *this* License's
        attributes (eg. we're applying further Timespan constraints to this License).

        """
        start			= self.start
        length			= self.length
        for other in others:
            # If we determine a 0-length overlap, we have failed.
            start,length,begun,ended = overlap_intersect( start, length, other )
            if length is not None and length.total_seconds() == 0:
                # Overlap was computable, and was zero
                raise LicenseIncompatibility(
                    "License for {author}'s {product!r} from {start} for {length} incompatible with others".format(
                        author	= getattr( getattr( other, 'author', None ), 'name', None )  or self.author.name,
                        product	= getattr( getattr( other, 'author', None ), 'product', None ) or self.author.product,
                        start	= into_str_LOC( other.start ),
                        length	= other.length,
                    ))
        return start, length

    def verify(
        self,
        author_pubkey	= None,
        signature	= None,
        confirm		= None,
        machine_id_path	= None,
        dependencies	= None,  # Defaults to not include this LicenseSigned in returned constraints['dependencies']
        **constraints
    ):
        """Verify that the License is valid:

            - Has properly signed License dependencies
              - Each public key can be confirmed, if desired
            - Complies with the bounds of any License dependencies
              - A sub-License must be issued while all License dependencies are active
            - Allows any constraints supplied.
              - Any .grant complies with License dependency Grants

        If it does, the constraints are returned, including this LicenseSigned added to the
        constraints['dependencies'].  If no additional constraints are supplied, this will simply
        return the empty constraints dict on success.  The returned constraints would be usable in
        constructing a new License (assuming at least the necessary author, author_domain and
        product were defined).

        """
        if author_pubkey:
            author_pubkey,_	= into_keys( author_pubkey )
            assert author_pubkey, "Unrecognized author_pubkey provided"

        # TODO: This identifies and allows *only* Licenses whose primary author matches the provided
        # pubkey.  However -- a License from a different author, which *carries* dependency licenses
        # (ie. has sub-licensed some License that carries Grants matching the desired author!) is
        # also something we want to allow!  In other words -- if I'm looking for a Grant from a
        # certain author, I might be interested in *any* License that is available that carries such
        # a Grant.  So, if some License from some author is A) sub-licenseable by me, and B) carries
        # a Grant from the desired author, than verify it!
        if author_pubkey and author_pubkey != self.author.pubkey:
            raise LicenseIncompatibility(
                "License for {auth}'s {prod!r} public key mismatch: {lhs} != {rhs}{stack}".format(
                    auth	= self.author.name,
                    prod	= self.author.product,
                    lhs		= into_b64( author_pubkey ),
                    rhs		= str( self.author ) if log.isEnabledFor( logging.TRACE ) else into_b64( self.author.pubkey ),
                    stack	= ''.join( traceback.format_stack() if log.isEnabledFor( logging.DEBUG ) else [] ),
                ))
        # Verify that the License's stated public key matches the one in the domain's DKIM.  Default
        # to True when confirm is None.  If the License author declined to provide a .domain and a
        # .product/.service to deduce a .servicekey (eg. for a License issued locally to an end-user
        # Agent ID), we don't validate the pubkey.  If you are a License author w/ a DKIM and want
        # validation, ensure you provide a .domain and a .product/.service when you author Licenses!
        if ( confirm or confirm is None ) and self.author.domain and self.author.servicekey:
            avkey	 	= self.author.pubkey_query()
            if avkey != self.author.pubkey:
                raise LicenseIncompatibility(
                    "License for {auth}'s {prod!r}: author key from DKIM {found} != {claim}".format(
                        auth	= self.author.name,
                        prod	= self.author.product,
                        found	= into_b64( avkey ),
                        claim	= into_b64( self.author.pubkey ),
                    ))
        # Verify that the License signature was indeed produced by the signing key corresponding to
        # the provided public key
        if signature:
            try:
                super( License, self ).verify( pubkey=self.author.pubkey, signature=signature )
            except Exception as exc:
                log.info( f"License not signed by Author: {self}" )
                raise LicenseIncompatibility(
                    "License for {auth}'s {prod!r}: signature mismatch: {sig!r}; {exc}".format(
                        auth	= self.author.name,
                        prod	= self.author.product,
                        sig	= into_b64( signature ),
                        exc	= exc,
                    )) from exc

        # Verify any License dependencies are valid; signed w/ DKIM specified key, License OK.  When
        # verifying License dependencies, we don't supply the constraints and decline inclusion of
        # dependencies, because we're not interested in sub-Licensing these Licenses, only verifying
        # them.  If a License dependency specifies a client, make certain it matches the issued
        # License's author; otherwise, any author is allowed.

        # This is where a client's self-signed License is validated; unless the License.dependencies
        # Licenses are "anonymous" (allow *any* client) or are specifically issued to the Keypair
        # used to sign (they allow *this* client), the License isn't valid.

        # TODO: Issuing a License that allows "anonymous" clients is somewhat dangerous, as the
        # entire package of License capabilities can be acquired by anyone.  When we validate
        # capabilities requested against those granted by a License, should we "stop", when we
        # encounter any anonymous License dependencies -- any capabilities they grant cannot be
        # assumed to be "for" the licensee; the Agent authoring the present license?  I don't think
        # so -- if some author issues "anonymous" License Grants for some capabilities, they must
        # intend that these are safe/approved for any sub-licensee to acquire...  If they want to
        # protect valuable Grants from widespread usage, then they would only issue them in Licenses
        # with specific client restrictions.
        for prov_dct in self.dependencies or []:
            prov		= LicenseSigned( confirm=confirm, machine_id_path=machine_id_path, **prov_dct )
            try:
                prov.verify( confirm=confirm, machine_id_path=machine_id_path )
                assert prov.license.client is None or prov.license.client.pubkey is None or prov.license.client.pubkey == self.author.pubkey, \
                    "sub-License client public key {client_pubkey} doesn't match Licence author's public key {author_pubkey}".format(
                        client_pubkey	= into_b64( prov.license.client.pubkey ),
                        author_pubkey	= into_b64( self.author.pubkey ),
                    )
            except Exception as exc:
                raise LicenseIncompatibility(
                    "License for {auth}'s {prod!r}; sub-License for {dep_auth}'s {dep_prod!r} invalid: {exc}".format(
                        auth		= self.author.name,
                        prod		= self.author.product,
                        dep_auth	= prov.license.author.name,
                        dep_prod	= prov.license.author.product,
                        exc		= exc,
                    )) from exc

        # Enforce all constraints, returning a dict suitable for creating a specialized License, if
        # a signature was provided; if not, we cannot produce a specialized sub-License, and must
        # fail.

        # First, scan the constraints to see if any are callable
        if constraints:
            log.info( "Enforcing constraints: {}".format( constraints ))
        # Verify all sub-license start/length durations comply with this License' duration.
        # Remember, these start/length specify the validity period of the License to be
        # sub-licensed, not the execution time of the installation!
        try:
            # Collect any things with .start/.length; all sub-Licenses dependencies, and a Timespan
            # representing any supplied start/length constraints in order to validate their
            # consistency with the sub-License start/lengths.
            others		= list( ls.license for ls in ( self.dependencies or [] ))
            # Find any non-empty timespan w/ non-empty start/length in constraints
            timespan_cons	= constraints.get( 'timespan' )
            if timespan_cons:
                if isinstance( timespan_cons, type_str_base ):
                    timespan_cons = json.loads( timespan_cons )
            # At this point, only iff timespan_cons is Truthy, has there been a timespan constraint specified
            if timespan_cons:
                others.append( Timespan( **timespan_cons ))
            start, length	= self.overlap( *others )
        except LicenseIncompatibility as exc:
            raise LicenseIncompatibility(
                "License for {auth}'s {prod!r}; sub-{exc}".format(
                    auth	= self.author.name,
                    prod	= self.author.product,
                    exc		= exc,
                )) from exc
        else:
            # Finally, if a timespan constraint w/ either start or length was supplied, update it
            # with the computed timespan of start/length constraints overlapped with all
            # dependencies.  For example, we might get only a timespan.length constraint; this
            # would use produce the earliest overlapping timespan.start of all dependency Licenses,
            # with a duration of the supplied length.
            if timespan_cons:  # Iff a timespan constraint was specified...
                constraints['timespan'] = Timespan( start, length )

        # TODO: Implement License expiration date, to allow a software deployment to time out and
        # refuse to run after a License as expired, forcing the software owner to obtain a new
        # License with a future expiration.  Typically, for example, Cpppo installations are
        # perpetual; if installed with a valid License, they will continue to work without
        # expiration.  However, other software authors may want to sell software that requires
        # issuance of new Licenses.

        # Default 'machine' constraints to the local machine UUID.  If no constraints and
        # self.machine is None, we don't need to do anything, because the License is good for any
        # machine.  Use machine=True to force constraints to include the current machine UUID.
        machine			= None
        if machine_id_path is not False and ( self.machine or constraints.get( 'machine' )):
            # Either License or constraints specify a machine (so we have to verify), and the
            # machine_id_path directive doesn't indicate to *not* check the machine ID (eg. when
            # issuing the license from a different machine)
            machine_uuid	= machine_UUIDv4( machine_id_path=machine_id_path )
            if self.machine not in (None, True) and self.machine != machine_uuid:
                raise LicenseIncompatibility(
                    "License for {auth}'s {prod!r} specifies Machine ID {required}; found {detected}{via}".format(
                        auth	= self.author.name,
                        prod	= self.author.product,
                        required= self.machine,
                        detected= machine_uuid,
                        via	= " (via {})".format( machine_id_path ) if machine_id_path else "",
                    ))
            machine_cons	= constraints.get( 'machine' )
            if machine_cons not in (None, True) and machine_cons != machine_uuid:
                raise LicenseIncompatibility(
                    "Constraints on {auth}'s {prod!r} specifies Machine ID {required}; found {detected}{via}".format(
                        auth	= self.author.name,
                        prod	= self.author.product,
                        required= machine_cons,
                        detected= machine_uuid,
                        via	= " (via {})".format( machine_id_path ) if machine_id_path else "",
                    ))
            # Finally, unless the supplied 'machine' constraint was explicitly None (indicating that
            # the caller desires a machine-agnostic sub-License), default to constrain the License to
            # this machine.
            if machine_cons is not None:
                constraints['machine'] = machine_uuid

        # Check that our grants are valid
        grants			= self.grants()

        log.info( "License for {auth}'s {prod!r} is valid from {start} for {length} on machine {machine}".format(
            auth	= self.author.name,
            prod	= self.author.product,
            start	= into_str_LOC( start ),
            length	= length,
            machine	= into_str( machine ) or into_str( constraints.get( 'machine' )) or '(any)' )
            + ", grants: {grants}".format( grants=grants.serialize( encoding=None )) if log.isEnabledFor( logging.DEBUG ) else ""
        )

        # Finally, now that the License, all License.dependencies and any supplied constraints have
        # been verified, augment the constraints with this LicenseSigned as one of the dependencies.
        if dependencies:
            assert signature is not None, \
                "Attempt to issue a sub-License of an un-signed License"
            assert isinstance( dependencies, (list,bool) ), \
                "Provided dependencies must be False/True, or a list of LicenseSigned"
            constraints['dependencies'] = [] if dependencies is True else dependencies
            constraints['dependencies'].append( dict(
                LicenseSigned( license=self, signature=signature, confirm=confirm, machine_id_path=machine_id_path )
            ))

        return constraints

    def __le__( self, rhs ):
        """Incompatible dependencies and grants is always considered "not a subset" of another
        License.  However, if a License Grants at least the same capabilities, from dependencies
        that are found to be compatible, then it is considered "a subset".

        """
        grants		= self.grants()
        grants_rhs	= rhs.grants()
        if grants <= grants_rhs:
            # Grants compatible; all License dependencies must be represented in the other License' dependencies.
            return all(
                any(
                    lic <= rhs_lic
                    for rhs_lic in rhs.dependendencies or []
                )
                for lic in self.dependencies or []
            )
        log.warning( "This License grants: {} doesn't match rhs: {}".format( grants, grants_rhs ))
        return False


class LicenseSigned( Serializable ):
    """A License and its Ed25519 Signature provenance.  Only a LicenseSigned (and confirmation of
    the author's public key) proves that a License was actually issued by the purported author.  It
    is expected that authors will only sign a valid License.

    The public key of the author must be confirmed through independent means.  One typical means is
    by checking publication on the author's domain (the default behaviour w/ confirm=None), eg.:

        awesome-tool.crypto-licensing._domainkey.awesome-inc.com 86400 IN TXT \
            "v=DKIM1; k=ed25519; p=PW847sz.../M+/GZc="


    Authoring a License
    -------------------

    A software issuer (or end-user, in the case of machine-specific or numerically limited Licenses)
    must create new Licenses.

        >>> from crypto_licensing import authoring, issue, verify, License, Agent

    First, create a Keypair, including both signing (private, .sk) and verifying (public, .vk) keys:

        >>> signing_keypair = authoring( seed=b'our secret 32-byte seed material' )

    Then, create a License, identifying the author by their public key, and the product.  This
    example is a perpetual license (no start/length), for any machine.

        >>> license = License(				\
                author	= Agent(			 \
                    name	= "Awesome, Inc.",	  \
                    domain	= "awesome-inc.com",	   \
                    product	= "Awesome Tool",	    \
                    pubkey	= signing_keypair.vk,	     \
                ),					      \
                confirm=False,				       \
        )

    Finally, issue the LicenseSigned containing the License and its Ed25519 Signature provenance:

        >>> provenance = issue( license, signing_keypair, confirm=False )
        >>> provenance_ser = provenance.serialize( indent=4 )
        >>> print( provenance_ser.decode( 'UTF-8' ) )
        {
            "license":{
                "author":{
                    "domain":"awesome-inc.com",
                    "name":"Awesome, Inc.",
                    "product":"Awesome Tool",
                    "pubkey":"PW847szICqnQBzbdr5TAoGO26RwGxG95e3Vd/M+/GZc="
                }
            },
            "signature":"38gIOyPtcLO0EdElKQDpvUvMkm4xuVR9Ksm2P0ZaFhqo7X3p7dLZidxrNEHyvU8OrSrQA7wmpb+9xweWye8FBg=="
        }


    De/Serializing Licenses
    -----------------------

    Licenses are typically stored in files, in the configuration directory path of the application.

        import json
        # Locate, open, read
        #with config_open( "application.crypto-licencing", 'r' ) as provenance_file:
        #    provenance_ser	= provenance_file.read()
        >>> provenance_dict = json.loads( provenance_ser )

    Or use the crypto_licensing.load() API to get them all into a dict, with
    the license file basename deduced from your __package__ or __file__ name:

        import crypto_licensing as cl
        licenses		= dict( cl.load(
            filename	= __file__,
            confirm	= False, # don't check signing key validity via DKIM
        ))

    Validating Licenses
    -------------------

    Somewhere in the product's code, the License is loaded and validated.

        >>> provenance_load = LicenseSigned( confirm=False, **provenance_dict )
        >>> print( provenance_load )
        {
            "license":{
                "author":{
                    "domain":"awesome-inc.com",
                    "name":"Awesome, Inc.",
                    "product":"Awesome Tool",
                    "pubkey":"PW847szICqnQBzbdr5TAoGO26RwGxG95e3Vd/M+/GZc="
                }
            },
            "signature":"38gIOyPtcLO0EdElKQDpvUvMkm4xuVR9Ksm2P0ZaFhqo7X3p7dLZidxrNEHyvU8OrSrQA7wmpb+9xweWye8FBg=="
        }
        >>> print( json.dumps( verify( provenance_load, confirm=False, dependencies=False ), default=str ))
        {}

    Comparing License
    -----------------

    A License is considered a subset or less-than another license if:

    - it is not signed by the same author
    - it doesn't contain at least the same dependencies
    - it doesn't grant at least the same grants

    """

    __slots__			= ('license', 'signature')
    serializers			= dict(
        signature	= into_b64,
    )

    def __init__( self, license, author_sigkey=None, signature=None, confirm=None,
                  machine_id_path=None, **kwds ):
        """Given an ed25519 signing key (32-byte private + 32-byte public), produce the provenance
        for the supplied License.

        Normal constructor calling convention to take a License and a signing key and create
        a signed provenance:

            LicenseSigned( <License>, <Keypair> )

        To reconstruct from a dict (eg. recovered from a .crypto-licensing file):

            LicenseSigned( **provenance_dict )

        """
        if isinstance( license, type_str_base ):
            license		= json.loads( license )  # Deserialize License, if necessary
        assert isinstance( license, (License, dict) ) and not isinstance( license, LicenseSigned ), \
            "Require a License or its serialization dict, not a {!r}".format( license )
        if isinstance( license, dict ):
            license		= License( confirm=confirm, machine_id_path=machine_id_path, **license )
        self.license		= license

        assert signature or author_sigkey, \
            "Require either signature, or the means to produce one via the author's signing key"
        if author_sigkey and not signature:
            # Sign our default serialization, also confirming that the public key matches
            self.signature	= self.license.sign(
                sigkey=author_sigkey, pubkey=self.license.author.pubkey )
        elif signature:
            # Could be a hex-encoded signature on deserialization, or a 64-byte signature.  If both
            # signature and author_sigkey, we'll just be confirming the supplied signature, below.
            self.signature	= into_bytes( signature, ('base64',) )
        super( LicenseSigned, self ).__init__( **kwds )

        self.verify(
            author_pubkey	= author_sigkey,
            confirm		= confirm,
            machine_id_path	= machine_id_path,
        )

    def grants( self, once=None ):
        if once is None:
            once		= set()
        return self.license.grants( once=once )

    def verify(
        self,
        author_pubkey	= None,
        signature	= None,
        confirm		= None,
        machine_id_path	= None,
        dependencies	= None,
        **constraints
    ):
        return self.license.verify(
            author_pubkey	= author_pubkey or self.license.author.pubkey,
            signature		= signature or self.signature,
            confirm		= confirm,
            machine_id_path	= machine_id_path,
            dependencies	= dependencies,
            **constraints
        )

    def __le__( self, rhs ):
        """Incompatible author provenance is always considered "not a subet".  A LicenseSigned
        issued by different authors cannot be considered equivalent, regardless of other License
        similarities.

        """
        if self.license.author.pubkey != rhs.license.author.pubkey:
            log.warning( "This License author: {} doesn't match rhs: {}".format(
                self.license.author.pubkey, rhs.license.author.pubkey  ))
            return False
        # OK, the signing author is compatible.  What about the rest of the License?
        return self.license <= rhs.license


class KeypairPlaintext( Serializable ):
    """De/serialize the plaintext Ed25519 private and public key material.  Order of arguments is
    NOT the same as ed25519.Keypair, b/c the public vk is optional.

    """
    __slots__			= ('sk', 'vk')
    serializers			= dict(
        sk		= into_b64,
        vk		= into_b64,
    )

    def __init__( self, sk=None, vk=None, **kwds ):
        """Support sk and optionally vk to derive and verify the Keypair.  At minimum, the first 256
        bits of private key material must be supplied; the remainder of the 512-bit signing key is a
        copy of the public key.

        """
        if not sk and not vk:
            vk,sk		= authoring( why="No Keypair supplied to KeypairPlaintext" )
        if hasattr( sk, 'sk' ):
            # Provided with a raw ed25519.Keypair or KeypairPlaintext; use its sk; retain any supplied vk for confirmation
            _,self.sk		= into_keys( sk )
        else:
            self.sk		= into_bytes( sk, ('base64',) )
        assert len( self.sk ) in (32, 64), \
            "Expected 256-bit or 512-bit Ed25519 Private Key, not {}-bit {!r}".format(
                len( self.sk ) * 8, self.sk )
        if vk:
            self.vk		= into_bytes( vk, ('base64',) )
            assert len( self.vk ) == 32, \
                "Expected 256-bit Ed25519 Public Key, not {}-bit {!r}".format(
                    len( self.vk ) * 8, self.vk )
            assert len( self.sk ) != 64 or self.vk == self.sk[32:], \
                "Inconsistent Ed25519 signing / public keys in supplied data"
        elif len( self.sk ) == 64:
            self.vk		= self.sk[32:]
        else:
            self.vk		= None
        # We know into_keypair is *only* going to use the self.sk[:32] (and optionally self.vk to
        # verify), so we've recovered enough to call it.
        self.vk, self.sk	= self.into_keypair()
        super( KeypairPlaintext, self ).__init__( **kwds )

    def into_keypair( self, **kwds ):
        """No additional data required to obtain Keypair; just the leading 256-bit private key material
        of the private key.

        """
        keypair			= authoring( seed=self.sk[:32], why="provided plaintext signing key" )
        if self.vk:
            assert keypair.vk == self.vk, \
                "Failed to derive matching Ed25519 public key from supplied private key data"
        return keypair


class KeypairCredentialError( Exception ):
    """Something is wrong with the provided Keypair credentials."""
    pass


class KeypairEncrypted( Serializable ):
    """De/serialize the keypair encrypted derivation seed, and the salt used in combination with the
    supplied username and password to derive the symmetric encryption key for encrypting the seed.
    The supported derivation(s):

        sha256:		hash of salt + username + password

    The 256-bit Ed25519 Keypair seed is encrypted using ChaCha20Poly1305 w/ the salt and derived
    key.  The salt and ciphertext are always serialized in hex, to illustrate that it is not Ed25519
    Keypair data.

    Can be supplied w/ a raw signing key or an ed25519.Keypair as an unencrypted key, along with
    username/password.  If no signing key at all is provided, one will be generated.

    If possible, derives the public key and signs it, proving that the author did, indeed, have the
    signing key corresponding to the public key.

    """
    __slots__			= ('salt', 'ciphertext', 'vk', 'vk_signature')
    serializers			= dict(
        salt		= into_hex,
        ciphertext	= into_hex,
        vk		= into_b64,
        vk_signature	= into_b64,
    )

    def __init__( self, sk=None, vk=None, vk_signature=None, salt=None, ciphertext=None, username=None, password=None,
                  **kwds ):
        has_encrypted		= ciphertext is not None and salt is not None
        has_credentials		= password is not None and username is not None
        if not ( has_encrypted or has_credentials ):
            raise TypeError( "Insufficient arguments to create an Encrypted Keypair; either ciphertext/salt or password/username required" )
        if not has_encrypted and not sk:
            # Neither ciphertext supplied, nor plaintext signing key; must want a new Keypair
            vk,sk		= authoring( why="No Keypair supplied to KeypairEncrypted" )
        elif sk:
            # A signing key provided (and maybe also encrypted); let's get the private key bytes
            if hasattr( sk, 'sk' ):
                # Provided with a raw ed25519.Keypair or KeypairPlaintext; extract its sk, and use any supplied vk for confirmation
                vk,sk		= into_keys( sk )
            else:
                sk		= into_bytes( sk, ('base64',) )
            assert isinstance( sk, bytes ), \
                f"Expected bytes sk, not: {sk!r}"
        if salt:
            self.salt		= into_bytes( salt, ('hex',) )
        else:
            # If salt not supplied, supply one -- but we obviously can't be given an encrypted seed!
            assert sk and not ciphertext, \
                "Expected unencrypted keypair if no is salt provided"
            self.salt		= token_bytes( 12 )
        assert len( self.salt ) == 12, \
            "Expected 96-bit salt, not {!r}".format( self.salt )
        # And, if a pubkey and/or pubkey signature provided, also get their bytes
        vk			= into_bytes( vk, ('base64',) )
        vk_signature		= into_bytes( vk_signature, ('base64',) )

        # We've normalized everything provided into bytes; now produce/verify ciphertext
        if ciphertext:
            # We are provided with the encrypted seed (tag + ciphertext).  Done!  But, we don't know
            # the original Keypair, here, so we can't verify below.
            self.ciphertext	= into_bytes( ciphertext, ('hex',) )
            assert len( self.ciphertext ) * 8 == 384, \
                "Expected 384-bit ChaCha20Poly1305-encrypted seed, not a {}-bit {!r}".format(
                    len( self.ciphertext ) * 8, self.ciphtertext )
            keypair		= None
        else:
            # We are provided with the unencrypted signing key.  We must encrypt the 256-bit private
            # key material to produce the seed ciphertext.  Remember, the Ed25519 private signing
            # key always includes the 256-bit public key appended to the raw 256-bit private key
            # material.
            seed		= sk[:32]
            keypair		= authoring( seed=seed, why="Signing key supplied to KeypairEncrypted" )
            if vk:
                assert keypair.vk == vk, \
                    "Failed to derive Ed25519 signing key from supplied data"
            key			= self.key( username=username, password=password )
            cipher		= ChaCha20Poly1305( key )
            plaintext		= bytearray( seed )
            nonce		= self.salt
            self.ciphertext	= bytes( cipher.encrypt( nonce, plaintext ))
        if username and password:
            # Verify MAC by decrypting w/ username and password, if provided
            keypair_rec		= self.into_keypair( username=username, password=password )
            assert keypair is None or keypair_rec == keypair, \
                "Failed to recover original key after decryption"
            if vk:
                assert keypair_rec.vk == vk, \
                    "Failed deriving Ed25519 signing key {} matching claimed public key {}".format(
                        into_b64( keypair_rec.vk ), into_b64( vk ))
            if sk:
                assert keypair_rec.sk == sk, \
                    "Failed deriving Ed25519 signing key {} matching claimed signing key {}".format(
                        into_b64( keypair_rec.sk ), into_b64( sk ))
            vk,sk		= keypair_rec
        if vk:
            if vk_signature:
                # Verify supplied/deduced vk with provided vk_signature.  This allows us to validate
                # that the supplied vk was self-signed, even if we never decrypt the ciphertext.
                try:
                    ed25519.crypto_sign_open( vk_signature + vk, vk )
                except Exception as exc:
                    raise ValueError( "Failed to verify Ed25519 pubkey {} signature".format( into_b64( vk ))) from exc
            elif sk:
                # We have both vk and sk, either supplied or deduced, but no vk_signature.  Produce it.
                vk_signature	= ed25519.crypto_sign( vk, sk )[:64]

        # If an encrypted (ciphertext-only) is supplied, we will not be able to deduce the
        # vk/vk_signature, and these will remain None.  Thus, only iff no username/password.
        self.vk			= vk
        self.vk_signature	= vk_signature
        super( KeypairEncrypted, self ).__init__( **kwds )

        assert vk_signature or not has_credentials, \
            "No pubkey signature deduced, but credentials are available: {}".format( self )

    def key( self, username, password ):
        # The username, which is often an email address, should be case-insensitive.
        username		= username.lower()
        username		= username.encode( 'UTF-8' )
        password		= password.encode( 'UTF-8' )
        m			= hashlib.sha256()
        m.update( self.salt )
        m.update( username )
        m.update( password )
        return m.digest()

    def into_keypair( self, username=None, password=None ):
        """Recover the original signing Keypair by decrypting with the supplied data.  Raises a
        KeypairCredentialError on decryption failure.

        """
        assert username and password, \
            "Cannot recover encrypted Keypair without username and password"
        key			= self.key( username=username, password=password )
        cipher			= ChaCha20Poly1305( key )
        nonce			= self.salt
        ciphertext		= bytearray( self.ciphertext )
        try:
            plaintext		= bytes( cipher.decrypt( nonce, ciphertext ))
        except Exception as exc:
            raise KeypairCredentialError(
                "Failed to decrypt ChaCha20Poly1305-encrypted Keypair w/ {}'s credentials".format( username )) from exc
        keypair			= authoring( seed=plaintext, why="decrypted w/ {}'s credentials".format( username ))
        return keypair


def authoring(
    seed		= None,
    why			= None,
):
    """Prepare to begin authoring Licenses, by creating an Ed25519 Keypair."""
    keypair			= ed25519.crypto_sign_keypair( seed or token_bytes( 32 ))
    log.info( "{how} Ed25519 signing keypair  w/ Public key: {pubkey}{why}".format(
        how	= "Recover" if seed else "Created",
        pubkey	= into_b64( keypair.vk ),
        why	= " ({})".format( why ) if why else "",
    ))
    return keypair


def save_keypair(
    keypair,
    why			= None,
    extension		= None,
    reverse_save	= None,
    **kwds  # eg. {base,file}name, package, extra=["..."], reverse_save, other open() args; see config_open
):
    """
    Successfully created new Keypair; now, try to create file; will not overwrite.
    """
    if why is None:
        why			= "the"
    for f in config_open_deduced(
        mode		= "wb",
        extension	= extension or KEYEXTENSION,  # But uses default extension on creation
        skip		= False,  # For writing/creating, of course we don't want to "skip" anything...
        reverse		= reverse_save,
        **kwds
    ):
        try:
            with f:
                keypair.save( f )  # keypair._from preserves f.name
        except Exception as exc:
            log.detail( "Writing {why} Keypair to {path} failed: {exc}".format( why=why, path=f.name, exc=exc ))
            raise NotRegistered( "Failed to register {why} Keypair: {exc}".format( why=why, exc=exc )) from exc
        else:
            log.normal( "Wrote {why} Keypair to {path}: {pubkey}".format( why=why, path=keypair._from, pubkey=keypair['vk'] ))
            break
    else:
        raise NotRegistered( "Failed to find a place to save {why} Keypair".format( why=why ))
    return keypair._from


def registered(
    seed		= None,
    why			= None,
    username		= None,		# The credentials for our agent's Keypair
    password		= None,
    extension		= None,		# Use exactly this extension for searching/registering
    registering		= None,		# True by default, create a new Keypair if none found
    reverse_save	= None,		# None (False by default); saves from most general location to most specific
    **kwds  # eg. {base,file}name, package, extra=["..."], reverse_save, other open() args; see config_open
):
    """Find an existing Keypair w/ the given basename and extension, or create an authoring Keypair
    and save it, returning the Keypair.  Always searches from the most specific to the most general
    config location.  However, defaults to save in the most general (writable) location possible,
    but will use the CWD if necessary.

    Will not overwrite an existing file of the same name, if found!  If the Keypair can be loaded
    with the given credentials, it is considered as registered and returned.  Otherwise, this is
    considered an error; you already have a Keypair registered with perhaps different credentials,
    and you should probably be trying to 'load_keypairs' before you register a new Agent ID...

    Returns the resultant KeypairEncryped or KeypairPlaintext, w/ a ._from property == path.

    """
    if not why:
        why			= "End-user"
    if registering is None:
        registering		= True
    # See if the target Keypair already exists somewhere; if so, we don't want to overwrite it -- if
    # we can successfully load it, then consider the Keypair already registered.
    log.debug( "Looking for existing {why} Keypair...".format(
        why	= why,
    ))
    try:
        _,keypair,_,keypair_raw = next( load_keypairs(
            extension	= extension or KEYPATTERN,  # Uses the glob pattern for searching
            username	= username,
            password	= password,
            detail	= True,
            **kwds
        ))
    except StopIteration:
        log.info( "Looking for existing {why} Keypair failed: no Keypair found".format(
            why		= why,
        ))
        pass
    else:
        log.normal( "Found {why} Keypair at {path}: {pubkey}".format(
            why		= why,
            path	= keypair._from,
            pubkey	= into_b64( keypair_raw.vk ),
        ))
        return keypair

    if not registering:
        raise NotRegistered( "Failed to find a {why} Keypair; registering a new one was declined".format(
            why		= why,
        ))

    # Not already registered, and registering is desired; create one.
    keypair_raw			= authoring(
        seed		= seed,
        why		= why )
    if username and password:
        keypair			= KeypairEncrypted(
            sk		= keypair_raw.sk,
            username	= username,
            password	= password,
        )
    else:
        keypair			= KeypairPlaintext(
            sk		= keypair_raw.sk,
        )

    save_keypair(
        keypair,
        reverse_save	= reverse_save,
        **kwds
    )
    return keypair


def issue(
    license,
    author_sigkey,
    signature		= None,
    confirm		= None,
    machine_id_path	= None,
):
    """If possible, issue the license signed with the supplied authoring signing key. Ensures that the
    license is allowed to be issued, by verifying the signatures of the tree of dependent license(s)
    if any.

    The holder of an author secret key can issue any license they wish (so long as it is compatible
    with any License dependencies).

    Generally, a license may be issued if it is more "specific" (less general) than any License
    dependencies.  For example, a License could specify that it can be used on *any* 1
    installation.  The holder of the license may then issue a License specifying the machine ID
    of a certain computer.  The software then confirms successfully that the License is allocated
    to *this* computer.

    Of course, this is all administrative; any sufficiently dedicated programmer can simply remove
    the License checks from the software.  However, such people are *not* Clients: they are simply
    thieves.  The issuance and checking of Licenses is to help support ethical Clients in confirming
    that they are following the rules of the software author.

    """
    return LicenseSigned(
        license,
        author_sigkey,
        signature	= signature,
        confirm		= confirm,
        machine_id_path	= machine_id_path,
    )


def save(
    provenance,
    why			= None,
    extension		= None,
    reverse_save	= None,
    **kwds  # eg. {base,file}name, package, extra=["..."], reverse_save, other open() args; see config_open
):
    """
    Successfully created License; now, try to create file; will not overwrite.  Returns the saved License's path.
    """
    if why is None:
        why			= "the"
    for f in config_open_deduced(
        mode		= "wb",
        extension	= extension or LICEXTENSION,  # But uses default extension on creation
        skip		= False,  # For writing/creating, of course we don't want to "skip" anything...
        reverse		= reverse_save,
        **kwds
    ):
        try:
            with f:
                provenance.save( f )  # LicenseSigned._from preserves f.name
        except Exception as exc:
            log.detail( "Writing {why} License to {path} failed: {exc}".format( why=why, path=f.name, exc=exc ))
            raise NotLicensed( "Failed to save {why} License: {exc}".format( why=why, exc=exc )) from exc
        else:
            log.normal( "Wrote {why} License to {path}".format( why=why, path=provenance._from ))
            break
    else:
        raise NotLicensed( "Failed to find a place to save {why} License".format( why=why ))
    return provenance._from


def license(
    author,				# w/ a .keypair, or
    author_sigkey	= None,		# an separate signing key
    why			= None,
    client		= None,		# If no designated client, allow anyone to sub-License
    dependencies	= None,		# Any Licenses this License depends on
    machine		= None,
    timespan		= None,
    grant		= None,
    machine_id_path	= None,
    confirm		= None,		# Validate License' author.pubkey from DNS
    extension		= None,		# Defaults to exactly match LICEXTENSION
    **kwds  # eg. {base,file}name, package, extra=["..."], reverse_save, other open() args; see config_open
):
    """Create a License w/ the specified author and grant(s), and save it, returning the path.  By
    default, attempts to save in the most general (writable) location possible, but will use the CWD
    if necessary.

    Will not overwrite an existing file of the same name, if found!  This is considered an error;
    you should probably be trying to 'check' before you save a License w/ the same basename and extension.

    Returns the resultant LicenseSigned, w/ a ._from property containing the path.

    """
    if not why:
        why			= "End-user"
    try:
        lic			= License(
            author		= author,
            client		= client,
            dependencies	= dependencies,
            machine		= machine,
            timespan		= timespan,
            grant		= grant,
            machine_id_path	= machine_id_path,
            confirm		= confirm,
        )
        provenance		= issue(
            lic,
            author_sigkey	= author.keypair or author_sigkey,
            confirm		= confirm,
            machine_id_path	= machine_id_path
        )
    except Exception as exc:
        log.warning( "Creating {why} License failed: {exc}".format(
            why		= why,
            exc		= ''.join( traceback.format_exception( *sys.exc_info() )) if log.isEnabledFor( logging.DEBUG ) else exc,
        ))
        raise NotLicensed( "Failed to save a new License: {exc}".format( exc=exc )) from exc
    else:
        log.info( "Created License provenance {}".format( provenance ))

    # If we have already saved an identical license
    try:
        save(
            provenance,
            extension	= extension,
            why		= why,
            **kwds
        )
    except ConfigFoundError as existing_exc:
        # Deja Vu?  If the proposed License is a subset of the one found, return it instead.
        path,*_			= existing_exc.args
        with open( path, "rb" ) as f:
            existing_ser	= f.read()
            existing_dict	= json.loads( existing_ser )
            existing		= LicenseSigned(
                confirm=confirm, machine_id_path=machine_id_path, _from=f.name, **existing_dict
            )
        if not ( provenance <= existing ):
            raise LicenseDuplicated( existing, provenance ) from existing_exc
        log.info( "Existing License provenance {} is compatible".format( existing ))
        provenance		= existing
    return provenance


def verify(
    provenance,
    author_pubkey	= None,
    signature		= None,
    confirm		= None,
    machine_id_path	= None,
    dependencies	= None,
    **constraints
):
    """Verify that the supplied License or LicenseSigned contains a valid signature, and that the
    License follows the rules in all of its License dependencies.  Optionally, 'confirm' the
    validity of any public keys.

    Apply any additional constraints, returning a License serialization dict satisfying them.  If
    you plan to issue a new LicenseSigned, it is recommended to include your author, author_domain
    and product names, and perhaps also the client and client_pubkey of any intended License
    recipient (otherwise, any client may sub-license, so be careful to only grant capabilities
    appropriate for many generic licensees).

    Works with either a License and signature= keyword parameter, or a LicenseSigned provenance.

    Defaults to demand that any supplied LicenseSigned 'dependencies' are included in the resultant
    remaining constraints.  If it is None, by default (unlike the License{Signed}.verify, which is
    intended for recursive verification, so doesn't alter constraints), this will include this
    target LicenseSigned provenance in the returned constraints required, so that a sub-License for
    the verified License can be produced.

    Therefore, when you have a LicenseSigned or a License + a signature, calling verify( <lic> ... )
    will return a requirements dict ready to pass to License, along with an author and (optionally)
    designated client Agent, with the target verified License itself in the dependencies list,
    producing a new License which sub-licenses the just verified License.

    """
    return provenance.verify(
        author_pubkey	= author_pubkey,
        signature	= signature or provenance.signature,
        confirm		= confirm,
        machine_id_path	= machine_id_path,
        dependencies	= True if dependencies is None else dependencies,
        **constraints
    )


def load(
    mode	= None,
    extension	= None,
    confirm	= None,
    machine_id_path = None,
    **kwds  # eg. {base,file}name, package, extra=["..."], reverse_save, other open() args; see config_open
):
    """Open and load all crypto-lic[ens{e,ing}] file(s) found on the config path(s) (and any
    extra=[...,...]  paths) containing a LicenseSigned provenance record.  By default, use the
    provided package's (your __package__) name, or the executable filename's (your __file__)
    basename.  Assumes '<basename>.crypto-lic*', if no extension provided.

    Applies glob pattern matching via config_open....

    Yields the resultant (filename, LicenseSigned) provenance(s), or an Exception if any
    glob-matching file is found that doesn't contain a serialized LicenseSigned.

    """
    for f in config_open_deduced(
        extension	= extension or LICPATTERN,
        mode		= mode,
        **kwds
    ):
        with f:
            prov_ser		= f.read()
            prov_dict		= json.loads( prov_ser )
            prov		= LicenseSigned(
                confirm=confirm, machine_id_path=machine_id_path, _from=f.name, **prov_dict
            )
        yield prov._from, prov


def load_keypairs(
    mode	= None,
    extension	= None,
    username	= None,
    password	= None,		# Decryption credentials to use
    every	= False,
    detail	= False,        # Yield every file w/ origin + credentials info or exception?
    **kwds  # eg. {base,file}name, package, extra=["..."], reverse_save, other open() args; see config_open
):
    """Load Ed25519 signing Keypair(s) from glob-matching file(s) with any supplied credentials.
    Yields all Encrypted/Plaintext Keypairs successfully opened (may be none at all), as a sequence
    of:

        <filename>, <Keypair/Exception>

    or, if detail is True:

        <filename>, <Keypair{Encrypted,Plaintext}>, <credentials dict>, <Keypair/Exception>

    If every=True, then every file found will be returned with every credential, and an either
    Exception explaining why it couldn't be opened, or the resultant decrypted Ed25519 Keypair.
    Otherwise, only successfully decrypted Keypairs will be returned.

    - Read the plaintext Keypair's public/private keys.

      WARNING: Only perform this on action on a secured computer: this file contains your private
      signing key material in plain text form!

    - Load the encrypted seed (w/ a random salt), and:
      - Derive the decryption symmetric cipher key from the salt + username + password

        The plaintext 256-bit Ed25519 private key seed is encrypted using ChaCha20Poly1305 with the
        symmetric cipher key using the (same) salt as a Nonce.  Since the random salt is only (ever)
        used to encrypt one thing, it satisfies the requirement that the same Nonce only ever be
        used once to encrypt something using a certain key.

    - TODO: use a second Keypair's private key to derive a shared secret key

      Optionally, this Signing Keypair's derivation seed can be protected by a symmetric cipher
      key derived from the *public* key of this signing key, and the *private* key of another
      Ed25519 key using diffie-hellman.  For example, one derived via Argon2 from an email +
      password + salt.

    Therefore, the following deserialized Keypair dicts are supported:

    Unencrypted Keypair:

        {
            "sk":"bw58LSvuadS76jFBCWxkK+KkmAqLrfuzEv7ly0Y3lCLSE2Y01EiPyZjxirwSjHoUf9kz9meeEEziwk358jthBw=="
            "vk":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk="
        }

    384-bit ChaCha20Poly1305-Encrypted seed (ya, don't use a non-random salt...):
        {
            "salt":"000000000000000000000000",
            "ciphertext":"d211f72ba97e9cdb68d864e362935a5170383e70ea10e2307118c6d955b814918ad7e28415e2bfe66a5b34dddf12d275"
        }

    NOTE: For encrypted Keypairs, we do not need to save the "derivation" we use to arrive at
    the cryptographic key from the salt + username + password, since the encryption used includes a
    MAC; we try each supported derivation.

    If NO ...Keypairs at all are found, TODO

    """
    issues			= {}		# { "name": [ <Exception>, ... ]
    tried			= 0		# How many files seen and tried
    found			= 0		# How many Keypairs successfully found
    for f in config_open_deduced(
        extension	= extension or KEYPATTERN,
        mode		= mode,
        **kwds
    ):
        tried		       += 1
        f_name			= f.name
        try:
            with f:
                f_ser		= f.read()
            keypair_dict	= json.loads( f_ser )
            keypair_dict['_from'] = f_name  # And define the Serializable._from we loaded from
        except Exception as exc:
            log.debug( "Failure to load KeypairEncrypted/Plaintext from {}: {}".format(
                f_name, exc ))
            issues.setdefault( f_name, [] )
            issues[f_name].append( exc )
            continue
        # Attempt to recover the different Keypair...() types, from most stringent requirements to least.
        encrypted		= None
        try:
            try:
                encrypted	= KeypairEncrypted( username=username, password=password, **keypair_dict )
            except TypeError as exc:  # Incorrect arguments, ...
                raise TypeError( "Keypair w/ keywords {} probably isn't a KeypairEncrypted: {}".format(
                    ', '.join( keypair_dict ), exc
                )) from exc
            keypair		= encrypted.into_keypair( username=username, password=password )
            log.info( "Recover Ed25519 KeypairEncrypted w/ Public key: {} (from {}) w/ credentials {} / {}".format(
                into_b64( keypair.vk ), f_name, username, '*' * len( password )))
            if detail:
                yield f_name, encrypted, dict( username=username, password=password ), keypair
            else:
                yield f_name, keypair
            found	       += 1
            continue
        except KeypairCredentialError as exc:
            # The KeypairEncrypted was OK -- just the credentials were wrong; don't bother trying as non-Encrypted
            log.debug( "Failed to decrypt KeypairEncrypted: {exc}".format(
                exc=''.join( traceback.format_exception( *sys.exc_info() )) if log.isEnabledFor( logging.TRACE ) else exc ))
            issues.setdefault( f_name, [] )
            issues[f_name].append( exc )
            if every:
                if detail:
                    yield f_name, encrypted, dict( username=username, password=password ), exc
                else:
                    yield f_name, exc
            continue
        except Exception as exc:
            # Some other problem attempting to interpret this thing as a KeypairEncrypted; carry on and try again
            issues.setdefault( f_name, [] )
            issues[f_name].append( exc )
            log.debug( "Failed to decode KeypairEncrypted: {exc}".format(
                exc=''.join( traceback.format_exception( *sys.exc_info() )) if log.isEnabledFor( logging.TRACE ) else exc ))
        # Not a KeypairEncrypted; try as KeypairPlaintext
        plaintext		= None
        try:
            try:
                plaintext	= KeypairPlaintext( **keypair_dict )
            except TypeError as exc:
                raise RuntimeError( "Keypair file w/ keywords {} probably isn't a KeypairPlaintext".format(
                    ', '.join( keypair_dict )
                )) from exc
            keypair		= plaintext.into_keypair()
            log.isEnabledFor( logging.DEBUG ) and log.debug(
                "Recover Ed25519 KeypairPlaintext w/ Public key: {} (from {})".format(
                    into_b64( keypair.vk ), f_name ))
            if detail:
                yield f_name, plaintext, {}, keypair
            else:
                yield f_name, keypair
            found	       += 1
            continue
        except Exception as exc:
            # Some other problem attempting to interpret as a KeypairPlaintext
            issues.setdefault( f_name, [] )
            issues[f_name].append( exc )
            if every:
                if detail:
                    yield f_name, plaintext, {}, exc
                else:
                    yield f_name, exc
            log.debug( "Failed to decode KeypairPlaintext: {exc}".format(
                exc=''.join( traceback.format_exception( *sys.exc_info() )) if log.isEnabledFor( logging.TRACE ) else exc ))

    if not found:
        for f_name in issues:
            log.warning( "Cannot load Keypair(s) from {f_name}: {reasons}".format(
                f_name=f_name, reasons=', '.join( "{}".format( exc ) for exc in issues[f_name] )))


def key_lic_sequence_logger( func ):
    """Logs a sequence of <Keypair>,<License>, including _from (if available).  Passes thru any
    <generator>.send( payload ).  Supports either ed25519.Keypair, or Keypair{Plaintext,Encrypted}"""
    @wraps( func )
    def wrapper( *args, **kwds ):
        labelled		= False
        func_iter		= func( *args, **kwds )
        try:
            payload		= None
            while True:
                key,lic		= func_iter.send( payload )
                level		= logging.NORMAL if key and lic else logging.DETAIL
                if log.isEnabledFor( level ):
                    if not labelled:
                        log.normal( "{:56} {:20} {:20} {:16}: {}".format(
                            'License', 'Client', 'Author', 'Product', 'Keypair'
                        ))
                        labelled	= True
                    log.log( level, "{:56} {:20.20} {:20.20} {:16.16}: {}{}".format(
                        'N/A' if not hasattr( lic, '_from' ) or not lic._from else os.path.basename( lic._from ),
                        'N/A' if not lic or not lic.license.client else "{}/{}".format( lic.license.client.name, into_b64( lic.license.client.pubkey )),
                        'N/A' if not lic else "{}/{}".format( lic.license.author.name, into_b64( lic.license.author.pubkey )),
                        'N/A' if not lic or not lic.license.author.product else lic.license.author.product,
                        'N/A' if not key else into_b64( key.vk ),
                        key._from if hasattr( key, '_from' ) else '',
                    ))
                payload		= ( yield key,lic )
        except StopIteration:
            pass
    return wrapper


def check_nolog(
    mode		= None,
    extension_keypair	= None,
    extension_license	= None,
    username		= None,			# Keypair protected w/ supplied credentials
    password		= None,
    confirm		= None,
    machine_id_path	= None,
    constraints		= None,
    keypairs		= None,			# Any additional ed25519.Keypairs we might need, to utilize Licenses
    **kwds  # eg. {base,file}name, package, extra=["..."], reverse_save, other open() args; see config_open
):
    """Load our agent key(s), check that License(s) have been (or can be) issued to our agent, for
    this machine and/or username, yielding a sequence of:

        (None,None)			- nothing, if no Keypair could be found w/ given credentials
        (<Keypair>,None,)		- if Keypair found, but no Licenses available
        (<Keypair>,<LicenseSigned>)	- if Keypair and issued License(s) found

    Thus, if a <Keypair> is found but no <LicenseSigned> can be found or assigned, the caller can
    use the <Keypair> in a subsequent 'issue' request, and then save the received LicenseSigned
    provenance for future use.

    Can deduce a basename from provided filename/package, if desired

    - Load our Ed25519 Keypair
      - Create one, if not found
    - Load our Licenses
      - Obtain one, if not found

    If an Ed25519 Agent signing authority Keypair or License must be created, the default location
    where they should be stored is in the most general configuration path location that is writable.
    We don't do that here; the caller should create one, as appropriate, and either save it (so we
    find it with load_keypairs on a subsequent call), or pass it in via keypairs.  We will load all
    available Keypairs/Licenses, and attempt to return any Licenses that are verified for any
    Keypair (ie. were issued by the Keypair, or could be sub-licensed by the Keypair, which we will
    do automatically, so the Licensee doesn't actually need to save their LicenseSigned provenance
    -- unless they wish to avoid the need to be online and "confirm" the validity of the
    sub-Licenses in the future; they can save the generated LicenseSigned, and trust their
    signature to prove that, in the past, they agreed that the sub-License(s) were verified).

    Agent signing authority is usually machine- or username-specific: a License to run a program on
    one machine and/or for one username usually doesn't transfer to another machine/username.
    However, you can arrange for a License to have a certain client Agent Keypair, and issue a
    License for a certain Machine ID.  Later, when the client restores from backups onto a new
    machine, the License will fail to validate (b/c new Machine ID).

    However, if the issued License is specific to the client's Keypair (or the License doesn't
    specify a client public key at all), they can load their Keypair (by entering credentials), and
    re-sub-license their License for the new machine.  Thus, we'll automatically do this here, w/
    proper username/password, and return the newly sub-licensed LicenseSigned provenance.

    We assume that any Keypair we can load (ie. we have the username/password to access) must imply
    a signing authority.  So, don't keep generic license keypairs (ie. those used to author
    licenses, or sub-license master Licenses to clients) n the same directories (or with the same
    credentials) as those used for end-user client agents.  Otherwise, this will pick them up and
    use them to create sub-licenses!

    """
    # Any supplied authoring ed25519.Keypairs are of unknown paths
    keypairs			= [ (None,key) for key in keypairs or [] ]
    # Load any Keypair{Plaintext,Encrypted} available, and convert to a ed25519.Keypair,
    # ready for signing/verification.  Retains orders of load_keypairs / load.
    keypairs		       += list(
        (key_path, keypair_or_error)
        for key_path, keypair_typed, cred, keypair_or_error in load_keypairs(
            username	= username,
            password	= password,
            mode	= mode,
            extension	= extension_keypair,
            every	= True,
            detail	= True,
            **kwds
        )
        if isinstance( keypair_or_error, ed25519.Keypair )
    )

    licenses			= list( load(
        mode		= mode,
        extension	= extension_license,
        confirm		= confirm,
        machine_id_path	= machine_id_path,
        **kwds
    ))

    # See if license(s) has been (or can be) issued to our Agent keypair(s) (ie. was issued to this
    # keypair as a specific client_pubkey or was non-client-specific, and then was signed by our
    # Keypair), for this Machine ID.
    matches			= 0
    key_seen			= set()  # of Ed25519.Keypair.vk.  No keys loaded --> yield None,None
    for key_path,keypair in keypairs:    # key_path may be None for any authoring Keypairs provided
        if keypair.vk in key_seen:
            log.debug( "Ignoring redundant keypair {pubkey} from {path}".format(
                pubkey	= into_b64( keypair.vk ),
                path	= key_path,
            ))
            continue
        key_seen.add( keypair.vk )
        log.info( "Checking keypair {key_path:32} ({pubkey})...".format(
            key_path	= os.path.basename( key_path or '(unknown)' ),
            pubkey	= into_b64( keypair.vk ),
        ))
        # For each unique Keypair, discover any LicenceSigned we've been issued, or can issue.
        lic_path,lic		= None,None	 # If no Licensese found, at all
        prov,reasons		= None,[]        # Why didn't any Licenses qualify?
        for lic_path,lic in licenses:
            # Was this license issued by our Keypair Agent as the author?  This means that one was
            # issued by some author, with our Keypair Agent as a client (or no client specified),
            # and we (previously) issued and saved it -- we sub-licensed it.  All this means is that
            # (at some point) we had access to the un-encrypted Keypair, and we've issued ourselves
            # this License, claiming it's valid for us to use; for example, when we installed the
            # software on this machine and the client was sitting at the keyboard or otherwise
            # authorizing the installation, and was present to make the Keypair credentials
            # available.
            #
            # That claim must be checked by the software's author, in its license validation code...
            log.trace( "Evaluate {lic_path:32} / {key_path:32} w/ constrints {constraints!r}".format(
                lic_path	= os.path.basename( lic_path ),
                key_path	= os.path.basename( key_path or '(unknown)' ),
                constraints	= constraints ))
            try:
                lic.verify(
                    author_pubkey	= keypair.vk,
                    confirm		= confirm,
                    machine_id_path	= machine_id_path,
                    dependencies	= False,
                    **( constraints or {} )
                )
            except Exception as exc:
                log.info( "Checked  {lic_path:32} / {key_path:32} ({pubkey:64}); License is not sub-licensed to this Keypair: {exc}".format(
                    lic_path	= os.path.basename( lic_path ),
                    key_path	= os.path.basename( key_path or '(unknown)' ),
                    pubkey	= into_b64( keypair.vk ),
                    exc		= ''.join( traceback.format_exception( *sys.exc_info() )) if log.isEnabledFor( logging.TRACE ) else exc ))
                reasons.append( str( exc ))
            else:
                # This license passed muster w/ the constraints supplied and it was already issued
                # to us; we're done.
                matches	       += 1
                yield keypair,lic
                continue

            # License not already issued to us; check whether it could be ours w/ some remaining
            # constraints requirements.  We're going to try to issue a sub-License, so include the
            # LicenseSigned itself in the resultant computed constraints requirements.
            try:
                requirements	= lic.verify(
                    confirm		= confirm,
                    machine_id_path	= machine_id_path,
                    dependencies	= True,
                    **( constraints or {} )
                )
            except Exception as exc:
                log.info( "Verify  {lic_path:32} / {key_path:32} ({pubkey:64}); License is not sub-licensable: {exc}".format(
                    lic_path	= os.path.basename( lic_path ),
                    key_path	= os.path.basename( key_path or '(unknown)' ),
                    pubkey	= into_b64( keypair.vk ),
                    exc		= ''.join( traceback.format_exception( *sys.exc_info() )) if log.isEnabledFor( logging.TRACE ) else exc
                ))
                continue

            # Validated this License is sub-Licensable by this Keypair Agent!  This License is
            # available to be issued to us and verified, now, as one of our License dependencies.
            # Craft a new License, w/ the requirements produced by the verify, above.  If the
            # LicenseSigned provenance can be issued, it has fully passed verification.  We are
            # assuming that the License is sub-licensable (is author-able) by this agent's Keypair
            # as the client; if the License allows anonymous clients (no lic.license.client
            # specified), then make an ad-hoc Agent record.
            log.info( "Require {requirements!r}".format( requirements=requirements ))
            try:
                author		= lic.license.client
                if not author:
                    pubkey	= into_b64( keypair.vk )
                    author	= Agent( name=pubkey, pubkey=pubkey )
                prov		= issue(
                    License(
                        author		= author,
                        confirm		= confirm,
                        machine_id_path	= machine_id_path,
                        **requirements
                    ),
                    author_sigkey	= keypair.sk,
                    confirm		= confirm,
                    machine_id_path	= machine_id_path,
                )
            except Exception as exc:
                log.info( "Issuing {lic_path:32} / {key_path:32} ({pubkey:64}) failure: {exc}".format(
                    lic_path	= os.path.basename( lic_path ),
                    key_path	= os.path.basename( key_path or '(unknown)' ),
                    pubkey	= into_b64( keypair.vk ),
                    exc		= ''.join( traceback.format_exception( *sys.exc_info() )) if log.isEnabledFor( logging.TRACE ) else exc
                ))
                continue
            else:
                # The License was available to be issued as one of our dependencies, and passed
                # remaining constraints requirements; Use prov; prov_path remains None.
                matches	       += 1
                yield (keypair,prov)		# Reports <Keypair>,<LicenseSigned>
        else:
            if not licenses:
                yield (keypair,None)		# Reports <Keypair>,None
    else:
        if not key_seen:
            yield (None,None)			# Or None,None if no <Keypair>(s) at all (bad credentials?)

    log.debug( "Observed {keys} unique keys: {pubkeys}, {lics} licenses, finding {matches} possible Licenses".format(
        keys	= len( key_seen ),
        pubkeys	= ', '.join( into_b64( k ) for k in sorted( key_seen )),
        lics	= len( licenses ),
        matches	= matches,
    ))


check			= key_lic_sequence_logger( check_nolog )


def authorized_nolog(
    author,					# Details of the author's product we're licensing
    client		= None,			# ..and the intended specific client Agent
    username		= None,			# The credentials for our client Agent's Keypair
    password		= None,
    confirm		= None,
    machine_id_path	= None,
    constraints		= None,			# The additional constraints required of the author's license (if any)
    keypairs		= None,			# Any additional ed25519.Keypairs we might need, to utilize Licenses
    registering		= None,			# Default (to True) if necessary, create a new Keypair (register a new License client)
    acquiring		= None,			# Default (to True) if necessary, obtain/create a new License
    reverse_save	= None,
    basename		= None,			# A specific basename to use; otherwise client/author.servicekey
    **kwds  # eg. {base,file}name, package, extra=["..."], reverse_save, other open() args; see config_open
):
    """If possible, load and verify the client Agent's KeyPair (creating one if 'registering').
    Looks first for Keypairs/Licenses under the specified basename; defaults to client.servicekey,
    and then looks in author.servicekey.  Any Keypairs collected are used in subsequent searches, to
    see if a License issued by the author or to the client can be refined and issued on behalf of
    the named client agent.

    All Keypairs found are assumed to be client Agent keypairs useful for issuing sub-licenses: So,
    don't store author Agent keypairs in the same directories, or using the same credentials!

    Obtain any LicenseSigned provenances, and sift through them for any that authorize usage of the
    given author's domain and product, to the given client, for a certain space and time, and
    satisfying any constraints.

    If the period of authorization has expired, confirm with a license server that the LicenseSigned
    provenance is still valid (hasn't been revoked, eg. for reasons of license fraud, such as
    someone issuing the LicenseSigned provenance to clients on too many machines). A License without
    a period is never required to check the server (ie. lasts forever).

    If it can be proven that:

    1) The KeyPair belongs to the agent (unencrypted, decrypted or signed by the agent)
    2) the License is signed by the agent's KeyPair signing key (proving that the agent asked
       for it, and it was issued to the agent)
       - This indicates that the author was satisfied to authorize the client to use the resource in
         a certain space (machine) and for a certain time (period)
    3) The License was issued by the author for the machine-id on which we are running, and remains valid
    4) The License contains the required capabilities
       - and were issued by the expected Author

    then the requested capability is authorized.

    If a License is found that can be sub-licensed by a KeyPair, check_nolog will 'issue' it and
    return it.  We can tell that it wasn't loaded because it will not have a '._from' property.  We
    will simply return the LicenseSigned found; we can re-sublicense it again in the future, but the
    caller may wish to save it (to avoid having to provide credentials again in the future to
    decrypt the KeyPairEncryped).

    Yields the discovered sequence of KeyPair, License found, or if none found under any name,
    finally yields:

        - (None, None): No Keypair found

    Any new Keypair/License created/acquired will be save in basename or client.servicekey (or by
    package/filename if neither are supplied).

    """
    if registering is None:
        registering		= True
    if acquiring is None:
        acquiring		= True

    class State( Enum ):
        INITIAL		= 0
        CHECKING	= 1
        REGISTERING	= 2
        LICENSING	= 3
        DONE		= 4

    # We'll search for Keypairs and Licenses first under any basename supplied, then
    # client.servicekey, then author.servicekey.  This allows us to eg. save an author's License
    # somewhere, and then (later) load and sub-license it (if possible) on behalf of one or more
    # client Agents.  All Keypairs required to utilize a certain License must be typically found
    # under the same basename; however, we'll collect up all Keypairs found (eg. first under
    # basename, then client.servicekey, ...) for each subsequent License check... call.  Thus, we
    # can save a specific application agent Keypair (eg. under basename="some-application"), then
    # find a License we saved under eg. "our-company" Agent, or (if not found), we can locate a
    # generic "authors-product" License which is sublicensable using our
    # some-application.crypto-keypair.

    credentials_seen		= { (username,password) }
    # Remember all Keypair... --> [ License, ... ] under current credentials, incl. any supplied in 'keypairs'
    licenses			= { k: [] for k in keypairs or [] }
    state			= State.INITIAL
    basechecks			= None		# Triggers re-computation of all basenames to check (ie. after REGISTERING)
    while state is not State.DONE:
        state			= State( state.value + 1 )
        log.detail( "{state}".format( state=state ))
        if state is State.CHECKING:
            # Look for Agent Keypairs and any associated Licenses issued to it, filtered by the
            # Author we're looking for a License from.  We want to keep CHECKING, again and again,
            # while the caller provides new credentials, in case new Keypairs become available.
            if basechecks is None:
                basechecks	= [ basename ] if basename else []
                if client and client.servicekey and client.servicekey not in basechecks:
                    basechecks	= [ client.servicekey ] + basechecks  # then client...
                if author and author.servicekey and author.servicekey not in basechecks:
                    basechecks	= [ author.servicekey ] + basechecks  # then author...
            log.detail( "{state} for Keypairs/Licenses w/ {keys} Keypairs, basename {base} (of {checks})".format(
                state=state, keys=len( licenses ), base=basechecks[-1] if basechecks else None, checks=', '.join( map( str, basechecks )),
            ))

            # Check for Licenses available under one basename, given any ed25519.Keypairs collected
            # thus far, or found under this basename.  This will yield None,None if none found, but
            # we don't want to re-yield that until all hope is gone...
            basenow		= basechecks.pop() if basechecks else None  # Iff no basename or author/client.servicekey
            keypairs		= list( licenses.keys() )  # Use all previous discovered ed25519.Keypairs
            for key,lic in check_nolog(
                username	= username,
                password	= password,
                confirm		= confirm,
                constraints	= constraints,
                machine_id_path	= machine_id_path,
                basename	= basenow,
                keypairs	= keypairs,
                **kwds
            ):
                log.info( "{state} Checking w/ basename {base} & {keys} prior keypairs: key: {key} w/ lic: {lic}".format(
                    state=state, base=basenow, keys=len( keypairs), key=into_b64( key.vk if key else key ), lic=lic ))
                if key is None:
                    assert lic is None, \
                        "No Agent ID KeyPair; should not have found a License {}".format( lic )
                    # No KeyPair, and no new credentials provided.  Give them the opportunity to
                    # enter new Credentials by falling to end of loop; if none provided, then assume
                    # they want to go through the proceess; advance to REGISTERING.
                    log.detail( "No Agent, no License(s) found for {base} -- enter different credentials?".format(
                        base	= basename
                    ))
                    if basechecks:
                        # There remain further basenames to examine for potential Licenses; avoid
                        # emitting None,None 'til they've been exhausted!
                        log.detail( "{state} no more Keypairs/Licenses w/ basename {base}; trying next)".format(
                            state=state, base=basenow
                        ))
                        break  # still some basenames to check; don't yield None,None yet, avoid check's else: clause
                elif lic is None:
                    # An Agent ID KeyPair, but no License found available under some Keypair (and no
                    # new credentials supplied).  This is our moment to issue a new License;
                    # continues in state after REGISTERING (as if we've just completed REGISTERING).
                    licenses.setdefault( key, [] )
                    log.detail( "{state} Agent {agent}; but no License(s) found for {base} -- enter different credentials?".format(
                        state	= state,
                        agent	= into_b64( key.vk ),
                        base	= basename,
                    ))
                    pass  # A keypair, but no License; yield
                else:
                    # A candidate License!  See if it's what we're looking for.  This is probably a
                    # sub-License signed by this Agent containing a chain of LicenseSigned
                    # dependencies back to a License authored by the required authoring Agent, for
                    # the product we're looking for.  We look at the grants to see if one in there
                    # contains a Grant._from the required authoring Agent, eg. "cpppo-test":
                    # Grant(..., _from=<LicenseSigned>); TODO: check... won't verify any License
                    # that isn't issued (or issuable) explicitly to one of its keypairs; Hmmm.  It
                    # *will* emit any License that is issuable to one of our Keypairs, which may
                    # carry a sub-licensed grant from our target author.  So, this may be sufficient
                    # to catch all available licenses that *could* carry a sub-licensed Grant we're
                    # interested in.  We can't use any License (w/ sub-licenses) *unless* they are
                    # issuable to one of our Keypairs, anyway.
                    licenses.setdefault( key, [] )
                    log.detail( "{state} Agent {agent}; License found for {auth}'s {prod!r}{lic}".format(
                        state	= state,
                        agent	= into_b64( key.vk ),
                        auth	= lic.license.author.name,
                        prod	= lic.license.author.product,
                        lic	= str( lic ) if log.isEnabledFor( logging.DEBUG ) else ""
                    ))
                    # BUG: We should be checking that the License is issued to the *client* agent,
                    # or not checking at all?  The authorized API will return every License issued
                    # (possibly just now!) to any one of our Keypairs.  This is all we care about --
                    # that we were able to acquire the License.  If it carries no Grants from our
                    # desired author, that's all we care about verifying here?
                    if ( author is not None
                         and author != lic.license.author  # See Agent.__equal__; pubkey or 2/4 identifying attributes
                         and not any(
                             hasattr( v, '_from' ) and isinstance( v._from, Agent ) and author == v._from
                             for k,v in lic.license.grants().vars() )):
                        # This LicenseSigned not authored directly by the requested authoring Agent;
                        # nor does it *deliver* some Grant from the requested author.  Reject.
                        log.info( "{state} Agent {agent}; License for {auth}'s {prod!r} doesn't grant capabilities{extra}".format(
                            state	= state,
                            agent	= into_b64( key.vk ),
                            auth	= lic.license.author.name,
                            prod	= lic.license.author.product,
                            extra	= " (author {} not in grants {})".format(
                                author.serialize( encoding=None ),
                                ', '.join( map( repr, (
                                    v._from if ( hasattr( v, '_from' ) and isinstance( v._from, Agent )) else k
                                    for k,v in lic.grants().vars()
                                )))
                            ) if log.isEnabledFor( logging.DEBUG ) else ""
                        ))
                        continue
                    log.normal( "License for {auth_lic}'s {prod_lic!r} does grant capabilities for {auth}'s {prod}{stack}".format(
                        auth_lic	= lic.license.author.name,
                        prod_lic	= lic.license.author.product,
                        auth		= author.name,
                        prod		= author.product,
                        stack		= ''.join( traceback.format_stack() if log.isEnabledFor( logging.TRACE ) else [] ),
                    ))
                    # This License passed muster
                    licenses[key].append( lic )

                # Otherwise, we've found at least one passable license (or <key>,None or None,None
                # and no more basenames to check).  Keep yielding them 'til the caller finds one
                # that satisfies their requirements -- or, they might have purchased multiple licenses,
                # and could be accumulating their grants.  If we're back here, they haven't (yet)
                # found one; yield the next (collecting any .send( (username,password) )
                log.detail( "{state} Authorize key: {key}, lic: {lic}".format( state=state, key=KeypairPlaintext( key ), lic=lic ))
                credentials		= ( yield key,lic )
                if credentials and credentials not in credentials_seen:
                    # The caller supplied new credentials via .send( (username,password) ).  Restart
                    # the License authorization process using the new credentials (but retain prior
                    # Keypairs/Licenses), IFF they are different from previously seen credentials.
                    # (We do this test here (not at the start of the loop), to catch the case where
                    # only None,None is yielded from check).
                    username,password	= credentials
                    credentials_seen.add( credentials )
                    basechecks		= None  # Reset w/ new credentials; re-scan all basenames
                    state		= State.INITIAL
                    continue
            else:
                # Out of keypairs/licenses under this basename (and no more basechecks, b/c the last
                # thing we'd get from authorized would be (None,None), and we'd have broken out
                # above if there were more).  So, if no Licenses collected are satisfactory, but if we
                # do have at least one Agent ID, continue as if we've just completed REGISTER, and
                # proceed to LICENSE.  Otherwise, fall thru to REGISTERING (unless we've got more
                # basenames to try; then loop back.)
                log.info( "{state} Checking w/ basename {base} finished w/ {keys} known Keypairs, {lics} Licenses".format(
                    state=state, base=basenow, keys=len( licenses ), lics=len( sum( licenses.values(), [] ))))
            # At the end of check... loop, no acceptable Licenses found (or still collecting).  If
            # any more basenames available, let's try them (inheriting all ed25519.Keypairs found).
            if basechecks:
                log.info( "{state} Checking w/ basenames {bases} restarts w/ {keys} known Keypairs, {lics} Licenses".format(
                    state=state, bases=', '.join( basechecks ), keys=len( licenses ), lics=len( sum( licenses.values(), [] ))))
                state		= State.INITIAL
                continue
            # No more basenames available, done CHECKING.  Did we find anything?  If not, we'll have to fall thru to REGISTERING
            if licenses:
                # OK, we found at least one keypair, so we dont' need to fall thru to REGISTERING.
                # Did we find any Licenses?
                if not any( lic for lic in licenses.values() ):
                    # Keypair(s) found, but no Licenses.  Guess we have to try to get one...
                    state	= State.REGISTERING  # continues on to LICENSING
                    continue
                # Success!  We found at least one Keypair, and at least one License was found/issued!
                return

        elif state is State.REGISTERING:
            # We mustn't have seen even one Keypair available to sub-license an existing License;
            # should we try "registering" a new Keypair?  If None/'' is supplied for either
            # credential, an unencrypted Keypair will be produced.  Name defaults to basename or
            # client.servicekey (if exists); if neither, then package/filename must be provided.
            if not registering:
                raise NotRegistered( "No Keypair found; request registering one, or provide different credentials" )
            savename		= basename or ( client and client.servicekey ),  # Remains None if basename/client are None
            key			= registered(
                why		= "{} Keypair".format( savename or "End-user" ),
                username	= username,
                password	= password,
                registering	= True,
                reverse_save	= reverse_save,
                basename	= savename,
                **kwds
            )
            log.detail( "{state}: {action} {key}".format(
                state	= state,
                action	= "Loaded " if key._from else "Created",
                key	= key ))
            # BUG: If we do issue a Keypair, here, we must go on to re-evaluate every available
            # License in respect to the new Keypair; if there is a sub-licensable License w/o
            # restrictions on the client keypair, we could obtain it.  Do we loop back to CHECKING
            # (w/ a new client.keypair value), or carry on and do in it LICENSING?  We don't need to
            # try to load more new Keypairs, so maybe carry on...
            licenses		= { key.into_keypair( username=username, password=password ): [] }

        elif state is State.LICENSING:
            # We can end up here after yielding zero, one or more valid Licenses.  This is because
            # the caller is trying to accumulate all available Licenses, and can't know when no more
            # are available.  As they accumulate Licenses, looking for a certain accumulation of
            # License.grants(), the final remaining required Grant should be supplied.
            if acquiring and len( licenses ) != 1:
                log.normal( "{state}, w/ {keys} Agent IDs available -- enter different credentials?".format(
                    state	= state,
                    keys	= len( licenses )))
                credentials	= ( yield None, None )
                if credentials and credentials not in credentials_seen:
                    licenses		= dict()
                    username,password	= credentials
                    credentials_seen.add( credentials )
                    state		= State.INITIAL
                else:
                    # No keypairs (or too many), no new credentials.  We're done the authorize process.
                    log.warning( "{state}: {which} Agent Keypair; Not acquiring a License".format(
                        state	= state,
                        which	= "No" if not license else "Ambiguous",
                    ))
                    continue
            if not acquiring:
                # Not directed to attempt to acquire License.  We're done the authorize process.
                log.warning( "{state}; no Licenses found, not directed to acquire one".format(
                    state	= state,
                ))
                continue
            # One Agent Keypair; try to obtain a License
            key,	= licenses.keys()
            log.normal( "{state}, w/ Agent ID {agent}; attempting licensing".format(
                state	= state,
                agent	= into_b64( key.vk ),
            ))

            #
            # TODO: obtain a License
            #
        else:
            log.normal( "{state}, w/ {keys} Agent IDs and {lics} Licenses found".format(
                state	= state,
                keys	= len( licenses ),
                lics	= sum( len( licenses ) for _,licenses in licenses.items() ),
            ))


authorized		= key_lic_sequence_logger( authorized_nolog )
