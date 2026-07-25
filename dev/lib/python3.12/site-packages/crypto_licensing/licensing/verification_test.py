# -*- coding: utf-8 -*-

import binascii
import codecs
import copy
import json
import logging
import os
import pytest

from ..misc import pytz

try:
    import chacha20poly1305
except ImportError:
    chacha20poly1305		= None

from dns.exception	import DNSException
from requests		import ConnectionError
from .verification	import (
    License, LicenseSigned, LicenseIncompatibility, Timespan, Agent,
    KeypairPlaintext, KeypairEncrypted, machine_UUIDv4,
    domainkey, domainkey_service, overlap_intersect,
    into_b64, into_hex, into_str, into_str_UTC, into_JSON, into_keys, into_bytes,
    into_Timestamp, into_Duration,
    authoring, issue, verify, load, load_keypairs, check, authorized,
    DKIM_pubkey, DKIMError,
    ChaCha20Poly1305
)
from ..			import ed25519

from ..misc 		import (
    deduce_name, Timestamp
)
from .defaults		import LICEXTENSION

log				= logging.getLogger( "verification_test" )

dominion_sigkey			= binascii.unhexlify(
    '431f3fb4339144cb5bdeb77db3148a5d340269fa3bc0bf2bf598ce0625750fdca991119e30d96539a70cd34983dd00714259f8b60a2163bdb748f3fc0cf036c9' )
awesome_sigkey			= binascii.unhexlify(
    '4e4d27b26b6f4db69871709d68da53854bd61aeee70e63e3b3ff124379c1c6147321ce7a2fb87395fe0ff9e2416bc31b9a25475aa2e2375d70f4c326ffd47eb4' )
enduser_seed			= binascii.unhexlify( '00' * 32 )

username			= 'a@b.c'
password			= 'password'

machine_id_path			= __file__.replace( ".py", ".machine-id" )


def test_Agent():
    agent		= Agent(
        name	= "Someone",
        keypair	= authoring( seed=enduser_seed ),
    )
    agent_str		= str( agent )
    assert agent_str == """\
{
    "name":"Someone",
    "pubkey":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
}"""


def test_DKIM():
    assert DKIM_pubkey( 'v=DKIM1; k=ed25519; p=25lf4lFp0UHKubu6krqgH58uHs599MsqwFGQ83/MH50=' ) \
        == into_bytes( '25lf4lFp0UHKubu6krqgH58uHs599MsqwFGQ83/MH50=', ('base64',) )
    with pytest.raises( DKIMError ) as exc_info:
        DKIM_pubkey( 'v=DKIM2; k=ed25519; p=25lf4lFp0UHKubu6krqgH58uHs599MsqwFGQ83/MH50=' )
    assert "Failed to find 'DKIM1' record" in str( exc_info )


def test_License_domainkey():
    """Ensure we can handle arbitrary UTF-8 domains, and compute the proper DKIM1 RR path"""
    assert domainkey_service( u"π" ) == 'xn--1xa'
    assert domainkey_service( u"π/1" ) == 'xn---1-lbc'

    path, dkim_rr		= domainkey( u"Some Product", "example.com" )
    assert path == 'some-product.crypto-licensing._domainkey.example.com.'
    assert dkim_rr is None
    author_keypair		= authoring( seed=b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' )
    path, dkim_rr		= domainkey( u"ᛞᚩᛗᛖᛋ᛫ᚻᛚᛇᛏᚪᚾ᛬", "awesome-inc.com", pubkey=author_keypair )
    assert path == 'xn--dwec4cn7bwa4a4ci7a1b2lta.crypto-licensing._domainkey.awesome-inc.com.'
    assert dkim_rr == 'v=DKIM1; k=ed25519; p=25lf4lFp0UHKubu6krqgH58uHs599MsqwFGQ83/MH50='

    assert domainkey_service( u"יה-ה" ) == 'xn----7hcbr'
    assert domainkey_service( u"יהוה" ) == 'xn--8dbaco'
    path, dkim_rr		= domainkey( u"Raspberry π", u"יהוה.email", pubkey=author_keypair )
    assert path == 'xn--raspberry--1qh.crypto-licensing._domainkey.xn--8dbaco.email.'
    assert dkim_rr == 'v=DKIM1; k=ed25519; p=25lf4lFp0UHKubu6krqgH58uHs599MsqwFGQ83/MH50='

    # "Лайка.ru" wants to run a crypto-licensing server, selling  "Raspberry π"
    # http://crypto-licensing.xn--80aa0aec.ru/ (crypto-licensing.Лайка.ru)
    path, dkim_rr = domainkey( u"Raspberry π", u"Лайка.ru", pubkey=author_keypair )
    assert path == 'xn--raspberry--1qh.crypto-licensing._domainkey.xn--80aa0aec.ru.'
    # And make certain round-tripping punycoded domain names doesn't break
    path, dkim_rr = domainkey( "xn--raspberry--1qh", "xn--80aa0aec.ru", pubkey=author_keypair )
    assert path == 'xn--raspberry--1qh.crypto-licensing._domainkey.xn--80aa0aec.ru.'
    path, dkim_rr = domainkey( u"xn--raspberry--1qh", u"xn--80aa0aec.ru", pubkey=author_keypair )
    assert path == 'xn--raspberry--1qh.crypto-licensing._domainkey.xn--80aa0aec.ru.'


def test_License_overlap():
    """A License can only issued while all the sub-Licenses are valid.  The start/length should "close"
    to encompass the start/length of any dependencies sub-Licenses, and any supplied constraints.

    """
    other = Timespan( '2021-01-01 00:00:00 Canada/Pacific', '1w' )
    start,length,begun,ended = overlap_intersect( None, None, other )
    assert into_str_UTC( start ) == "2021-01-01 08:00:00 UTC"
    assert into_str( length ) == "1w"
    assert into_str_UTC( begun ) == "2021-01-01 08:00:00 UTC"
    assert into_str_UTC( ended ) == "2021-01-08 08:00:00 UTC"

    start = into_Timestamp( '2021-01-01 00:00:00 Canada/Pacific' )
    length = into_Duration( "1w" )
    start,length,begun,ended = overlap_intersect( start, length, Timespan( None, None ))
    assert into_str_UTC( start ) == "2021-01-01 08:00:00 UTC"
    assert into_str( length ) == "1w"
    assert into_str_UTC( begun ) == "2021-01-01 08:00:00 UTC"
    assert into_str_UTC( ended ) == "2021-01-08 08:00:00 UTC"


def test_KeypairPlaintext_smoke():
    enduser_keypair		= authoring( seed=enduser_seed, why="from enduser seed" )
    kp_p			= KeypairPlaintext( sk=into_b64( enduser_seed ), vk=into_b64( enduser_keypair.vk ))
    kp_p_ser			= str( kp_p )
    assert kp_p_ser == """\
{
    "sk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ==",
    "vk":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
}"""
    kp_p_rec			= KeypairPlaintext( **json.loads( kp_p_ser ))
    assert str( kp_p_rec ) == kp_p_ser

    # We can also recover with various subsets of sk, vk
    kp_p2			= KeypairPlaintext( sk=kp_p.sk[:32] )
    kp_p3			= KeypairPlaintext( sk=kp_p.sk[:64] )
    kp_p4			= KeypairPlaintext( sk=kp_p.sk[:64], vk=kp_p.vk )

    assert str( kp_p2 ) == str( kp_p3 ) == str( kp_p4 )

    # And see if we can copy Serializable things properly
    kp_c1			= copy.copy( kp_p4 )
    assert str( kp_c1 ) == str( kp_p4 )


@pytest.mark.skipif( ChaCha20Poly1305 is None, reason="Needs ChaCha20Poly1305" )
def test_KeypairEncrypted_smoke():
    enduser_keypair		= authoring( seed=enduser_seed, why="from enduser seed" )
    salt			= b'\x00' * 12
    kp_e			= KeypairEncrypted(
        salt		= salt,
        sk		= enduser_keypair.sk,
        username	= username,
        password	= password
    )
    assert kp_e.into_keypair( username=username, password=password ) == enduser_keypair

    kp_e_ser			= str( kp_e )
    assert kp_e_ser == """\
{
    "ciphertext":"d211f72ba97e9cdb68d864e362935a5170383e70ea10e2307118c6d955b814918ad7e28415e2bfe66a5b34dddf12d275",
    "salt":"000000000000000000000000",
    "vk":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
    "vk_signature":"YxRSIqHzZs5lfmWYm09wdKS8QJPSunH/Gjty/MQN5PQ3B+HkDeMtspXLWE9qbwYPGcNd1pBGaGpWAxW10l6RBg=="
}"""
    kp_r			= KeypairEncrypted( **json.loads( kp_e_ser ))
    assert str( kp_r ) == kp_e_ser

    # We can also reconstruct from just seed and salt (but no kv/vk_signature will be available
    kp_e2			= KeypairEncrypted( salt=salt, ciphertext=kp_e.ciphertext )
    assert str( kp_e2 ) == """\
{
    "ciphertext":"d211f72ba97e9cdb68d864e362935a5170383e70ea10e2307118c6d955b814918ad7e28415e2bfe66a5b34dddf12d275",
    "salt":"000000000000000000000000"
}"""

    assert kp_e.into_keypair( username=username, password=password ) \
        == kp_r.into_keypair( username=username, password=password ) \
        == kp_e2.into_keypair( username=username, password=password )

    awesome_keypair		= into_keys( awesome_sigkey )
    kp_a			= KeypairEncrypted(
        salt		= b'\x01' * 12,
        sk		= awesome_keypair[1],
        username	= username,
        password	= password
    )
    assert kp_a.into_keypair( username=username, password=password )[1] == awesome_keypair[1]

    kp_a_ser			= str( kp_a )
    assert kp_a_ser == """\
{
    "ciphertext":"aea5129b033c3072be503b91957dbac0e4c672ab49bb1cc981a8955ec01dc47280effc21092403509086caa8684003c7",
    "salt":"010101010101010101010101",
    "vk":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ=",
    "vk_signature":"yaxxz6ZxCWFdtgRF1JnK+k46UYjv650f/J1yHHf9olUpLXR/KrBOrAD71cC/dAc2FVOTqzCv1S5IXhULho2QAg=="
}"""

    # Ensure we can't even /load/ an EncryptedKeypair unless the vk_signature matches the public key!
    KeypairEncrypted(
        ciphertext	= "d211f72ba97e9cdb68d864e362935a5170383e70ea10e2307118c6d955b814918ad7e28415e2bfe66a5b34dddf12d275",
        salt		= "000000000000000000000000",
        vk		= "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
        vk_signature	= "YxRSIqHzZs5lfmWYm09wdKS8QJPSunH/Gjty/MQN5PQ3B+HkDeMtspXLWE9qbwYPGcNd1pBGaGpWAxW10l6RBg==",
    )
    KeypairEncrypted(
        ciphertext	= "aea5129b033c3072be503b91957dbac0e4c672ab49bb1cc981a8955ec01dc47280effc21092403509086caa8684003c7",
        salt		= "010101010101010101010101",
        vk		= "cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ=",
        vk_signature	= "yaxxz6ZxCWFdtgRF1JnK+k46UYjv650f/J1yHHf9olUpLXR/KrBOrAD71cC/dAc2FVOTqzCv1S5IXhULho2QAg==",
    )
    # Signature from some some other keypair:
    with pytest.raises( ValueError ) as exc_sig:
        KeypairEncrypted(
            ciphertext	= "aea5129b033c3072be503b91957dbac0e4c672ab49bb1cc981a8955ec01dc47280effc21092403509086caa8684003c7",
            salt	= "010101010101010101010101",
            vk		= "cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ=",
            vk_signature= "YxRSIqHzZs5lfmWYm09wdKS8QJPSunH/Gjty/MQN5PQ3B+HkDeMtspXLWE9qbwYPGcNd1pBGaGpWAxW10l6RBg==",
        )
    assert "Failed to verify Ed25519 pubkey cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ= signature" in str(exc_sig)


def test_KeypairEncrypted_readme():
    """Ensure providing Ed25519 Keypairs to Keypair... works."""
    username		= 'admin@awesome-inc.com'
    password		= 'password'
    auth_keypair	= None or authoring( seed=b'\xff' * 32 )  # don't supply, unless you have a random seed!
    encr_keypair	= KeypairEncrypted( auth_keypair, username=username, password=password )
    decr_keypair	= KeypairPlaintext( encr_keypair.into_keypair( username=username, password=password ))
    assert [
        [ "Plaintext:", "" ],
        [ "verifying", decr_keypair['vk'] ],
        [ "signing", decr_keypair['sk'] ],
        [ "Encrypted:" ],
        #[ "salt", encr_keypair['salt'] ],
        #[ "ciphertext", encr_keypair['ciphertext'] ],
    ] == [
        ['Plaintext:', ''],
        ['verifying', 'dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU='],
        ['signing', '//////////////////////////////////////////92oVkgRKbk9REmW8pzpgTZCwUp0d9gK+MKGakldmDR9Q=='],
        ['Encrypted:'],
        #['salt', 'ee7083c2c9a00a1635b56b75'],
        #['ciphertext', '8e428db1085442c53a4e27de3dcac84c730f4fe0c22a3fd0f81791ed9891d2e6cc402a0251c92bfbefc06f2ee881abf7']
    ]


@pytest.mark.skipif( ChaCha20Poly1305 is None, reason="Needs ChaCha20Poly1305" )
def test_KeypairEncrypted_load_keypairs():
    enduser_keypair		= authoring( seed=enduser_seed, why="from enduser seed" )
    # load just the one encrypted crypto-keypair (no glob wildcard on extension)
    (keyname,keypair_encrypted,keycred,keypair), = load_keypairs(
        extension="crypto-keypair", username=username, password=password,
        extra=[os.path.dirname( __file__ )], filename=__file__, detail=True )
    assert keycred == dict( username=username, password=password )
    assert enduser_keypair == keypair_encrypted.into_keypair( **keycred ) == keypair


def test_KeypairPlaintext_load_keypairs():
    enduser_keypair		= authoring( seed=enduser_seed, why="from enduser seed" )
    (keyname,keypair_plaintext,keycred,keypair), = load_keypairs(
        extension="crypto-keypair-plaintext",
        extra=[os.path.dirname( __file__ )], filename=__file__, detail=True )
    assert keycred == {}
    assert enduser_keypair == keypair_plaintext.into_keypair( **keycred ) == keypair


def test_License_serialization():
    # Deduce the basename from our __file__ (note: this is destructuring a 1-element sequence from a
    # generator!)
    (provname,prov), = load( extra=[os.path.dirname( __file__ )], filename=__file__, confirm=False )
    with open( os.path.join( os.path.dirname( __file__ ), "verification_test.crypto-license" )) as f:
        assert str( prov ) == f.read()


def test_License_base( monkeypatch ):
    monkeypatch.setattr( Timestamp, 'LOC', pytz.timezone( "Canada/Mountain" ))
    # Issue a License usable by any client, on any machine.  This would be suitable for the
    # "default" or "free" license for a product granting limited functionality, and might be
    # shipped along with the default installation of the software.
    confirm		= True
    try:
        lic		= License(
            author	= dict(
                domain	= "dominionrnd.com",
                name	= "Dominion Research & Development Corp.",
                product	= "Cpppo Test",
            ),
            timespan = dict(
                start	= "2021-09-30 11:22:33 Canada/Mountain",
                length	= "1y"
            ),
        )
    except (DNSException, ConnectionError) as exc:
        # No DNS; OK, let the test pass anyway.
        log.warning( "No DNS; disabling crypto-licensing DKIM confirmation for test: {}".format( exc ))
        confirm		= False
        lic		= License(
            author	= dict(
                domain	= "dominionrnd.com",
                name	= "Dominion Research & Development Corp.",
                product	= "Cpppo Test",
                pubkey	= dominion_sigkey[32:],
            ),
            timespan = dict(
                start	= "2021-09-30 11:22:33 Canada/Mountain",
                length	= "1y"
            ),
            confirm	= confirm,
        )

    lic_str		= str( lic )
    #print( lic_str )
    assert lic_str == """\
{
    "author":{
        "domain":"dominionrnd.com",
        "name":"Dominion Research & Development Corp.",
        "product":"Cpppo Test",
        "pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk="
    },
    "timespan":{
        "length":"1y",
        "start":"2021-09-30 17:22:33 UTC"
    }
}"""
    lic_digest_b64 = 'YycfaBSQH0YpY5g1X1HHYAurQFUzvzHWBQWfFk8MgNo='
    assert lic.digest('base64', 'ASCII' ) == lic_digest_b64
    if lic.digest('base64', 'ASCII' ) ==  lic_digest_b64:
        #print( repr( lic.digest() ))
        assert lic.digest() == b"c'\x1fh\x14\x90\x1fF)c\x985_Q\xc7`\x0b\xab@U3\xbf1\xd6\x05\x05\x9f\x16O\x0c\x80\xda"
        assert lic.digest('hex', 'ASCII' ) == '63271f6814901f46296398355f51c7600bab405533bf31d605059f164f0c80da'

    keypair = ed25519.crypto_sign_keypair( dominion_sigkey[:32] )
    assert keypair.sk == dominion_sigkey
    assert lic.author.pubkey == b'\xa9\x91\x11\x9e0\xd9e9\xa7\x0c\xd3I\x83\xdd\x00qBY\xf8\xb6\n!c\xbd\xb7H\xf3\xfc\x0c\xf06\xc9'
    assert codecs.getencoder( 'base64' )( keypair.vk ) == (b'qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk=\n', 32)
    prov = LicenseSigned( lic, keypair.sk, confirm=confirm )

    machine_uuid = machine_UUIDv4( machine_id_path=machine_id_path )
    assert machine_uuid.hex == "000102030405460788090a0b0c0d0e0f"
    assert machine_uuid.version == 4

    prov_str = str( prov )
    #print( prov_str )
    assert prov_str == """\
{
    "license":{
        "author":{
            "domain":"dominionrnd.com",
            "name":"Dominion Research & Development Corp.",
            "product":"Cpppo Test",
            "pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk="
        },
        "timespan":{
            "length":"1y",
            "start":"2021-09-30 17:22:33 UTC"
        }
    },
    "signature":"NF2v602UTFix78R4VO96lktZVFRGcU7PeTmRAdblUxNWtfLGBX/jfHw7ZYrvEa+QGq6amgV4eRPRJO8XXFK8Dw=="
}"""

    # Multiple licenses, some of which truncate the duration of the initial License. Non-timezone
    # timestamps are assumed to be UTC.  These are fake domains, so no confirm.
    start, length = lic.overlap(
        License( author = dict( name="A", product='a', domain='a-inc.com', pubkey=keypair.vk ), confirm=False,
                 timespan=Timespan( "2021-09-29 00:00:00",  "1w" )),
        License( author = dict( name="B", product='b', domain='b-inc.com', pubkey=keypair.vk ), confirm=False,
                 timespan=Timespan( "2021-09-30 00:00:00", "1w" )))

    # Default rendering of a timestamp is w/ milliseconds, and no tz info for UTC
    assert str( start ) == "2021-09-30 11:22:33.000 Canada/Mountain"
    assert str( length ) == "5d6h37m27s"

    # Attempt to find overlap between non-overlapping Licenses.  Uses the local timezone for
    # rendering; force by setting environment variable TZ=Canada/Mountain for this test!
    with pytest.raises( LicenseIncompatibility ) as exc_info:
        start, length = lic.overlap(
            License( author = dict( name="A", product='a', domain='a-inc.com', pubkey=keypair.vk ), confirm=False,
                     timespan=Timespan( "2021-09-29 00:00:00", "1w" )),
            License( author = dict( name="B", product='b', domain='b-inc.com', pubkey=keypair.vk ), confirm=False,
                     timespan=Timespan( "2021-10-07 00:00:00", length = "1w" )))
    assert str( exc_info.value ).endswith(
        "License for B's 'b' from 2021-10-06 18:00:00 Canada/Mountain for 1w incompatible with others" )


def test_LicenseSigned():
    """Tests Licenses derived from other License dependencies."""
    awesome_keypair = authoring( seed=awesome_sigkey[:32] )
    awesome_pubkey, _ = into_keys( awesome_keypair )

    print("Awesome, Inc. ed25519 keypair; Signing: {sk}".format( sk=binascii.hexlify( awesome_keypair.sk )))
    print("Awesome, Inc. ed25519 keypair; Public:  {pk_hex} == {pk}".format( pk_hex=into_hex( awesome_keypair.vk ), pk=into_b64( awesome_keypair.vk )))

    confirm			= True
    try:
        # If we're connected to the Internet and can check DNS, lets try to confirm that DKIM public
        # key checking works properly.  First, lets try to create a License with the *wrong* public
        # key (doesn't match DKIM record in DNS).

        with pytest.raises( LicenseIncompatibility ) as exc_info:
            License(
                author	= dict(
                    name	= "Dominion Research & Development Corp.",
                    product	= "Cpppo Test",
                    domain	= "dominionrnd.com",
                    pubkey	= awesome_pubkey,  # Purposely *wrong*; will not match cpppo-test.cpppo-licensing.. DKIM entry
                ),
                client	= dict(
                    name	= "Awesome, Inc.",
                    pubkey	= awesome_pubkey
                ),
                timespan	= Timespan( "2021-09-30 11:22:33 Canada/Mountain", "1y" ),
            )
        assert str( exc_info.value ).endswith(
            """License for Dominion Research & Development Corp.'s 'Cpppo Test': author key from DKIM qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk= != cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ=""" )

        lic			= License(
            author	= dict(
                name	= "Dominion Research & Development Corp.",
                product	= "Cpppo Test",
                domain	= "dominionrnd.com",
            ),
            client	= dict(
                name	= "Awesome, Inc.",
                pubkey	= awesome_pubkey,
            ),
            timespan	= Timespan( "2021-09-30 11:22:33 Canada/Mountain", "1y" ),
        )
    except (DNSException, ConnectionError) as exc:
        # No DNS; OK, let the test pass anyway (and indicate to future tests to not confirm)
        log.warning( "No DNS; disabling crypto-licensing DKIM confirmation for test: {}".format( exc ))
        confirm			= False
        lic			= License(
            author	= dict(
                name	= "Dominion Research & Development Corp.",
                product	= "Cpppo Test",
                domain	= "dominionrnd.com",
                pubkey	= dominion_sigkey[32:],  # This is the correct key, which matches the DKIM entry
            ),
            client	= dict(
                name	= "Awesome, Inc.",
                pubkey	= awesome_pubkey,
            ),
            timespan	= Timespan( "2021-09-30 11:22:33 Canada/Mountain", "1y" ),
            confirm	= confirm,
        )

    # Obtain a signed Cpppo license for 2021-09-30 + 1y
    lic_prov = issue( lic, dominion_sigkey, confirm=confirm )

    lic_prov_str = str( lic_prov )
    print(lic_prov_str)
    assert lic_prov.b64digest() == 'VR8vHPEOpm2d77/FM/23oUHus1NtBYiM4qSRudChyrQ='
    assert lic_prov_str == """\
{
    "license":{
        "author":{
            "domain":"dominionrnd.com",
            "name":"Dominion Research & Development Corp.",
            "product":"Cpppo Test",
            "pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk="
        },
        "client":{
            "name":"Awesome, Inc.",
            "pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ="
        },
        "timespan":{
            "length":"1y",
            "start":"2021-09-30 17:22:33 UTC"
        }
    },
    "signature":"tr2OcE1pT0tg7i+rotQJmFG8dIf8GhLtmBYxYDIshIRGKkmvAbCpuDgBKg8V0xUyaqh7OCCvlKRvvyqOEbD5DQ=="
}"""

    # Create a signing key for Awesome, Inc.; securely hide it (or, print it for everyone to see,
    # just below! ;), and publish the base-64 encoded public key as a TXT RR at:
    #
    #     ethernet-ip-tool.crypto-licensing._domainkey.awesome.com 300 IN TXT \
    #        "v=DKIM1; k=ed25519; p=PW847szICqnQBzbdr5TAoGO26RwGxG95e3Vd/M+/GZc="
    #
    enduser_keypair		= authoring( seed=enduser_seed, why="from enduser seed" )
    enduser_pubkey, enduser_sigkey = into_keys( enduser_keypair )
    print("End User, LLC ed25519 keypair; Signing: {sk}".format( sk=into_hex( enduser_keypair.sk )))
    print("End User, LLC ed25519 keypair; Public:  {pk_hex} == {pk}".format( pk_hex=into_hex( enduser_keypair.vk ), pk=into_b64( enduser_keypair.vk )))

    # Almost at the end of their annual Cpppo license, they issue a new License to End User, LLC for
    # their Awesome EtherNet/IP Tool.
    drv				= License(
        author	= dict(
            name	= "Awesome, Inc.",
            product	= "EtherNet/IP Tool",
            domain	= "awesome-inc.com",
            pubkey	= awesome_keypair.vk  # Avoid the dns.resolver.NXDOMAIN by providing the pubkey
        ),
        client = dict(
            name	= "End User, LLC",
            pubkey	= enduser_pubkey
        ),
        dependencies	= [ lic_prov ],
        timespan	= Timespan( "2022-09-29 11:22:33 Canada/Mountain", "1y" ),
        confirm		= False,  # There is no "Awesome, Inc." or awesome-inc.com ...
    )
    drv_prov = issue( drv, awesome_keypair.sk, confirm=False )
    drv_prov_str = str( drv_prov )
    # This is a license used in other tests; saved to verification_test.crypto-license and
    # licensing_test/licensing.sql.licenses.
    print(drv_prov_str)
    assert drv_prov.b64digest() == 'RTJWBCZefmYYbese4//tNmqDEaPrvMj3iqsu8lNLxLo='
    assert drv_prov_str == """\
{
    "license":{
        "author":{
            "domain":"awesome-inc.com",
            "name":"Awesome, Inc.",
            "product":"EtherNet/IP Tool",
            "pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ="
        },
        "client":{
            "name":"End User, LLC",
            "pubkey":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
        },
        "dependencies":[
            {
                "license":{
                    "author":{
                        "domain":"dominionrnd.com",
                        "name":"Dominion Research & Development Corp.",
                        "product":"Cpppo Test",
                        "pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk="
                    },
                    "client":{
                        "name":"Awesome, Inc.",
                        "pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ="
                    },
                    "timespan":{
                        "length":"1y",
                        "start":"2021-09-30 17:22:33 UTC"
                    }
                },
                "signature":"tr2OcE1pT0tg7i+rotQJmFG8dIf8GhLtmBYxYDIshIRGKkmvAbCpuDgBKg8V0xUyaqh7OCCvlKRvvyqOEbD5DQ=="
            }
        ],
        "timespan":{
            "length":"1y",
            "start":"2022-09-29 17:22:33 UTC"
        }
    },
    "signature":"NXRCa4r81zywf2Ad5SZlH3bx9yA8mBQ69RQUOqYzJW9cfN1qWnLSevV7OOnQ/jbwaejghOBRZZoy3P+oX69mBQ=="
}"""

    # Test the cpppo.crypto.licensing API, as used in applications.  A LicenseSigned is saved to an
    # <application>.crypto-license file in the Application's configuration directory path.  The
    # process for deploying an application onto a new host:
    #
    # 1) Install software to target directory
    # 2) Obtain serialized LicenseSigned containing necessary License(s)
    #    - This is normally done in a company License Server, which holds the
    #      master license and issues specialized ones up to the purchased limits (eg. 10 machines)
    # 3) Derive a new License, specialized for the host's machine-id UUID
    #    - This will be a LicenseSigned by the company License server using the company's key,
    #    - Its client_pubkey will match this software installation's private key, and machine-id UUID
    # 4) Save to <application>.crypto-license in application's config path

    # Lets specialize the license for a specific machine, and with a specific start time.  The
    # default will include the just-verified license in the resultant dependencies (ie. same as if
    # dependencies=[drv_prov] was provided)
    lic_host_dict		= verify(
        drv_prov,
        confirm		= False,
        machine_id_path	= machine_id_path,
        machine		= True,
        timespan	= Timespan( "2022-09-28 08:00:00 Canada/Mountain" ),
    )
    lic_host_dict_str = into_JSON( lic_host_dict, indent=4, default=str )
    print( lic_host_dict_str )
    assert lic_host_dict_str == """\
{
    "dependencies":[
        {
            "license":{
                "author":{
                    "domain":"awesome-inc.com",
                    "name":"Awesome, Inc.",
                    "product":"EtherNet/IP Tool",
                    "pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ="
                },
                "client":{
                    "name":"End User, LLC",
                    "pubkey":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
                },
                "dependencies":[
                    {
                        "license":{
                            "author":{
                                "domain":"dominionrnd.com",
                                "name":"Dominion Research & Development Corp.",
                                "product":"Cpppo Test",
                                "pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk="
                            },
                            "client":{
                                "name":"Awesome, Inc.",
                                "pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ="
                            },
                            "timespan":{
                                "length":"1y",
                                "start":"2021-09-30 17:22:33 UTC"
                            }
                        },
                        "signature":"tr2OcE1pT0tg7i+rotQJmFG8dIf8GhLtmBYxYDIshIRGKkmvAbCpuDgBKg8V0xUyaqh7OCCvlKRvvyqOEbD5DQ=="
                    }
                ],
                "timespan":{
                    "length":"1y",
                    "start":"2022-09-29 17:22:33 UTC"
                }
            },
            "signature":"NXRCa4r81zywf2Ad5SZlH3bx9yA8mBQ69RQUOqYzJW9cfN1qWnLSevV7OOnQ/jbwaejghOBRZZoy3P+oX69mBQ=="
        }
    ],
    "machine":"00010203-0405-4607-8809-0a0b0c0d0e0f",
    "timespan":{
        "length":"1d6h",
        "start":"2022-09-29 17:22:33 UTC"
    }
}"""

    lic_host			= License(
        author	= dict(
            name	= "End User",
            product	= "application",
            pubkey	= enduser_keypair
        ),
        confirm		= False,
        machine_id_path	= machine_id_path,
        **lic_host_dict
    )
    lic_host_prov = issue( lic_host, enduser_keypair, confirm=False, machine_id_path=machine_id_path )
    lic_host_str = str( lic_host_prov )
    #print( lic_host_str )
    assert lic_host_str == """\
{
    "license":{
        "author":{
            "name":"End User",
            "product":"application",
            "pubkey":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
        },
        "dependencies":[
            {
                "license":{
                    "author":{
                        "domain":"awesome-inc.com",
                        "name":"Awesome, Inc.",
                        "product":"EtherNet/IP Tool",
                        "pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ="
                    },
                    "client":{
                        "name":"End User, LLC",
                        "pubkey":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
                    },
                    "dependencies":[
                        {
                            "license":{
                                "author":{
                                    "domain":"dominionrnd.com",
                                    "name":"Dominion Research & Development Corp.",
                                    "product":"Cpppo Test",
                                    "pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk="
                                },
                                "client":{
                                    "name":"Awesome, Inc.",
                                    "pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ="
                                },
                                "timespan":{
                                    "length":"1y",
                                    "start":"2021-09-30 17:22:33 UTC"
                                }
                            },
                            "signature":"tr2OcE1pT0tg7i+rotQJmFG8dIf8GhLtmBYxYDIshIRGKkmvAbCpuDgBKg8V0xUyaqh7OCCvlKRvvyqOEbD5DQ=="
                        }
                    ],
                    "timespan":{
                        "length":"1y",
                        "start":"2022-09-29 17:22:33 UTC"
                    }
                },
                "signature":"NXRCa4r81zywf2Ad5SZlH3bx9yA8mBQ69RQUOqYzJW9cfN1qWnLSevV7OOnQ/jbwaejghOBRZZoy3P+oX69mBQ=="
            }
        ],
        "machine":"00010203-0405-4607-8809-0a0b0c0d0e0f",
        "timespan":{
            "length":"1d6h",
            "start":"2022-09-29 17:22:33 UTC"
        }
    },
    "signature":"hd4/vmsWK6yJc6v+X6reYWz6Q1rblGQe3Y6VLP9d1UoxsEfmfBxc8D4RIg3FH2upodgIJRx5IFc6mUBgYUrqAw=="
}"""


def test_licensing_check():
    checked			= dict(
        (into_b64( key.vk ), lic)
        for key,lic in check(
            filename=__file__, package=__package__,  # filename takes precedence
            username="a@b.c", password="passwor", confirm=False,
            machine_id_path	= machine_id_path,
            extra		= [os.path.dirname( __file__ )],
        )
    )
    assert len( checked ) == 1  # bad password, but same key is available in plaintext
    checked			= dict(
        (into_b64( key.vk ), lic)
        for key,lic in check(
            filename=__file__, package=__package__,  # filename takes precedence
            username="a@b.c", password="password", confirm=False,
            machine_id_path	= machine_id_path,
            extra		= [os.path.dirname( __file__ )],
        )
    )
    assert len( checked ) == 1
    checked_str		= into_JSON( checked, indent=4, default=str )
    #print( checked_str )
    assert checked_str == """\
{
    "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=":{
        "license":{
            "author":{
                "name":"End User, LLC",
                "pubkey":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
            },
            "dependencies":[
                {
                    "license":{
                        "author":{
                            "domain":"awesome-inc.com",
                            "name":"Awesome, Inc.",
                            "product":"EtherNet/IP Tool",
                            "pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ="
                        },
                        "client":{
                            "name":"End User, LLC",
                            "pubkey":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
                        },
                        "dependencies":[
                            {
                                "license":{
                                    "author":{
                                        "domain":"dominionrnd.com",
                                        "name":"Dominion Research & Development Corp.",
                                        "product":"Cpppo Test",
                                        "pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk="
                                    },
                                    "client":{
                                        "name":"Awesome, Inc.",
                                        "pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ="
                                    },
                                    "timespan":{
                                        "length":"1y",
                                        "start":"2021-09-30 17:22:33 UTC"
                                    }
                                },
                                "signature":"tr2OcE1pT0tg7i+rotQJmFG8dIf8GhLtmBYxYDIshIRGKkmvAbCpuDgBKg8V0xUyaqh7OCCvlKRvvyqOEbD5DQ=="
                            }
                        ],
                        "timespan":{
                            "length":"1y",
                            "start":"2022-09-29 17:22:33 UTC"
                        }
                    },
                    "signature":"NXRCa4r81zywf2Ad5SZlH3bx9yA8mBQ69RQUOqYzJW9cfN1qWnLSevV7OOnQ/jbwaejghOBRZZoy3P+oX69mBQ=="
                }
            ]
        },
        "signature":"aGPcJUI+arV24ipAWfJJxTOhLGKMG51Vzob7mhldYme+qxU/amnUgPNUKY3iqnK7jbT7BbFIx4aywUGuh9p6BQ=="
    }
}"""

    # Now, check that we can issue the license to our machine-id.  Since we don't specify a client,
    # any client Agent Keypair could sub-license this License, on that machine-id.
    checked_mach		= dict(
        (into_b64( key.vk ), lic)
        for key,lic in check(
            filename=__file__, package=__package__,  # filename takes precedence
            username="a@b.c", password="password", confirm=False,
            machine_id_path	= machine_id_path,
            extra		= [os.path.dirname( __file__ )],
            constraints		= dict(
                machine	= True,
            )
        )
    )
    assert len( checked_mach ) == 1
    checked_mach_str	= into_JSON( checked_mach, indent=4, default=str )
    print( checked_mach_str )
    assert checked_mach_str == """\
{
    "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=":{
        "license":{
            "author":{
                "name":"End User, LLC",
                "pubkey":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
            },
            "dependencies":[
                {
                    "license":{
                        "author":{
                            "domain":"awesome-inc.com",
                            "name":"Awesome, Inc.",
                            "product":"EtherNet/IP Tool",
                            "pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ="
                        },
                        "client":{
                            "name":"End User, LLC",
                            "pubkey":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
                        },
                        "dependencies":[
                            {
                                "license":{
                                    "author":{
                                        "domain":"dominionrnd.com",
                                        "name":"Dominion Research & Development Corp.",
                                        "product":"Cpppo Test",
                                        "pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk="
                                    },
                                    "client":{
                                        "name":"Awesome, Inc.",
                                        "pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ="
                                    },
                                    "timespan":{
                                        "length":"1y",
                                        "start":"2021-09-30 17:22:33 UTC"
                                    }
                                },
                                "signature":"tr2OcE1pT0tg7i+rotQJmFG8dIf8GhLtmBYxYDIshIRGKkmvAbCpuDgBKg8V0xUyaqh7OCCvlKRvvyqOEbD5DQ=="
                            }
                        ],
                        "timespan":{
                            "length":"1y",
                            "start":"2022-09-29 17:22:33 UTC"
                        }
                    },
                    "signature":"NXRCa4r81zywf2Ad5SZlH3bx9yA8mBQ69RQUOqYzJW9cfN1qWnLSevV7OOnQ/jbwaejghOBRZZoy3P+oX69mBQ=="
                }
            ],
            "machine":"00010203-0405-4607-8809-0a0b0c0d0e0f"
        },
        "signature":"YZSrREYtzPR/O/12NaH6RcKRWToINaYF6ZN1nPgmT8Cc9y7r/18hssiXKqOcA963497u7DuhftcMYd1q1AQwAA=="
    }
}"""


def test_licensing_authorized( tmp_path ):
    # Specific keys/licenses for the -authorize tests
    basename			= deduce_name(
        filename=__file__, package=__package__
    ) + '-authorize'

    # Get an agent-agnosic license for any client agent on this machine-id, from End User, LLC, good
    # for polling 10 EtherNet/IP nodes using 'ethernet-ip-tool'.  This would normally come from End
    # User, LLC's license server (which would hold End User, LLC's corporate Keypair).  This license
    # is good for any number of application agent's Keypairs running on this machine.
    username			= "a@b.c"
    password			= "password"
    checked			= dict(
        (into_b64( key.vk ) if key else None, lic)
        for key,lic in check(
            basename	= basename,
            username	= username,
            password	= password,
            confirm	= False,
            machine_id_path = machine_id_path,
            extra	= [
                os.path.dirname( __file__ )  # This test's directory
            ],
            constraints	= dict(
                machine	= True,
                grant	= {
                    "ethernet-ip-tool": dict(
                        nodes	= 10,
                    ),
                },
            ),
        )
    )
    assert len( checked ) == 1
    assert into_JSON( list(checked.values())[0], indent=4 ) == """\
{
    "license":{
        "author":{
            "name":"End User, LLC",
            "pubkey":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
        },
        "dependencies":[
            {
                "license":{
                    "author":{
                        "domain":"awesome-inc.com",
                        "name":"Awesome, Inc.",
                        "product":"EtherNet/IP Tool",
                        "pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ="
                    },
                    "client":{
                        "name":"End User, LLC",
                        "pubkey":"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
                    },
                    "dependencies":[
                        {
                            "license":{
                                "author":{
                                    "domain":"dominionrnd.com",
                                    "name":"Dominion Research & Development Corp.",
                                    "product":"Cpppo Test",
                                    "pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk="
                                },
                                "client":{
                                    "name":"Awesome, Inc.",
                                    "pubkey":"cyHOei+4c5X+D/niQWvDG5olR1qi4jddcPTDJv/UfrQ="
                                },
                                "timespan":{
                                    "length":"1y",
                                    "start":"2021-09-30 17:22:33 UTC"
                                }
                            },
                            "signature":"tr2OcE1pT0tg7i+rotQJmFG8dIf8GhLtmBYxYDIshIRGKkmvAbCpuDgBKg8V0xUyaqh7OCCvlKRvvyqOEbD5DQ=="
                        }
                    ],
                    "timespan":{
                        "length":"1y",
                        "start":"2022-09-29 17:22:33 UTC"
                    }
                },
                "signature":"NXRCa4r81zywf2Ad5SZlH3bx9yA8mBQ69RQUOqYzJW9cfN1qWnLSevV7OOnQ/jbwaejghOBRZZoy3P+oX69mBQ=="
            }
        ],
        "grant":{
            "ethernet-ip-tool":{
                "nodes":10
            }
        },
        "machine":"00010203-0405-4607-8809-0a0b0c0d0e0f"
    },
    "signature":"+NpdHBXPtgBfqph8FkW4a+otGTeCCbim+2Gst6pJ3ZuQHa8zUKJQS1Y6lBWfr7uN4AsdRd6hAZi2jynt/+tjDw=="
}"""

    # print( "Changing CWD to {}".format( tmp_path ))
    # os.chdir( str( tmp_path ))

    # Lets save the End User, LLC machine-id license in our temp. dir
    lic_machine			= LicenseSigned(
        confirm		= False,
        machine_id_path	= machine_id_path,
        **checked.popitem()[1]
    )
    machine			= lic_machine.license.machine
    lic_name			= basename + '.' + LICEXTENSION + "-enduser-{}".format( machine )
    with open( os.path.join( str( tmp_path ), lic_name ), 'wb' ) as f:
        print( "Saving our License to {}: {}".format( f.name, into_JSON( dict( lic_machine ), indent=4 ) ))
        f.write( lic_machine.serialize( indent=4 ))

    # OK, we want to get a license, issued to this dynamically generated application agent's
    # Keypair, to run Awesome, Inc's "EtherNet/IP Tool" on this machine.  We know our company, End
    # User, LLC has a license to run "EtherNet/IP Tool" on any machine, any number of times, and
    # that it was previously saved (eg. when we installed a copy of "EtherNet/IP Tool" here?)  So,
    # we should be able to find it...
    awesome_pubkey, _		= into_keys( awesome_sigkey )
    authorizations		= dict(
        (into_b64( key.vk ) if key else None, lic)
        for key, lic in authorized(
            author	= Agent(
                name	= "Awesome, Inc.",
                domain	= 'awesome-inc.com',
                product	= 'EtherNet/IP Tool',
                pubkey	= awesome_pubkey,
                confirm	= False,
            ),
            username	= username,
            password	= password,
            registering	= False,
            acquiring	= False,
            basename	= basename,
            machine_id_path = machine_id_path,
            confirm	= False,
            reverse_save = True,  # Save in most specific (instead of most general) location
            extra	= [      # config_paths and extras are always in general to specific order
                os.path.dirname( __file__ ),  # Our verification_test.crypto-keypair... file w/ O2o...2ik=
                str( tmp_path ),     # so make sure we write here first (in reverse_save)
            ],
        )
    )

    authorizations_str		= into_JSON( authorizations, indent=4, default=str )
    print( "authorized: {}".format( authorizations_str ))
    assert len( authorizations ) == 1
