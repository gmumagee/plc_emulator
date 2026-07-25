# -*- coding: utf-8 -*-

import json
import logging
import pytest
import random

from ..misc import pytz

from dns.exception import DNSException
from requests import ConnectionError

from .verification import (
    License, LicenseSigned, authoring, issue, into_keys,
    Grant, into_Grant,
    Timespan, into_Timespan, Timestamp, into_Timestamp, into_Duration,
    LicenseIncompatibility
)

from .verification_test import (
    dominion_sigkey, awesome_sigkey, enduser_seed,
)

log				= logging.getLogger( "grant_test" )


def test_Timespan():
    timespan			= Timespan( start='2021-01-01 00:00:00 Canada/Pacific', length='1w1d1h1m1s1ms' )
    assert str(timespan) == """\
{
    "length":"1w1d1h1m1.001s",
    "start":"2021-01-01 08:00:00 UTC"
}"""
    assert float(timespan.length) == 694861.001

    for timespan in [
        '{"start": "2022-02-22 22:22:22", "length": "22w22m"}',
        {"start": "2022-02-22 22:22:22", "length": "22w22m"},
        [("start", "2022-02-22 22:22:22"), ("length", "22w22m")],
    ]:
        assert str( into_Timespan( timespan )) == """\
{
    "length":"22w22m",
    "start":"2022-02-22 22:22:22 UTC"
}"""


def test_Timespan_in():
    start			= into_Timestamp( '2021-01-01 00:00:00 Canada/Pacific' )
    length			= into_Duration( '1w1d1h1m1s1ms' )
    timespan			= Timespan( start, length )

    assert timespan in timespan

    assert timespan in Timespan( None, None )				# The for-all-time perpetual
    assert Timespan( None, None ) not in timespan

    assert timespan in Timespan( timespan.start, None )			# The from-a-time perpetual
    assert Timespan( start, None ) not in timespan

    assert timespan not in Timespan( start + 1, None )
    assert timespan in Timespan( start - 1, None )

    assert timespan in Timespan( start, length + 1 )
    assert timespan in Timespan( start - 1, length + 1 )
    assert timespan not in Timespan( start - 2, length + 1 )
    assert timespan in Timespan( start - 2, length + 2 )
    assert timespan not in Timespan( start, length - 1 )


def test_Timespan_intersection():
    # Note: Assumes TZ="Canada/Mountain"  TODO: remove this assumption to pytest runs cleanly w/ TZ=... in env
    start			= into_Timestamp( '2021-01-01 00:00:00 Canada/Pacific' )
    mountain			= pytz.timezone( 'Canada/Mountain' )
    assert start.render( tzinfo=mountain ) == '2021-01-01 01:00:00.000 Canada/Mountain'
    assert ( start - '1h1m' ).render( tzinfo=mountain ) == '2020-12-31 23:59:00.000 Canada/Mountain'
    #assert repr( timespan ) == "<Timespan('2021-01-01 01:00:00.000 Canada/Mountain','1w1d1h1m1.001s')>"

    for i,(q,a) in enumerate(set([  # also tests __hash__ from SHA-256 digest of serialization
        (
            (
                Timespan( None, None ),
            ),
            Timespan()
        ),
        (
            (
                Timespan( Timestamp( 0 ), None ),
                Timespan( Timestamp( 0 ), '0s' ),
            ),
            Timespan( Timestamp( 0 ), '0s' ),
        ),
        (
            (
                Timespan( start='2021-01-01 00:00:00 Canada/Pacific', length='1w' ),
            ),
            Timespan( start='2021-01-01 00:00:00 Canada/Pacific', length='1w' )
        ),
        (
            (
                Timespan(start - '1s', '1d' ),
                Timespan(start, '1d1m' ),
            ),
            Timespan( start, '23h59m59s' )
        ),
        (
            (
                Timespan(start - '1s', '1d' ),
                Timespan(start, '1d1m' ),
                Timespan(start + '23h', '1d1m' ),
            ),
            Timespan( start + '23h', '59m59s' )
        ),
        (
            (
                Timespan(start - '1s', '1d' ),
                Timespan(start, '1d1m' ),
                Timespan(start + '23h', '1d1m' ),
                Timespan(start + '23h59m58s', '1d1m' ),
            ),
            Timespan( start + '23h59m58s', '1s' )
        ),
    ])):
        print( "Intersection of: \n    {} should equal \n==> {}".format( '\n    '.join( map( repr, q )), repr( a )))
        qr			= Timespan().intersection( *q )
        print( "--> {}".format( repr( qr ) ))
        assert repr( qr ) == repr( a )


def test_Timespan_add():
    start			= into_Timestamp( '2021-01-01 00:00:00 Canada/Pacific' )
    for i,(f,s,a) in enumerate(set([  # also tests __hash__ from SHA-256 digest of serialization
        (
            Timespan(),
            Timespan(),
            Timespan(),
        ),
        (
            Timespan( start, '1s' ),
            Timespan( start + '1s', '1s' ),  # Adjacent
            Timespan( start, '2s'),
        ),
        (
            Timespan( start, '1s' ),
            Timespan( start + '1s', None ),  # Adjacent, perpetual
            Timespan( start, None),
        ),
        (
            Timespan( start, '1s' ),
            Timespan( start + '2s', '1s' ),  # not adjacent; 1 second away
            Timespan( start, '1s'),
        ),
        (
            Timespan( start + '2s', '1s' ),  # not adjacent; 1 second away
            Timespan( start, '1s' ),
            Timespan( start + '2s', '1s'),
        ),
        (
            Timespan('2021-01-01 08:00:00.000','1w1d1h1m1.001s'),
            Timespan('2021-01-09 09:01:01.001','2s'),
            Timespan('2021-01-01 08:00:00.000','1w1d1h1m3.001s'),
        ),
    ])):
        print( "Addition of:\n    {}\n  + {} should equal \n==> {}".format( repr( f ), repr( s ), repr( a )))
        fs			= f + s
        print( "--> {}".format( repr( fs )))
        assert repr( fs ) == repr( a )


def test_Timespan_union():
    start			= into_Timestamp( '2021-01-01 00:00:00 Canada/Pacific' )
    length			= into_Duration( '1w1d1h1m1s1ms' )
    for i,(f,q,a) in enumerate(set([  # also tests __hash__ from SHA-256 digest of serialization
        (
            Timespan( None, None ),
            (
                Timespan( None, None ),
            ),
            Timespan()
        ),
        (
            Timespan( Timestamp( 2 ), None ),
            (
                Timespan( Timestamp( 3 ), None ),
            ),
            Timespan( Timestamp( 2 ), None )
        ),
        (
            Timespan( start, length ),
            (
                Timespan( start + length - '1s', '2s' ),   # Overlappping by 1s at end
            ),
            Timespan( start, length + '1s' ),
        ),
        (
            Timespan( start, length ),
            (
                Timespan( start + length, '2s' ),		# Adjacent at end
            ),
            Timespan( start, length + '2s' ),
        ),
        (
            Timespan('2021-01-01 08:00:00.000','1w1d1h1m1.001s'),
            (
                Timespan('2021-01-09 09:01:01.001','2s'),
            ),
            Timespan('2021-01-01 08:00:00.000','1w1d1h1m3.001s'),
        ),
        # (
        #     Timespan( start, length ),
        #     (
        #         Timespan( start + length + '0s', '1s' ),   # Adjacent at end in multiple segments
        #         Timespan( start + length + '1s', '1s' ),
        #         Timespan( start + length + '2s', '1s' ),
        #         Timespan( start + length + '3s', '1s' ),
        #         Timespan( start + length + '4s', '1s' ),
        #         Timespan( start + length + '5s', '1s' ),
        #         Timespan( start + length + '6s', '1s' ),
        #         Timespan( start + length + '7s', '1s' ),
        #         Timespan( start + length + '8s', '1s' ),
        #         Timespan( start + length + '9s', '1s' ),
        #     ),
        #     Timespan( start, length + '10s' ),
        # ),
        # (
        #     Timespan( start, length ),
        #     (
        #         Timespan( start + length + '1s', '2s' ),   # Missed by 1s at end (no union)
        #     ),
        #     Timespan( start, length ),
        # ),
    ])):
        print( "Union of:\n    {} w/ \n    {} should equal \n==> {}".format( repr( f ), '\n    '.join( map( repr, q )), repr( a )))
        qr			= f.union( *q )
        print( "--> {}".format( repr( qr ) ))
        assert repr( qr ) == repr( a )
        # And, any random permutation of f and the qs should yield the identical union
        ql			= list( ( f, ) + q )
        for i in range( len( q )):
            random.shuffle( ql )
            qr			= ql[0].union( *ql[1:] )
            print( "--> {}".format( repr( qr ) ))
            assert repr( qr ) == repr( a ), \
                "Union of:\n    {} w/ \n    {} should equal \n==> {}".format( repr( ql[0] ), '\n    '.join( map( repr, ql[1:] )), repr( a ))


def test_Grant_smoke():
    lic_cpppo_test		= LicenseSigned( **json.loads('''{
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
    }''' ))

    for CpppoTest in [
            dict( Hz = 1000 ),
            Grant( Hz = 1000, _from=lic_cpppo_test ),
    ]:
        grant			= Grant(
            { 'cpppo-test': CpppoTest }
        )

        assert len( list( grant.vars() )) == 1
        assert tuple( grant.keys() ) == ('cpppo-test', )
        #assert not grant.empty()
        grant_str			= str( grant )
        #print( grant_str )
        assert grant_str == """\
{
    "cpppo-test":{
        "Hz":1000
    }
}"""
        assert grant.serialize(encoding=None) == '{"cpppo-test":{"Hz":1000}}'
        assert Grant().empty()
        assert not grant.empty()

        assert grant.merge( 'cpppo-test', 'Hz', 100, style=Grant.Merging.REFINING ) == 100
        with pytest.raises( LicenseIncompatibility ) as exc_info:
            grant.merge( 'cpppo-test', 'Hz', None, style=Grant.Merging.REFINING )
        assert "exceeds limit: 1000" in str( exc_info )

        # Confirm that trees of "empty" Grants are empty.  By default, if a serialization would be
        # empty, the Grant should be considered empty.
        still_empty		= Grant( sub_grant = Grant( yet_empty = None, _from = lic_cpppo_test ))
        assert still_empty.empty() is True


def test_Grant_grants():
    grant100			= {
        'cpppo-test': dict(
            Hz		= 100,
        ),
    }
    grant200			= {
        'cpppo-test': dict(
            Hz		= 200,
        ),
    }

    confirm		= True
    try:
        lic1			= License(
            author	= dict(
                domain	= "dominionrnd.com",
                name	= "Dominion Research & Development Corp.",
                product	= "Cpppo Test",
            ),
            grant	= grant100,
            timespan = dict(
                start	= "2021-09-30 11:22:33 Canada/Mountain",
                length	= "1y"
            ),
        )
    except (DNSException, ConnectionError) as exc:
        # No DNS; OK, let the test pass anyway.
        log.warning( "No DNS; disabling crypto-licensing DKIM confirmation for test: {}".format( exc ))
        confirm		= False
        lic1			= License(
            author	= dict(
                domain	= "dominionrnd.com",
                name	= "Dominion Research & Development Corp.",
                product	= "Cpppo Test",
                pubkey	= dominion_sigkey[32:],
            ),
            grant	= grant100,
            timespan = dict(
                start	= "2021-09-30 11:22:33 Canada/Mountain",
                length	= "1y"
            ),
            confirm	= confirm,
        )

    confirm		= True
    try:
        lic2			= License(
            author	= dict(
                domain	= "dominionrnd.com",
                name	= "Dominion Research & Development Corp.",
                product	= "Cpppo Test",
            ),
            grant	= grant200,
            timespan = dict(
                start	= "2021-09-30 11:22:33 Canada/Mountain",
                length	= "1y"
            ),
        )
    except (DNSException, ConnectionError) as exc:
        # No DNS; OK, let the test pass anyway.
        log.warning( "No DNS; disabling crypto-licensing DKIM confirmation for test: {}".format( exc ))
        confirm		= False
        lic2			= License(
            author	= dict(
                domain	= "dominionrnd.com",
                name	= "Dominion Research & Development Corp.",
                product	= "Cpppo Test",
                pubkey	= dominion_sigkey[32:],
            ),
            grant	= grant200,
            timespan = dict(
                start	= "2021-09-30 11:22:33 Canada/Mountain",
                length	= "1y"
            ),
            confirm	= confirm,
        )

    lic2_str			= str( lic2 )
    #print( lic2_str )
    assert lic2_str == """\
{
    "author":{
        "domain":"dominionrnd.com",
        "name":"Dominion Research & Development Corp.",
        "product":"Cpppo Test",
        "pubkey":"qZERnjDZZTmnDNNJg90AcUJZ+LYKIWO9t0jz/AzwNsk="
    },
    "grant":{
        "cpppo-test":{
            "Hz":200
        }
    },
    "timespan":{
        "length":"1y",
        "start":"2021-09-30 17:22:33 UTC"
    }
}"""

    lic1_prov			= issue( lic1, dominion_sigkey, confirm=confirm )
    lic1_grants			= lic1_prov.grants()

    #print( str( lic1_prov.license.grant ) )
    assert str( lic1_prov.license.grant ) == """\
{
    "cpppo-test":{
        "Hz":100
    }
}"""
    #print( str( lic1_grants ) )
    assert str( lic1_grants ) == """\
{
    "cpppo-test":{
        "Hz":100
    }
}"""

    lic2_prov			= issue( lic2, dominion_sigkey, confirm=confirm )
    lic2_grants			= lic2_prov.grants()

    #print( str( lic2_grants ) )
    assert str( lic2_grants ) == """\
{
    "cpppo-test":{
        "Hz":200
    }
}"""
    assert lic1_grants['cpppo-test']._from == lic1_prov.license.author
    assert lic2_grants['cpppo-test']._from == lic2_prov.license.author

    # Confirm that combining grants works
    lic1_comb			= lic1_prov.grants()
    lic1_comb		       |= lic2_grants
    #print( str( lic1_comb ))
    assert str( lic1_comb) == """\
{
    "cpppo-test":{
        "Hz":300
    }
}"""

    # Confirm that refining grants works
    lic1_refi			= lic1_prov.grants()
    with pytest.raises( LicenseIncompatibility ) as exc_info:
        lic1_refi	       &= lic2_grants
    assert "200 exceeds limit: 100" in str( exc_info )

    lic2_refi			= lic2_prov.grants()
    lic2_refi		       &= lic1_grants
    #print( str( lic2_refi ) )
    assert str( lic2_refi ) == """\
{
    "cpppo-test":{
        "Hz":100
    }
}"""

    # Check that the same License' Grants aren't included multiple times
    awesome_keypair		= authoring( seed=awesome_sigkey[:32] )
    awesome_pubkey,_		= into_keys( awesome_keypair )
    enduser_keypair		= authoring( seed=enduser_seed, why="from enduser seed" )
    enduser_pubkey,_		= into_keys( enduser_keypair )
    drv_dup			= License(
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
        dependencies	= [ lic1_prov, lic1_prov ],
        timespan	= Timespan( "2022-09-29 11:22:33 Canada/Mountain", "1y" ),
        confirm		= False,  # There is no "Awesome, Inc." or awesome-inc.com ...
    )

    assert drv_dup.grants()['cpppo-test']['Hz'] == 100

    # No matter how many times the same dependencies License Grants are supplied, they only apply once.
    #drv_dup_prov		= issue( drv_dup, awesome_keypair, confirm=False )
    drv_two			= License(
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
        dependencies	= [ lic1_prov, lic2_prov ],
        timespan	= Timespan( "2022-09-29 11:22:33 Canada/Mountain", "1y" ),
        confirm		= False,  # There is no "Awesome, Inc." or awesome-inc.com ...
    )

    # This license passes through the dependencies' Grants unmollested
    assert drv_two.grants()['cpppo-test']['Hz'] == 300
    assert drv_two.grants()['cpppo-test']._from == lic1_prov.license.author

    grant10			= {
        'cpppo-test': dict(
            Hz		= 10,
        ),
    }
    grant1000			= {
        'cpppo-test': dict(
            Hz		= 1000,
        ),
    }

    # Derive a License with a Grant within what is supplied by the dependencies.  This one refines
    # the Grants, but their source remains the original author of the Grant.
    drv_sub			= License(
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
        grant		= grant10 | { "awesome": { "something": 123 }},
        dependencies	= [ lic1_prov, lic2_prov ],
        timespan	= Timespan( "2022-09-29 11:22:33 Canada/Mountain", "1y" ),
        confirm		= False,  # There is no "Awesome, Inc." or awesome-inc.com ...
    )

    assert str(drv_sub.grants()) == """{
    "awesome":{
        "something":123
    },
    "cpppo-test":{
        "Hz":10
    }
}"""
    assert drv_sub.grants()._from is None
    assert drv_sub.grants()['awesome']._from == drv_sub.author
    assert drv_sub.grants()['cpppo-test']['Hz'] == 10
    assert drv_sub.grants()['cpppo-test']._from == lic1_prov.license.author

    assert str(Grant( **grant10 )) == """{
    "cpppo-test":{
        "Hz":10
    }
}"""

    assert lic1_prov.grants() <= lic2_prov.grants()

    def make_Grant( **kwds ):
        return Grant( **dict( (k, into_Grant( v, _from=k )) for k,v in kwds.items() ))

    assert make_Grant( **grant10 )	<= make_Grant( **grant1000 )
    assert make_Grant( **grant10 )	<= make_Grant( **grant10 )
    assert not ( make_Grant( **grant1000 ) <= make_Grant( **grant10 ))
    assert make_Grant( **grant1000 )	<= make_Grant( **grant1000 )
    assert make_Grant( **grant1000 )	<= make_Grant( something = dict( good = 1 ), **grant1000 )
    assert make_Grant( **grant10 )	<= make_Grant( something = dict( good = 1 ), **grant1000 )
    assert not ( make_Grant( something = dict( good = 1 ), **grant1000 ) <= make_Grant( **grant1000 ))

    # Try to derive a License with a Grant exceeding what the dependencies supply
    with pytest.raises( LicenseIncompatibility ) as exc_info:
        License(
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
            grant	= grant1000,  # Too much
            dependencies = [ lic1_prov, lic2_prov ],
            timespan	= Timespan( "2022-09-29 11:22:33 Canada/Mountain", "1y" ),
            confirm	= False,  # There is no "Awesome, Inc." or awesome-inc.com ...
        )
    assert "1000 exceeds limit: 300" in str( exc_info )
