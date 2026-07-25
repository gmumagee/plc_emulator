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

"""
    Implements a simple DNS-over-HTTPS (DoH) query client, via requests.
"""

import json
import logging

from enum		import Enum

import requests

from ...misc		import type_str_base, memoize, log_cfg, log_level
from ..defaults		import DOHMAXSIZE, DOHMAXAGE

log				= logging.getLogger( "DoH" )


class DoHError( RuntimeError ):
    pass


class DNSRecord( Enum ):
    A		= 1
    NS		= 2
    CNAME	= 5
    SOA		= 6
    PTR		= 12
    HINFO	= 13
    MX		= 15
    TXT		= 16
    RP		= 17
    AFSDB	= 18
    SIG		= 24
    KEY		= 25
    AAAA	= 28
    LOC		= 29
    SRV		= 33
    NAPTR	= 35
    KX		= 36
    CERT	= 37
    DNAME	= 39
    APL		= 42
    DS		= 43
    SSHFP	= 44
    IPSECKEY	= 45
    RRSIG	= 46
    NSEC	= 47
    DNSKEY	= 48
    DHCID	= 49
    NSEC3	= 50
    NSEC3PARAM	= 51
    TLSA	= 52
    SMIMEA	= 53
    HIP		= 55
    CDS		= 59
    CDNSKEY	= 60
    OPENPGPKEY	= 61
    CSYNC	= 62
    ZONEMD	= 63
    SVCB	= 64
    HTTPS	= 65
    EUI48	= 108
    EUI64	= 109
    TKEY	= 249
    TSIG	= 250
    URI		= 256
    CAA		= 257
    TA		= 32768
    DLV		= 32769


class DoH_Provider( Enum ):
    GOOGLE	= 0
    CLOUDFLARE	= 1


@memoize( maxsize=DOHMAXSIZE, maxage=DOHMAXAGE, log_at=logging.DEBUG )
def query_cached( domain, record_type, provider=None, timeout=5 ):
    if provider in ( None, DoH_Provider.GOOGLE ):
        url			= 'https://dns.google/resolve'
        #url			= 'https://8.8.8.8/resolve'
        headers			= {
            'Content-Type':  'application/x-javascript',
        }
    elif provider == DoH_Provider.CLOUDFLARE:
        url			= 'https://cloudflare-dns.com/dns-query'
        #url			= 'https://1.1.1.1/dns-query'
        headers			= {
            'Content-Type':  'application/dns-json',
        }
    else:
        raise DoHError( "Invalid DoH provider: {}".format( provider ))

    params			= dict(
        name	= domain,
        type	= record_type.value,
        ct	= headers['Content-Type'],
        do	= 'true',			# Include DNSSEC
    )

    response			= requests.get(
        url,
        params	= params,
        headers	= headers,
        timeout	= timeout,
        verify	= True,
    )

    if response.status_code != 200:
        raise DoHError( "Invalid DNS-over-HTTPS request for {}".format( response.url ))

    payload			= response.json()
    if not payload.get( 'Answer' ) or not all( a.get( 'type' ) == record_type.value for a in payload.get( 'Answer', [] )):
        raise DoHError( "Invalid DNS-over-HTTPS response from {}; missing {}{}".format(
            response.url, record_type.name, json.dumps( payload, indent=4 ) if log.isEnabledFor( logging.DEBUG ) else '' ))

    return payload['Answer']


def query( domain, record=None, provider=None, timeout=5.0 ):
    """Return a list of dicts containing the response(s) to the DNS record query.

    We assume that the domain is already properly encoded, ie. transformed from UTF-8 to punycode.

    Transform the record into a DNSRecord Enum; the first 2 args of query_cached are memoized, so
    ensure they are of the expected type.

    """
    try:
        assert isinstance( domain, type_str_base )
        # Convert a string DNS record name eg. 'TXT' to Enum DNSRecord.TXT == 16
        if isinstance( record, type_str_base ):
            record_type,	= ( t for t in DNSRecord if t.name == record )
        else:
            record_type		= record
        assert isinstance( record_type, DNSRecord )
    except Exception as exc:
        raise DoHError( "Invalid DNS-over-HTTPS record {!r}".format( record )) from exc

    return query_cached( domain, record_type, provider=provider, timeout=timeout )
