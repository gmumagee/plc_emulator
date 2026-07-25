
#
# Crypto-licensing -- Cryptographically signed licensing, w/ Cryptocurrency payments
#
# Copyright (c) 2022, Dominion Research & Development Corp.
#
# Crypto-licensing is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.  See the LICENSE file at the top of the source tree.
#
# It is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#

import json
import logging

import click

from ...misc		import log_cfg, log_level
from .			import query

__author__                      = "Perry Kundert"
__email__                       = "perry@dominionrnd.com"
__copyright__                   = "Copyright (c) 2022 Dominion Research & Development Corp."
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"


@click.group()
@click.option('-v', '--verbose', count=True)
@click.option('-q', '--quiet', count=True)
@click.option( '--json/--no-json', default=True, help="Output JSON (the default)")
def cli( verbose, quiet, json ):
    cli.verbosity		= verbose - quiet
    log_cfg['level']		= log_level( cli.verbosity )
    logging.basicConfig( **log_cfg )
    if verbose or quiet:
        logging.getLogger().setLevel( log_cfg['level'] )
    cli.json			= json
cli.verbosity			= 0  # noqa: E305
cli.json			= False


@click.command()
@click.argument( 'domain' )
@click.argument( 'record' )
def dig( domain, record ):
    if cli.json:
        click.echo( "[", nl=cli.verbosity != 0 )
    for i,rec in enumerate( query( domain, record )):
        if cli.json:
            if i:
                click.echo( ",", nl=bool( cli.verbosity != 0 ))
            if cli.verbosity > 1:
                click.echo( "{rec}".format( rec=json.dumps( rec, indent=4 )), nl=False )
            elif cli.verbosity > 0:
                click.echo( "    {rec}".format( rec=json.dumps( rec['data'] )), nl=False )
            else:
                click.echo( "{rec}".format( rec=json.dumps( rec['data'] )), nl=False )
        else:
            if cli.verbosity > 1:
                click.echo( "{rec!r}".format( rec=rec ))
            elif cli.verbosity > 0:
                click.echo( "{rec!r}".format( rec=rec['data'] ))
            else:
                click.echo( "{rec}".format( rec=rec['data'] ))
    if cli.json:
        click.echo( "\n]" if cli.verbosity != 0 else "]" )


cli.add_command( dig )
