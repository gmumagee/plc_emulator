
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

import click
import json
import logging
import os

from .misc	import log_cfg, log_level, CONFIG_BASE, input_secure
from .		import licensing
from .licensing.verification import into_bytes


__author__                      = "Perry Kundert"
__email__                       = "perry@dominionrnd.com"
__copyright__                   = "Copyright (c) 2022, Dominion Research & Development Corp."
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"


log				= logging.getLogger( __package__ )


#
# Generate Agent Keypairs and Licenses
#
# --name	The name of the Keypair or License; recommend eg. Some Name ==> some-name.crypto-key
#
@click.group()
@click.option('-v', '--verbose', count=True)
@click.option('-q', '--quiet', count=True)
@click.option('-p', '--private/--no-private', default=False, help="Disclose Private Key material")
@click.option('-l', '--log-file', help="Log file name")
@click.option('-w', '--why', help="What is being done (for logging details)")
@click.option('-n', '--name', help="Defines the file name loaded/saved (default: {base})".format( base=CONFIG_BASE ))
@click.option('-r', '--reverse-save/--no-reverse-save', default=None, help="Reverse the search for saving Keypair/License files; from most specific to most general" )
@click.option('-e', '--extra', multiple=True, help="Extra config directories to use, from most general to most specific" )
def cli( verbose, quiet, private, log_file, why, name, reverse_save, extra ):
    cli.verbosity		= verbose - quiet
    log_cfg['level']		= log_level( cli.verbosity )
    if log_file:
        log_cfg['filename']	= log_file
    logging.basicConfig( **log_cfg )
    if verbose or quiet:
        logging.getLogger().setLevel( log_cfg['level'] )
    if private:
        cli.private	= True
    if why:
        cli.why		= why
    cli.name		= name or CONFIG_BASE
    if extra:
        cli.extra	= list( extra )
    if reverse_save is not None:
        cli.reverse_save = reverse_save
cli.private		= False  # noqa: E305
cli.verbosity		= 0
cli.why			= None
cli.name		= None
cli.extra		= None
cli.reverse_save	= None


@click.command()
@click.option( "--username", help="The email address (if encrypted Keypair desired))" )
@click.option( "--password", help="The password (- to read from input)" )
def check( username, password ):
    """Check for Agent ID Ed25519 Key, and any associated License(s).  If neither Keypair nor
    License(s) are found, an Exception is raised.

    If not -q, outputs JSON { <key>: [ <lic>, ...], }

    """
    username			= username or os.getenv( licensing.ENVUSERNAME )
    password			= password or os.getenv( licensing.ENVPASSWORD )
    if password == '-':
        password		= input_secure(
            "{basename} Ed25519 password: ".format( basename=cli.name ), secret=True
        )
    log.info( "Checking {why} w/ {username}: {password!r}".format(
        why		= cli.why or cli.name,
        username	= username,
        password	= '*' * len( password ) if password else password,
    ))

    i				= None
    licenses			= {}
    for i,(keypair_raw,lic) in enumerate( licensing.check(
        basename	= cli.name,
        username	= username,
        password	= password,
        extra		= cli.extra,
    )):
        if not keypair_raw:
            log.warning( "No Agent ID Keypair {name}".format( name=cli.name ))
        else:
            if cli.private:
                key		= licensing.into_hex( keypair_raw.sk )
            else:
                key 		= licensing.into_b64( keypair_raw.vk )
            licenses.setdefault( key, [] )
            if lic:
                licenses[key].append( lic )
    if cli.verbosity >= 0 and licenses:
        click.echo( licensing.into_JSON( licenses, indent=4, prefix=' ' * 4 ))
    assert licenses, \
        "Failed to find any Agent ID Keypairs or Licenses for {}".format( cli.name )


@click.command()
@click.option( "--username", help="The email address (if encrypted Keypair desired))" )
@click.option( "--password", help="The password (- to read from input)" )
@click.option( "--extension", help="A specific extension to look for" )
@click.option( "--registering/--no-registering", default=True, help="If no Keypair found, create and register a new one" )
@click.option( "--seed", help="A 32-byte (256-bit) Seed, in Hex (default: random)" )
def registered( username, password, extension, registering, seed ):
    """Determine if an Ed25519 Keypair is registered.  Locate (or create and save, by
    default) an Agent ID Ed25519 Keypair for the username and password.

    If not -q, outputs JSON "<Pubkey>" (or "<Privkey>" if --private).  If -v, the filename will also
    be output.

    If the CRYPTO_LIC_PASSWORD and/or CRYPTO_LIC_USERNAME environment variables are available, they
    will be used as default values for --username / --password.  If '-' is supplied for password, it
    will be securely read from standard input.

    """
    username			= username or os.getenv( licensing.ENVUSERNAME )
    password			= password or os.getenv( licensing.ENVPASSWORD )
    if password == '-':
        password		= input_secure(
            "{basename} Ed25519 password: ".format( basename=cli.name ), secret=True
        )
    log.info( "Registering {why} w/ {username}: {password!r}".format(
        why		= cli.why or cli.name,
        username	= username,
        password	= '*' * len( password ) if password else password,
    ))
    if seed:
        # Accept seed as either a base-64 encoded private key, or a (default) hex seed
        if seed.endswith( '=' ):
            seed		= into_bytes( seed, ('base64',) )
        else:
            if seed.lower().startswith( '0x' ):
                seed		= seed[2:]
            seed		= into_bytes( seed, ('hex',) )
    keypair			= licensing.registered(
        seed		= seed if seed else None,
        why		= cli.why or username,
        basename	= cli.name,
        extension	= extension,
        username	= username,
        password	= password,
        registering	= registering,
        reverse_save	= cli.reverse_save,
        extra		= cli.extra,
    )

    keypair_raw			= keypair.into_keypair(
        username	= username,
        password	= password,
    )

    val				= [ keypair._from ]
    if cli.verbosity >= 0:
        if cli.private:
            val.append( licensing.into_b64( keypair_raw.sk ))
        else:
            val.append( licensing.into_b64( keypair_raw.vk ))
    if cli.verbosity >= 1:
        assert cli.private or isinstance( keypair, licensing.KeypairEncrypted ), \
            "Cannot display un-encrypted Keypair without --private option"
        val.append( dict( keypair ))
    click.echo( licensing.into_JSON( val, indent=4 ))


@click.command()
@click.option( "--username", help="The email address (if encrypted Keypair))" )
@click.option( "--password", help="The password (- to read from input)" )
@click.option( "--registering/--no-registering", default=True, help="If no Keypair found, create and register a new one" )
@click.option( "--author", help="The author's name (eg. 'Awesome, Inc.', if different than authoring keypair name)" )
@click.option( "--domain", help="The company's DNS domain (eg. 'awesome.com'" )
@click.option( "--product", help="The product name, (eg. 'Awesome Product')" )
@click.option( "--service", help="The DKIM/License Grant key, (default is derived from product, eg. 'awesome-product')" )
@click.option( "--grant", help="The License's Grants (as JSON)" )
@click.option( "--dependency", multiple=True, help="Sub-license the specified License (by filename) as one of this License's dependencies" )
@click.option( "--confirm/--no-confirm", default=True, help="Confirm the signatures via DKIM (default: True)" )
@click.option( "--client", help="The client's name (eg. 'Example, Inc.'" )
@click.option( "--client-domain", help="The client's DNS domain (eg. 'example.com'" )
@click.option( "--client-pubkey", help="The client's Ed25519 Agent ID" )
def license( username, password, registering, author, domain, product, service, grant, dependency, confirm, client, client_domain, client_pubkey ):
    """Load/create an Author ID, and issue a License for a product.

    Won't overwrite existing keypair or license files.

    Appends any specified dependencies without confirming signatures.
    """
    username			= username or os.getenv( licensing.ENVUSERNAME )
    password			= password or os.getenv( licensing.ENVPASSWORD )
    if password == '-':
        password		= input_secure(
            "{basename} Ed25519 password: ".format( basename=cli.name ), secret=True
        )
    log.info( "Licensing {why} w/ {username}: {password!r}".format(
        why		= cli.why or cli.name,
        username	= username,
        password	= '*' * len( password ) if password else password,
    ))

    dependencies		= []
    for f in ( open( dep, 'r' ) for dep in dependency ):
        with f:
            prov_ser		= f.read()
            prov_dict		= json.loads( prov_ser )
            prov		= licensing.LicenseSigned( confirm=confirm, _from=f.name, **prov_dict )
            log.detail( "Dependency: {prov!r}".format( prov=prov ))
        dependencies.append( prov )

    # Locate the Agent ID Keypair to use to author the License.  Default to create if not found.
    keypair			= licensing.registered(
        why		= cli.why or product,
        basename	= cli.name,
        username	= username,
        password	= password,
        registering	= registering,
        reverse_save	= cli.reverse_save,
        extra		= cli.extra,
    )
    keypair_raw			= keypair.into_keypair(
        username	= username,
        password	= password,
    )
    if cli.private:
        key			= licensing.into_b64( keypair_raw.sk )
    else:
        key			= licensing.into_b64( keypair_raw.vk )
    log.detail( "Authoring Agent ID {what}: {key}, from {path}".format(
        what	= "Keypair" if cli.private else "Pubkey",
        key	= key,
        path	= keypair._from,
    ))

    # Issue and save (or find) the License, named after the product converted to a service name,
    # (eg. "some-service-name", the same as used for the License grant name and the DNS
    # <service>.crypto-licensing._domainkey.<domain> verification), or the specified service name,
    # or default to the Authoring keypair name (ie. in simple cases where the Authoring keypair is
    # only used for a single License and is the same as the product name)
    lic				= licensing.license(
        author		= licensing.Agent(
            name	= author or cli.name,
            domain	= domain,
            product	= product,
            service	= service or None,
            keypair	= keypair_raw,
        ),
        client		= None if not ( client or client_domain or client_pubkey ) else licensing.Agent(
            name	= client or "End-User",
            domain	= client_domain,
            pubkey	= client_pubkey
        ),
        dependencies	= dependencies,
        grant		= grant,
        why		= cli.why or product,
        basename	= licensing.domainkey_service( product ) or service or cli.name,
        confirm		= confirm,
        reverse_save	= cli.reverse_save,
        extra		= cli.extra,
    )
    log.normal( "Issued License {!r} in {}".format( lic, lic._from ))
    val				= [ lic._from ]
    if cli.verbosity >= 0:
        val.append( dict( lic ))
    click.echo( licensing.into_JSON( val, indent=4 ))


cli.add_command( registered )
cli.add_command( license )
cli.add_command( check )
