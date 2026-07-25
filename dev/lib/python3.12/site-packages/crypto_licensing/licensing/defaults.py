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

DISTRIBUTION			= 'crypto-licensing'

#
# Our core Crypto Licensing product's license information.  This
# Licences signed by this Keypair carry capabilities related to Crypto
# Licensing; eg. the ability to run a Crypto Licensing Server that may
# issue sub-licenses for your various "master" Licenses.
#
COMPANY				= "Dominion Research & Development Corp."
DOMAIN				= "dominionrnd.com"
PRODUCT				= "Crypto Licensing"
PUBKEY				= "je1DULlAfRv05GFBPWZwwt1RdRE7FyzImJeKBmH6BKE="

#
# The Crypto Licensing Server application:  python3 -m crypto_licensing.licensing
#
PRODUCT_SERVER			= "Crypto Licensing Server"
PRODUCT_SERVER_CAP_SUBLICENSES	= "sublicenses"		# How many master licenses may the Server sub-license?
PRODUCT_SERVER_CAP_FEE_TABLE	= "sublicense-fees"     # A table of sub-licensing fee thresholds
PRODUCT_SERVER_CAP_FEE_XPUB	= "sublicense-xpub"     # The X/Y/ZPublicKey to use to generate fee wallets

#
# Extensions and Globbing patterns for Agent ID Keypair, License... files
#
LICEXTENSION			= 'crypto-license'
LICPATTERN			= 'crypto-lic*'
KEYEXTENSION			= 'crypto-keypair'
KEYPATTERN			= 'crypto-key*'

#
# Environment variable names
#
ENVPASSWORD			= 'CRYPTO_LIC_PASSWORD'
ENVUSERNAME			= 'CRYPTO_LIC_USERNAME'


# How many DNS-over-HTTPS (DoH) requests should we cache?
DOHMAXSIZE			= 128
DOHMAXAGE			= 86400
