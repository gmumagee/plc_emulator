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

import warnings

# We require that at least the basic dholth/ed25519ll API must be available
__all__ = [
    'crypto_sign', 'crypto_sign_open', 'crypto_sign_keypair', 'Keypair',
    'PUBLICKEYBYTES', 'SECRETKEYBYTES', 'SIGNATUREBYTES'
]

# Get Ed25519 support. Try a globally installed ed25519ll possibly with a CTypes binding
try:
    from ed25519ll import *
except Exception: # If not installed/built correctly, may have various errors...
    # Otherwise, try our local Python-only ed25519ll derivation
    try:
        from ..ed25519ll_pyonly import *
    except ImportError:
        # Fall back to the very slow D.J.Bernstein Python reference implementation
        from ..ed25519_djb import *

# Disable warnings about seed source; we expect to provide cryptographically secure randomness
warnings.filterwarnings( action="ignore", category=RuntimeWarning, module=__name__ )
