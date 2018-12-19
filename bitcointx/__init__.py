# Copyright (C) 2012-2018 The python-bitcoinlib developers
# Copyright (C) 2018 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import sys
import bitcointx.core

# Note that setup.py can break if __init__.py imports any external
# dependencies, as these might not be installed when setup.py runs. In this
# case __version__ could be moved to a separate version.py and imported here.
__version__ = '0.10.4.dev0'


class _ParamsTag():
    pass


class MainParams(bitcointx.core.CoreMainParams, _ParamsTag):
    RPC_PORT = 8332
    BASE58_PREFIXES = {'PUBKEY_ADDR':0,
                       'SCRIPT_ADDR':5,
                       'SECRET_KEY' :128,
                       'EXTENDED_PUBKEY': b'\x04\x88\xB2\x1E',
                       'EXTENDED_PRIVKEY': b'\x04\x88\xAD\xE4'}
    BECH32_HRP = 'bc'


class ElementsSidechainParams(bitcointx.core.CoreElementsSidechainParams, _ParamsTag):
    RPC_PORT = 7041
    BASE58_PREFIXES = {'PUBKEY_ADDR' : 235,
                       'SCRIPT_ADDR' : 75,
                       'CONFIDENTIAL_ADDR': b'\x04',
                       'CONFIDENTIAL_PUBKEY_ADDR': b'\x04\xEB',
                       'CONFIDENTIAL_SCRIPT_ADDR': b'\x04\x4B',

                       # Note: these are the same as for Bitcoin testnet
                       'SECRET_KEY'  : 239,
                       'EXTENDED_PUBKEY': b'\x04\x35\x87\xCF',
                       'EXTENDED_PRIVKEY': b'\x04\x35\x83\x94'}

    BECH32_HRP = None


class TestNetParams(bitcointx.core.CoreTestNetParams, _ParamsTag):
    RPC_PORT = 18332
    BASE58_PREFIXES = {'PUBKEY_ADDR':111,
                       'SCRIPT_ADDR':196,
                       'SECRET_KEY' :239,
                       'EXTENDED_PUBKEY': b'\x04\x35\x87\xCF',
                       'EXTENDED_PRIVKEY': b'\x04\x35\x83\x94'}
    BECH32_HRP = 'tb'


class RegTestParams(bitcointx.core.CoreRegTestParams, _ParamsTag):
    RPC_PORT = 18443
    BASE58_PREFIXES = {'PUBKEY_ADDR':111,
                       'SCRIPT_ADDR':196,
                       'SECRET_KEY' :239,
                       'EXTENDED_PUBKEY': b'\x04\x35\x87\xCF',
                       'EXTENDED_PRIVKEY': b'\x04\x35\x83\x94'}
    BECH32_HRP = 'bcrt'

"""Master global setting for what chain params we're using.

However, don't set this directly, use SelectParams() instead so as to set the
bitcointx.core.params correctly too.
"""

params = MainParams()


def SelectAlternativeParams(alt_core_params, alt_main_params):
    """Select alternative chain parameters to use

    alt_core_params should be a subclass of core.CoreChainParams,
    but redefine all fields

    alt_main_params should be a subclass of alt_core_params,
    and define all fields that are defined in MainParams

    """
    global params

    bitcointx.core._SelectAlternativeCoreParams(alt_core_params)

    assert(issubclass(alt_main_params, alt_core_params))

    params = alt_main_params()

    if 'bitcointx.wallet' in sys.modules:
        bitcointx.wallet._SetBase58Prefixes()


def SelectParams(name):
    """Select the chain parameters to use

    name is one of 'mainnet', 'testnet', or 'regtest'

    Default chain is 'mainnet'
    """
    global params

    bitcointx.core._SelectCoreParams(name)

    for cls in _ParamsTag.__subclasses__():
        if name == cls.NAME:
            params = cls()
            break
    else:
        raise ValueError('Unknown chain %r' % name)

    if 'bitcointx.wallet' in sys.modules:
        bitcointx.wallet._SetBase58Prefixes()
