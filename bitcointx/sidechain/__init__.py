# Copyright (C) 2018 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

# You need to add sidechain names here after
# you placed the <sidechain_name>.py module
# in sidechain/ dir
SUPPORTED_SIDECHAINS = ('elements',)

import sys
from importlib import import_module


def GetChainParams(name):
    assert name.startswith('sidechain/')
    sc_name = name.split('/', maxsplit=1)[1]

    if sc_name not in SUPPORTED_SIDECHAINS:
        raise ValueError('Unknown sidechain {}'.format(name))

    mname = 'bitcointx.sidechain.{}'.format(sc_name)
    import_module(mname)
    coreparams, params = sys.modules[mname].GetChainParams(name)
    assert coreparams.NAME == name
    return (coreparams, params)

__all__ = ('GetAlternativeParams')
