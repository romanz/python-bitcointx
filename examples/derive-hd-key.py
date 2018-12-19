#!/usr/bin/env python3
#
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

import os
import sys
from bitcointx.core import b2x, BIP32_HARDENED_KEY_LIMIT
from bitcointx.base58 import Base58Error, UnexpectedBase58PrefixError
from bitcointx.wallet import CBitcoinExtKey, CBitcoinExtPubKey

if __name__ == '__main__':
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("usage: {} <derivation_path> [xpriv_or_xpub]"
              .format(sys.argv[0]))
        sys.exit(-1)

    if len(sys.argv) == 2:
        xkey = CBitcoinExtKey.from_seed(os.urandom(32))
        print("generated xpriv: ", xkey)
    else:
        for cls in (CBitcoinExtKey, CBitcoinExtPubKey):
            try:
                xkey = cls(sys.argv[2])
                break
            except UnexpectedBase58PrefixError:
                pass
            except Base58Error:
                print("ERROR: specified key is incorrectly encoded")
                sys.exit(-1)
            except ValueError:
                pass
        else:
            print("ERROR: specified key does not appear to be valid")
            sys.exit(-1)

    path = sys.argv[1]
    if path.startswith('m'):
        path = path[1:]

    numeric_path = []
    for elt in path.split('/'):
        if elt == '':
            continue

        c = elt
        hardened = 0
        if c.endswith("'") or c.endswith('h'):
            hardened = BIP32_HARDENED_KEY_LIMIT
            c = c[:-1]
        try:
            n = int(c) + hardened
        except ValueError:
            print("ERROR: invalid element in the path:", elt)
            sys.exit(-1)

        print("child number: 0x{:08x}".format(n))
        xkey = xkey.derive(n)
        if isinstance(xkey, CBitcoinExtKey):
            print("xpriv:", xkey)

            # Note:
            # if xkey is CBitcoinExtKey, xkey.priv is CBitcoinSecret
            #     CBitcoinSecret is in WIF format, and compressed
            #     len(bytes(xkey.privkey)) == 33
            # if xkey is CExtKey, xkey.priv is CKey
            #     CKey is always 32 bytes
            #
            # Standalone CBitcoinSecret key can be uncompressed,
            # and be of 32 bytes length, but this is not the case
            # with xpriv encapsulated in CBitcoinExtKey - it is
            # always compressed there.
            #
            # you can always use xkey.priv.secret_bytes
            # to get raw 32-byte secret data from both CBitcoinSecret and CKey
            #
            print("priv WIF:", xkey.priv)
            print("raw priv:", b2x(xkey.priv.secret_bytes))

            print("xpub: ", xkey.neuter())
            print("pub:", b2x(xkey.pub))
        else:
            assert isinstance(xkey, CBitcoinExtPubKey)
            print("xpub:", xkey)
            print("pub:", b2x(xkey.pub))
