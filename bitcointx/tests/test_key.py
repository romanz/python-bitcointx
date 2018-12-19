# Copyright (C) 2013-2014 The python-bitcoinlib developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

# pylama:ignore=E501

import unittest

from bitcointx.core.key import CKey, CPubKey
from bitcointx.core import x


class Test_CPubKey(unittest.TestCase):
    def test(self):
        def T(hex_pubkey, is_valid, is_fullyvalid, is_compressed):
            key = CPubKey(x(hex_pubkey))
            self.assertEqual(key.is_valid, is_valid)
            self.assertEqual(key.is_fullyvalid, is_fullyvalid)
            self.assertEqual(key.is_compressed, is_compressed)

        T('', False, False, False)
        T('00', True, False, False)  # Note: deemed valid by OpenSSL for some reason
        T('01', True, False, False)
        T('02', True, False, False)

        T('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71',
          True, True, True)
        T('0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71',
          True, False, True)

        T('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71',
          True, True, True)

        T('0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455',
          True, True, False)


class Test_CKey(unittest.TestCase):
    def test(self):
        data = x('5586e3531b857c5a3d7af6d512ec84161f4531b66daf2ad72a6f647e4164c8ae')
        k = CKey(data)
        self.assertEqual(k, data)
        expected_pub = x('0392aef1ad6db10a2da4aa9f9e874fa28d5423eaa29ee83aa9acec01cc812903df')
        self.assertEqual(k.pub, expected_pub)
        expected_uncompressed_pub = x('0492aef1ad6db10a2da4aa9f9e874fa28d5423eaa29ee83aa9acec01cc812903df4c9b555eb62f0bf6dc4406b271365768737733ec8af4024809348ea594eef1f3')
        k = CKey(data, compressed=False)
        self.assertEqual(k.pub, expected_uncompressed_pub)

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            CKey(b'\x00'*32)

        with self.assertRaises(ValueError):
            CKey(b'\xff'*32)
