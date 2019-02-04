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

# pylama:ignore=E501

import unittest

import bitcointx
from bitcointx.core import x
from bitcointx.wallet import (
    CBitcoinAddress, P2PKHBitcoinAddress
)
from bitcointx.sidechain.elements import P2PKHConfidentialAddress


class Test_ConfidentialAddress(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._prev_chain = bitcointx.params.NAME
        bitcointx.SelectParams('sidechain/elements')

    @classmethod
    def tearDownClass(cls):
        bitcointx.SelectParams(cls._prev_chain)

    def test(self):

        def T(confidential_addr, expected_bytes, unconfidential_addr, expected_blinding_pubkey,
              expected_class, expected_unconfidential_class):
            a = CBitcoinAddress(confidential_addr)
            self.assertEqual(a.to_bytes(), expected_bytes)
            self.assertEqual(unconfidential_addr, str(a.to_unconfidential()))
            self.assertEqual(expected_blinding_pubkey, a.blinding_pubkey)
            self.assertIsInstance(a, expected_class)

        T('CTEp1wviJ6U7SdAAs5sRJ1NzzRzAbmQGt1veiswjWrkzv98W7UJMQjBccafpS6v9w6evWTqeLsGc7TC1',
          x('029ffb47606c3d672a3429d91650960c63ff7d8f8ff9e00b4a8e3430c6549b4cc83422fe11c415bb9c8618f9d8498d9ad945056bdb'),
          '2deBRSp69HSsJ5WAegsaksoWj8PfaQ2PqDd',
          x('029ffb47606c3d672a3429d91650960c63ff7d8f8ff9e00b4a8e3430c6549b4cc8'),
          P2PKHConfidentialAddress, P2PKHBitcoinAddress)
