# Copyright (C) 2013-2015 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from __future__ import absolute_import, division, print_function, unicode_literals

import unittest

from bitcointx.core import *

class Test_str_value(unittest.TestCase):
    def test(self):
        def T(value, expected):
            actual = str_money_value(value)
            self.assertEqual(actual, expected)

        T(         0,  '0.0')
        T(         1,  '0.00000001')
        T(        10,  '0.0000001')
        T(  12345678,  '0.12345678')
        T(  10000000,  '0.1')
        T( 100000000,  '1.0')
        T(1000000000, '10.0')
        T(1010000000, '10.1')
        T(1001000000, '10.01')
        T(1012345678, '10.12345678')

class Test_Money(unittest.TestCase):
    def test_MoneyRange(self):
        self.assertFalse(MoneyRange(-1))
        self.assertTrue(MoneyRange(0))
        self.assertTrue(MoneyRange(100000))
        self.assertTrue(MoneyRange(21000000 * COIN)) # Maximum money on Bitcoin network
        self.assertFalse(MoneyRange(21000001 * COIN))

    def test_MoneyRangeCustomParams(self):
        highMaxParamsType = type(str('CoreHighMainParams'), (CoreMainParams,object), {'MAX_MONEY': 22000000 * COIN })
        highMaxParams = highMaxParamsType()
        self.assertTrue(MoneyRange(21000001 * COIN, highMaxParams))
        self.assertTrue(MoneyRange(22000000 * COIN, highMaxParams))
        self.assertFalse(MoneyRange(22000001 * COIN, highMaxParams))
