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

import json
import unittest
import os

from bitcointx.core import (
    x, lx, b2x,
    CTransaction, CMutableTransaction, COutPoint, CMutableOutPoint,
    CTxIn, CTxOut, CMutableTxIn, CMutableTxOut,
    CTxWitness, CTxInWitness,
    CMutableTxWitness, CMutableTxInWitness,
    CheckTransaction, CheckTransactionError, ValidationError
)
from bitcointx.core.script import CScript, CScriptWitness
from bitcointx.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH

from bitcointx.tests.test_scripteval import parse_script


def load_test_vectors(name):
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        for test_case in json.load(fd):
            # Comments designated by single length strings
            if len(test_case) == 1:
                continue
            assert len(test_case) == 3

            prevouts = {}
            for json_prevout in test_case[0]:
                assert len(json_prevout) == 3
                n = json_prevout[1]
                if n == -1:
                    n = 0xffffffff
                prevout = COutPoint(lx(json_prevout[0]), n)
                prevouts[prevout] = parse_script(json_prevout[2])

            tx_data = x(test_case[1])
            tx = CTransaction.deserialize(tx_data)
            enforceP2SH = test_case[2]

            yield (prevouts, tx, tx_data, enforceP2SH)


class Test_COutPoint(unittest.TestCase):
    def test_is_null(self):
        self.assertTrue(COutPoint().is_null())
        self.assertTrue(COutPoint(hash=b'\x00'*32,n=0xffffffff).is_null())
        self.assertFalse(COutPoint(hash=b'\x00'*31 + b'\x01').is_null())
        self.assertFalse(COutPoint(n=1).is_null())

    def test_repr(self):
        def T(outpoint, expected):
            actual = repr(outpoint)
            self.assertEqual(actual, expected)
        T( COutPoint(),
          'COutPoint()')
        T( COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0),
          "COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0)")

    def test_str(self):
        def T(outpoint, expected):
            actual = str(outpoint)
            self.assertEqual(actual, expected)
        T(COutPoint(),
          '0000000000000000000000000000000000000000000000000000000000000000:4294967295')
        T(COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0),
                       '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:0')
        T(COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 10),
                       '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:10')

    def test_immutable(self):
        """COutPoint shall not be mutable"""
        outpoint = COutPoint()
        with self.assertRaises(AttributeError):
            outpoint.n = 1


class Test_CMutableOutPoint(unittest.TestCase):
    def test_GetHash(self):
        """CMutableOutPoint.GetHash() is not cached"""
        outpoint = CMutableOutPoint()

        h1 = outpoint.GetHash()
        outpoint.n = 1

        self.assertNotEqual(h1, outpoint.GetHash())

    def test_repr(self):
        def T(outpoint, expected):
            actual = repr(outpoint)
            self.assertEqual(actual, expected)
        T( CMutableOutPoint(),
          'CMutableOutPoint()')
        T( CMutableOutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0),
          "CMutableOutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0)")


class Test_CTxIn(unittest.TestCase):
    def test_is_final(self):
        self.assertTrue(CTxIn().is_final())
        self.assertTrue(CTxIn(nSequence=0xffffffff).is_final())
        self.assertFalse(CTxIn(nSequence=0).is_final())

    def test_repr(self):
        def T(txin, expected):
            actual = repr(txin)
            self.assertEqual(actual, expected)
        T( CTxIn(),
          'CTxIn(COutPoint(), CScript([]), 0xffffffff)')

    def test_immutable(self):
        """CTxIn shall not be mutable"""
        txin = CTxIn()
        with self.assertRaises(AttributeError):
            txin.nSequence = 1

class Test_CMutableTxIn(unittest.TestCase):
    def test_GetHash(self):
        """CMutableTxIn.GetHash() is not cached"""
        txin = CMutableTxIn()

        h1 = txin.GetHash()
        txin.prevout.n = 1

        self.assertNotEqual(h1, txin.GetHash())

    def test_repr(self):
        def T(txin, expected):
            actual = repr(txin)
            self.assertEqual(actual, expected)
        T( CMutableTxIn(),
          'CMutableTxIn(CMutableOutPoint(), CScript([]), 0xffffffff)')


class Test_CTransaction(unittest.TestCase):
    def test_is_coinbase(self):
        tx = CMutableTransaction()
        self.assertFalse(tx.is_coinbase())

        tx.vin.append(CMutableTxIn())

        # IsCoinBase() in reference client doesn't check if vout is empty
        self.assertTrue(tx.is_coinbase())

        tx.vin[0].prevout.n = 0
        self.assertFalse(tx.is_coinbase())

        tx.vin[0] = CTxIn()
        tx.vin.append(CTxIn())
        self.assertFalse(tx.is_coinbase())

    def test_tx_valid(self):
        for prevouts, tx, tx_data, enforceP2SH in load_test_vectors('tx_valid.json'):
            self.assertEqual(tx_data, tx.serialize())
            self.assertEqual(tx_data, CTransaction.deserialize(tx.serialize()).serialize())
            try:
                CheckTransaction(tx)
            except CheckTransactionError:
                self.fail('tx failed CheckTransaction(): ' \
                        + str((prevouts, b2x(tx.serialize()), enforceP2SH)))
                continue

            for i in range(len(tx.vin)):
                flags = set()
                if enforceP2SH:
                    flags.add(SCRIPT_VERIFY_P2SH)

                VerifyScript(tx.vin[i].scriptSig, prevouts[tx.vin[i].prevout], tx, i, flags=flags)

    def test_tx_invalid(self):
        for prevouts, tx, _, enforceP2SH in load_test_vectors('tx_invalid.json'):
            try:
                CheckTransaction(tx)
            except CheckTransactionError:
                continue

            with self.assertRaises(ValidationError):
                for i in range(len(tx.vin)):
                    flags = set()
                    if enforceP2SH:
                        flags.add(SCRIPT_VERIFY_P2SH)

                    VerifyScript(tx.vin[i].scriptSig, prevouts[tx.vin[i].prevout], tx, i, flags=flags)

    def test_immutable(self):
        tx = CTransaction()
        self.assertFalse(tx.is_coinbase())

        with self.assertRaises(AttributeError):
            tx.nVersion = 2
        with self.assertRaises(AttributeError):
            tx.vin.append(CTxIn())

        mtx = tx.to_mutable()
        mtx.nVersion = 2
        mtx.vin.append(CTxIn())

        itx = tx.to_immutable()

        with self.assertRaises(AttributeError):
            itx.nVersion = 2
        with self.assertRaises(AttributeError):
            itx.vin.append(CTxIn())

    def test_mutable_tx_creation_with_immutable_parts_specified(self):
        tx = CMutableTransaction(
            vin=[CTxIn(prevout=COutPoint(hash=b'a'*32, n=0))],
            vout=[CTxOut(nValue=1)],
            witness=CTxWitness([CTxInWitness()]))

        def check_mutable_parts(tx):
            self.assertTrue(tx.vin[0]._immutable_restriction_lifted)
            self.assertTrue(tx.vin[0].prevout._immutable_restriction_lifted)
            self.assertTrue(tx.vout[0]._immutable_restriction_lifted)
            self.assertTrue(tx.wit._immutable_restriction_lifted)
            self.assertTrue(tx.wit.vtxinwit[0]._immutable_restriction_lifted)

        check_mutable_parts(tx)

        # Test that if we deserialize with CMutableTransaction,
        # all the parts are mutable
        tx = CMutableTransaction.deserialize(tx.serialize())
        check_mutable_parts(tx)

        # Test some parts separately, because when created via
        # CMutableTransaction instantiation, they are created with from_*
        # methods, and not directly

        txin = CMutableTxIn(prevout=COutPoint(hash=b'a'*32, n=0))
        self.assertTrue(txin.prevout._immutable_restriction_lifted)

        wit = CMutableTxWitness((CTxInWitness(),))
        self.assertTrue(wit.vtxinwit[0]._immutable_restriction_lifted)

    def test_immutable_tx_creation_with_mutable_parts_specified(self):
        tx = CTransaction(
            vin=[CMutableTxIn(prevout=COutPoint(hash=b'a'*32, n=0))],
            vout=[CMutableTxOut(nValue=1)],
            witness=CMutableTxWitness(
                [CMutableTxInWitness(CScriptWitness([CScript([0])]))]))

        def check_immutable_parts(tx):
            self.assertTrue(not tx.vin[0]._immutable_restriction_lifted)
            self.assertTrue(not tx.vin[0].prevout._immutable_restriction_lifted)
            self.assertTrue(not tx.vout[0]._immutable_restriction_lifted)
            self.assertTrue(not tx.wit._immutable_restriction_lifted)
            self.assertTrue(not tx.wit.vtxinwit[0]._immutable_restriction_lifted)

        check_immutable_parts(tx)

        # Test that if we deserialize with CTransaction,
        # all the parts are immutable
        tx = CTransaction.deserialize(tx.serialize())
        check_immutable_parts(tx)

        # Test some parts separately, because when created via
        # CMutableTransaction instantiation, they are created with from_*
        # methods, and not directly

        txin = CTxIn(prevout=CMutableOutPoint(hash=b'a'*32, n=0))
        self.assertTrue(not txin.prevout._immutable_restriction_lifted)

        wit = CTxWitness((CMutableTxInWitness(),))
        self.assertTrue(not wit.vtxinwit[0]._immutable_restriction_lifted)
