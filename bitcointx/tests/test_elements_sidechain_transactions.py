# Copyright (C) 2013-2014 The python-bitcointx developers
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

import bitcointx
from bitcointx.core import (
    x, b2lx, b2x, COIN,
    CTransaction, CTxIn, CMutableTxIn, CMutableTransaction
)
from bitcointx.sidechain.elements import (
    CalculateAsset, GenerateAssetEntropy, CalculateReissuanceToken
)
from bitcointx.wallet import CBitcoinAddress


def load_test_vectors(name):
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        for tx_decoded in json.load(fd):
            if isinstance(tx_decoded, str):
                continue  # skip comment
            tx_bytes = x(tx_decoded['hex'])
            assert len(tx_bytes) == tx_decoded['size']
            tx = CTransaction.deserialize(tx_bytes)
            yield (tx_decoded, tx, tx_bytes)


class ElementsSidechainTestSetupBase():
    @classmethod
    def setUpClass(cls):
        cls._prev_chain = bitcointx.params.NAME
        bitcointx.SelectParams('sidechain/elements')

    @classmethod
    def tearDownClass(cls):
        bitcointx.SelectParams(cls._prev_chain)


class Test_CTxIn(ElementsSidechainTestSetupBase, unittest.TestCase):
    def test_is_final(self):
        self.assertTrue(CTxIn().is_final())
        self.assertTrue(CTxIn(nSequence=0xffffffff).is_final())
        self.assertFalse(CTxIn(nSequence=0).is_final())

    def test_repr(self):
        def T(txin, expected):
            actual = repr(txin)
            self.assertEqual(actual, expected)
        T(CTxIn(),
          'CTxIn(COutPoint(), CScript([]), 0xffffffff, CAssetIssuance(), False)')

    def test_immutable(self):
        """CTxIn shall not be mutable"""
        txin = CTxIn()
        with self.assertRaises(AttributeError):
            txin.nSequence = 1


class Test_CMutableTxIn(ElementsSidechainTestSetupBase, unittest.TestCase):
    def test_GetHash(self):
        """CMutableTxIn.GetHash() is not cached"""
        txin = CMutableTxIn()

        h1 = txin.GetHash()
        txin.prevout.n = 1

        self.assertNotEqual(h1, txin.GetHash())


class Test_CTransaction(ElementsSidechainTestSetupBase, unittest.TestCase):
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

    def test_serialize_deserialize(self):

        for tx_decoded, tx, tx_bytes in load_test_vectors('elements_sidechain_txs.json'):
            self.assertEqual(tx_bytes, tx.serialize())
            self.assertEqual(tx_bytes, CTransaction.deserialize(tx.serialize()).serialize())
            self.assertEqual(tx_decoded['version'], tx.nVersion)
            self.assertEqual(tx_decoded['locktime'], tx.nLockTime)
            # we ignore withash field - we do not have ComputeWitnessHash() function
            # as it only relevant for blocks, not transactions
            self.assertEqual(tx_decoded['hash'], b2lx(tx.GetHash()))
            self.assertEqual(tx_decoded['txid'], b2lx(tx.GetTxid()))
            for n, vout in enumerate(tx_decoded['vout']):
                if 'amountcommitment' in vout:
                    self.assertEqual(x(vout['amountcommitment']),
                                     tx.vout[n].nValue.commitment)
                if 'assetcommitment' in vout:
                    self.assertEqual(x(vout['assetcommitment']),
                                     tx.vout[n].nAsset.commitment)
                if 'asset' in vout:
                    self.assertEqual(vout['asset'], tx.vout[n].nAsset.to_asset().id.to_hex())
                if 'value' in vout:
                    self.assertEqual(int(round(vout['value']*COIN)), tx.vout[n].nValue.to_amount())
                if 'scriptPubKey' in vout:
                    spk = vout['scriptPubKey']
                    self.assertEqual(x(spk['hex']), tx.vout[n].scriptPubKey)

                    if 'pegout_type' in spk:
                        self.assertEqual(spk['type'], 'nulldata')
                        self.assertTrue(tx.vout[n].scriptPubKey.is_pegout())
                        genesis_hash, pegout_scriptpubkey = tx.vout[n].scriptPubKey.get_pegout_data()
                        if spk['pegout_type'] != 'nonstandard':
                            assert spk['pegout_type'] in ('pubkeyhash', 'scripthash')
                            addr = CBitcoinAddress.from_scriptPubKey(pegout_scriptpubkey)
                            self.assertEqual(len(spk['pegout_addresses']), 1)
                            self.assertEqual(spk['pegout_addresses'][0], str(addr))
                        self.assertEqual(spk['pegout_hex'], b2x(pegout_scriptpubkey))
                        self.assertEqual(spk['pegout_chain'], b2lx(genesis_hash))

                    if spk['type'] in ('pubkeyhash', 'scripthash'):
                        self.assertEqual(len(spk['addresses']), 1)
                        addr = CBitcoinAddress.from_scriptPubKey(tx.vout[n].scriptPubKey)
                        self.assertEqual(spk['addresses'][0], str(addr))
                    elif spk['type'] == 'nulldata':
                        self.assertEqual(tx.vout[n].scriptPubKey, x(spk['hex']))
                    else:
                        self.assertEqual(spk['type'], 'fee')
                        self.assertEqual(len(tx.vout[n].scriptPubKey), 0)
                # TODO: test value-minimum, value-maximum, ct-exponent, ct-bits

            for n, vin in enumerate(tx_decoded['vin']):
                if 'scripSig' in vin:
                    self.assertEqual(x(vin['scriptSig']['hex'], tx.vin[n].scriptSig))
                if 'txid' in vin:
                    self.assertEqual(vin['txid'], b2lx(tx.vin[n].prevout.hash))
                if 'vout' in vin:
                    self.assertEqual(vin['vout'], tx.vin[n].prevout.n)
                if 'is_pegin' in vin:
                    self.assertEqual(vin['is_pegin'], tx.vin[n].is_pegin)
                    if vin['is_pegin'] is False:
                        if 'scriptWitness' in vin:
                            self.assertTrue(tx.wit.vtxinwit[n].scriptWitness.is_null())
                        if 'pegin_witness' in vin:
                            self.assertTrue(tx.wit.vtxinwit[n].pegin_witness.is_null())
                    else:
                        for stack_index, stack_item in enumerate(vin['scriptWitness']):
                            self.assertTrue(
                                stack_item,
                                b2x(tx.wit.vtxinwit[n].scriptWitness.stack[stack_index]))
                        for stack_index, stack_item in enumerate(vin['pegin_witness']):
                            self.assertTrue(
                                stack_item,
                                b2x(tx.wit.vtxinwit[n].pegin_witness.stack[stack_index]))
                if 'sequence' in vin:
                    self.assertEqual(vin['sequence'], tx.vin[n].nSequence)
                if 'coinbase' in vin:
                    self.assertTrue(tx.is_coinbase())
                if 'issuance' in vin:
                    iss = vin['issuance']
                    self.assertEqual(iss['assetBlindingNonce'],
                                     tx.vin[n].assetIssuance.assetBlindingNonce.to_hex())
                    if 'asset' in iss:
                        if iss['isreissuance']:
                            self.assertTrue(not tx.vin[n].assetIssuance.assetBlindingNonce.is_null())
                            self.assertEqual(iss['assetEntropy'],
                                             tx.vin[n].assetIssuance.assetEntropy.to_hex())
                            asset_hash = CalculateAsset(tx.vin[n].assetIssuance.assetEntropy)
                        else:
                            entropy = GenerateAssetEntropy(tx.vin[n].prevout,
                                                           tx.vin[n].assetIssuance.assetEntropy)
                            self.assertEqual(iss['assetEntropy'], entropy.to_hex())
                            asset_hash = CalculateAsset(entropy)
                            reiss_token = CalculateReissuanceToken(
                                entropy, tx.vin[n].assetIssuance.nAmount.is_commitment())
                            self.assertEqual(iss['token'], reiss_token.id.to_hex())
                        self.assertEqual(iss['asset'], asset_hash.id.to_hex())
                    if 'assetamount' in iss:
                        self.assertEqual(int(round(iss['assetamount']*COIN)),
                                         tx.vin[n].assetIssuance.nAmount.to_amount())
                    elif 'assetamountcommitment' in iss:
                        self.assertEqual(iss['assetamountcommitment'],
                                         b2x(tx.vin[n].assetIssuance.nAmount.commitment))
                    if 'tokenamount' in iss:
                        self.assertEqual(int(round(iss['tokenamount']*COIN)),
                                         tx.vin[n].assetIssuance.nInflationKeys.to_amount())
                    elif 'tokenamountcommitment' in iss:
                        self.assertEqual(iss['tokenamountcommitment'],
                                         b2x(tx.vin[n].assetIssuance.nInflationKeys.commitment))
