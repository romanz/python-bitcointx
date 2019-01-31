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

import os
import json
import random
import logging
import unittest

import bitcointx
from bitcointx.core import (
    x, lx, b2lx, b2x, COIN, Uint256,
    CTransaction, CTxIn, CMutableTxIn, CMutableTransaction
)
from bitcointx.core.key import CPubKey
from bitcointx.sidechain.elements import (
    CAsset,
    calculate_asset, generate_asset_entropy, calculate_reissuance_token
)
from bitcointx.wallet import CBitcoinAddress
from bitcointx.core.secp256k1 import secp256k1_has_zkp

zkp_unavailable_warning_shown = False


def warn_zkp_unavailable():
    global zkp_unavailable_warning_shown
    if not zkp_unavailable_warning_shown:
        log = logging.getLogger("Test_Elements_CTransaction")
        log.warning(' secp256k1-zkp unavailable')
        log.warning(' skipping rangeproof checks.')
        log.warning(' If you do not need Elements sidechain funcionality, it is safe to ignore this warning.')
        zkp_unavailable_warning_shown = True


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
        logging.basicConfig()
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


class Test_Elements_CTransaction(ElementsSidechainTestSetupBase, unittest.TestCase):
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
            # as it is only relevant for blocks, not transactions
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
                    self.assertEqual(vout['asset'], tx.vout[n].nAsset.to_asset().to_hex())
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

                if secp256k1_has_zkp:
                    if tx.wit.is_null():
                        rpinfo = None
                    else:
                        rpinfo = tx.wit.vtxoutwit[n].get_rangeproof_info()
                    if 'value-minimum' in vout:
                        self.assertIsNotNone(rpinfo)
                        self.assertEqual(vout['ct-exponent'], rpinfo.exp)
                        self.assertEqual(vout['ct-bits'], rpinfo.mantissa)
                        self.assertEqual(int(round(vout['value-minimum']*COIN)), rpinfo.value_min)
                        self.assertEqual(int(round(vout['value-maximum']*COIN)), rpinfo.value_max)
                    else:
                        self.assertTrue(rpinfo is None or rpinfo.exp == -1)
                        if rpinfo is None:
                            value = tx.vout[n].nValue.to_amount()
                        else:
                            value = rpinfo.value_min
                        self.assertEqual(int(round(vout['value']*COIN)), value)
                else:
                    warn_zkp_unavailable()
                    if 'value' in vout and tx.vout[n].nValue.is_explicit():
                        self.assertEqual(int(round(vout['value']*COIN)), tx.vout[n].nValue.to_amount())

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
                            asset = calculate_asset(tx.vin[n].assetIssuance.assetEntropy)
                        else:
                            entropy = generate_asset_entropy(tx.vin[n].prevout,
                                                             tx.vin[n].assetIssuance.assetEntropy)
                            self.assertEqual(iss['assetEntropy'], entropy.to_hex())
                            asset = calculate_asset(entropy)
                            reiss_token = calculate_reissuance_token(
                                entropy, tx.vin[n].assetIssuance.nAmount.is_commitment())
                            self.assertEqual(iss['token'], reiss_token.to_hex())
                        self.assertEqual(iss['asset'], asset.to_hex())
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

    def test_blinding(self):
        if not secp256k1_has_zkp:
            warn_zkp_unavailable()
            return

        blinders = [Uint256(lx(f))
                    for f in ('ec2f55906d389e56e76c84ac25a1e34a45fcc956d02edfa7469c6b170cdd5f80',
                              '675b20fa5ed25323964b9909744130a30c84c004f70fbff50cdb30a48963740f')]
        amounts = [2099993389703020, 300000000]
        assets = [CAsset(lx(f)) for f in ('b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23',
                                          'b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23')]
        assetblinders = [Uint256(lx(f))
                         for f in ('27bddd04f6c7ae2654fe1cdd5d7a53713eacb4516703d30f69839d276423d3fe',
                                   '28ab6564054ab141bad45326830c5a8403ac1585b4c754be0516c6666031b1f2')]
        unblinded_tx_raw = x('0200000000022d324def3d3d286e1acdde31ecf5f551bac65e65c8031ba651976904ce611eb00000000000ffffffff2d324def3d3d286e1acdde31ecf5f551bac65e65c8031ba651976904ce611eb00100000000ffffffff0201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000030d40000001230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000775eee1e4b52c0204edcb63429513e2a5292331d6b902ada4e7bd34ed93a31f1fbd8f3fe0edb7ff1976a91431b89ac07fa3f87443d2c5950ac3c8bcb75b72ba88ac00000000')
        blinded_tx_raw = x('0200000001022d324def3d3d286e1acdde31ecf5f551bac65e65c8031ba651976904ce611eb00000000000ffffffff2d324def3d3d286e1acdde31ecf5f551bac65e65c8031ba651976904ce611eb00100000000ffffffff0201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000030d4000000ac8b6248edd314a7fc5c0ba3bdeca820ef0a122e3e0769d8c73ea9777f4de44500944d521404330f6d2c3b7c8b6f581849bb39a003ead186e58d6a6e429043e5fb802e1b20ebfb7d796d5d6e280db4ec076911ef00dc95af9a29d381e5628fb6057791976a91431b89ac07fa3f87443d2c5950ac3c8bcb75b72ba88ac00000000000000000000000000006302000323313038985fca19a4d8b3b5d6eb584bab1b51a1b03a39dfb70ea39638f638f829673cd2194f287d496266b8d41e7b607718f9de279e80a78db10a264f990919e99543200bfcc5f883b85ff93e394dbc562b4692c600ba74e87c34569c3ac93cfd0e1060320000000000000001f50dd00116c28fc0717ee0265b2afd450127726b30d5f9df98b044bec745692526116c4877503584c8be87344bb472acfee7d0b99574eba1157bdc17c170f8cea8b6e92152a5a3f583e812adb25078dcdeac0d00cc499ec735d33134dfdf81cfcbdc2f030b9cdab0a01d52d043beb9daaa84e3cc4a2b6288b689fde731fa6441cd3610a8665b0c71e227027af3b908420ac13660e0123e2217e3d51f40e51a35e50498a9d9cc7a92c341739c96edac7d5aab544e4a3bcb8eb77bdd1bc40698b5fa227d45f19fee1f66f3d83a630b244b2add0bc29e2e02cd3861da5295ece6535af2c6e55097cd3b58f7d2ffbd41dd97cbbbb4c879daee651584db0009090388d72e79cb5943b0c58e224fb3c7a0b2f30a21b129bff6a820c631d81b50ee0c684de6bbdda56845af24ffcdc95eacf8fe6c04785ecf99cdb71a01c498a16571ec7d173d725fe39a48813fd0750ee440ade637ec31ddee204e225c2fdee6a02a3cfe0c9f9dbde70252c97676164b52d8f09b7e6d5732ad8880c8e185c27ac745fcf9f7ea44307f260453a9f7c9af35b450a60a85d0ce36477f073035bc1c6044f7ab1b80f80ec7772af3c855d71fd49c38fb6a2e1a5a0c2bbeb0edce21e7179eba89116737b8630edea551a9491824489c228cae87bad7b43cc222200850e7075c7760e7c0e8a146b132bcf0b772a29fd396f24084c1c014110c537c9e6ba76afe0f7c92769de2eff4dc8a93cbc4c4e7a69424dba8933ca35fb2f607172d8c8e5cacabd86679adc733fdca543a6870cccad0ddaf5d4d8a3afe706c223d09278a6099f9b55d77d8be764ea91e30e42acb5cbfac81c11a9660519b53b25d65ee91ba1b26d2e32e68ace973b569414d2721f72a70f82671b12b1481090a70c2a9209aa7e0e73d40ff0c0dc9ad828ea1faa58699dbb455c27008d2ac16cd0a9e9d380e8abcf75d839b3770fe3c5dca3c94d718fede971e68921e35420dbeb67907d2606f5d197d62ae2d45788ce7d42a76f403eed2137602e6b0a7ded68c7abed43a39f3e7b2e2bf252dfefef8208566c9e868b990a84c9c48ef28b8a8185dcbc3a28298381bf40db3fc1605b853b4802ea12757f6416c31ace032a2d33a758574aeb095951b67555894eb1ef83f24dd59be1b5b0fae40ab23342944ba08bc0cb8ec728419cc6030954a6a5d23e7d0557734b38f4bd8bc00f0ea2f643dd4e15bf2bf0a5770775a10e167214fc5c330180003308d9769463d50d02022151318c8b96899a6309d23b16dfceffe1b93c22868cca25d848ac49ec49672da0d8f0b2f76ce102196dccf88ba5c5e356d2b46eba02be84fc61ae945b62e6b36fbbc377c7009478e704a527dbcda54db0be4c18b2bb2661b3d49c3bb170465774891e98907b0dab7190f33110fddd12d84e6817c77488d92c4278cbe56299834f57a13ceade783083838c1abc80c563e9855dd87e23b4b5c2e2739d79e44f570a4e9d0ba253082681c7ebaa587b68ee7f0f89c0d30f89e48b84b6738f3e93d24f990f7868c9e14523984b2bb10730f8207e19bc049432c3aa23e3378c1e6372207c08028c05925bc12976f51a6b334c92542166bba806f0929d91497bbca182d9c08b9b9c0e51bf00611736364262df320b9d609927342f06d52c6b71bfafc253d7e2937b19bdca20b652dbd72729baad9db2355767ee12ff723e473e01b71a753d277df8ad8d9107b3f123eb7e9c42572c70c40ea75114bbe974030db91b9fea0c1fd54b7d3b3d8dbd3c5b789e3291ce19638fe77c58f5b3f485b5599ff47dac6494b688a12625b7d2b80f9bae2c6a4037bb51d71dd69a858ae771bf7c5e20316c4a8ba500c2abd803faaafbf4577ab3fdd042e26e5daeedf1dfc96079cfbc644ab5eaa77d6ebb6dbb9a6d1fdd913bea36e9511c1248da63ee64736ffbdc47a196b9a8559cb9aa0d4262f09d6a425322d81c076ae5af05e4f3f1d221aabadc1da91a079b559a26987a0539b6f0075b74d086f191485721ef9ec8d0666a5c30c6694bf32560f63a0a5c261b5ad413d7e791eee8480a6ccfa18f3fb1c2d71100dfe88f011be0e07c3e52bceee0eb1b6441f26e5f3f36dd5a9ddd14fffd7ca71eb0e8ef10f8ba493b8946bc305c12b8fc2ac7786318fb525e9915221b403647fa84e4acc5ab067c4cf1f16aa6ef2af019f8f62c5f854cddf4284e7bfc48c0a5eb13ca7ca82d415a30e4a0d10602f6f31dadadabac3f3f754edb3e8cd4d7c9b72388a4a85feffd8f740fb4ec448bf699853ab449a7d9e9f250859ffd172f410176a03d4a13bf8dd7dab6bd965385d671b40d08de1374e717e7ab2c1d69982589e1aa037381129b63d747f7d99823c9c2b58f9aa4fec09a3ac75faace61035895e43f0726d20017e6632588b7e157d1f24f0292f7be6fcd92d456c7414c2634539091c8bfbbb8bae00c11266bd2016cad88f01b84fac6849d299dbf662428d804bad8449aada51c95094a831e222edaf38cd50ca01568ba0e756749a71c0a9def23e04a19e78c7fea82410ff37d8ad58415aa4a0598bf97073d7fb6ae7df5d3897209ae3546b31f98bcf22664f44ba884f086a665377c878759867907e04aabc0b6fa3e920f853fba2b81dd8fe36c73884f6ae19c6ae8315120e22d42d9bbcefdad36ab996b2efc7f8d8abb7a67e5f28c8329393a6a8e03cfcfdeee0541548352efc63e93404ba6f9646cf5439405b7cca01ae3a3baf0952dc747b0fc1c5aa0131de234dd89a7b138f03873a7669c73aca060684d9aeaccbf2abd02fd8f067865c285840b87d6afd988b7689ff9d04c8db34d414ca667e58260103fef39e281066b0479e234fd07f87f9d5560da8e588fe1d7821bd96aea4585a5ad3a8bf532a8b8171b60e062b544cec819d6c58f2afa2098ecf4cfd734614728b2d3295ef4d504bf90f7988fd8ff66d3010427858eb389e156817a2b3d13815dbd67f910951533e9ac4681f5ed75cb01bcd0ae02c17b1b346848dbeb48ca4ff3882f3835706ea6f87d7f591909191bd7de62f4eb4ba2036fcce5fce67276fa394cbb0c15349b7f866099610ec6d7eee638aabf9c8ad80268d5745b0c4d4a241822c30d2758322b225fafd230af2cbd090fd9fac11a1af9cb355db31c2da301a11101a89f33b794a8d3df3d43f641e57fe8cb469e499503f56c4905c983fcc7b0dd5873ec8bd0eaac51e33c1c504891599788f0f95beadd13c37c82b0b801f54b67834df355d5dbd368fdf7f6dc679dabecbaacafb4ae66995d7a3aece989f2bf745a74e84266852d642e4d9f08178ac0426cf5ab804985caf9d385db33db51ec17f18f5f32a461ad9e63ff90aa4ba741c7b26912e0d42c009db31da4d1609b28b66d4fd15f08012d4a540653fec113050e008b5b501b6061849050b6ae8ab07b86b1666fc45cdb763c948a439ebbcc4a9e1ca79b8dd9be474c273e8c924bf497892c71cea3a6b8a6731693d04760ff68e7ef907abcc2fbefa19fd7f95cb70147d7b6e47d4f20321d1b773d428d5318a2144856d1a3b0cc3107942abc09b26ad4a19326047dc750aa62263d38d2a905d3da4f10aa3735339e810b36524dda0030421b1fdb1de7c5c749c5f5e1a298464c3f577457a5e41c07e924496a7b9b7fd675ed964e5e61fcdc7332e72887fcf77ec1b2f5c1971880faa284a98206329b0ec2f2e1a3f3b3f35af691f4944194cdcf4b6061deff0c10b428fc4cbcfd67eb8630860e1ff97c08f37422d315f5230b5bf39f47a0327237e9582faa6dd58f6424812b05a16836669ed049aa4e53c592e68abed25e2a9836b7874269c0c55ff44e09bd4fd804b11cef1ea2d2b67e0ccb0b1a1a8cac8a9605cf463aa2c9414522763c3d9e8c3ade15f90188373d9a419a072b9956ccbc3f68f3e922408851871b7a22975ffa90355f92efb725e14a8dc52573d462cadad2daa1619549aaf649ce0cb1344b1f36b276ba03e5c7bf698509866858978905d8dc459094a2abb1bebfeab6651bf111c3b9c9137b78344eae073290dbbd1a9522b7c737b64343a48815d5a6010d5f341e4328959f21bfc9044974fd40c8746e99033b381393008bb428f0274b33094199e5d93f265c8244500d219be632311c51c7f789c2c6b1f8cb6232150c140d6e6b65e1f4e65c4c6d2b08367939703b1f319a2c63964bc768688129bcc8715dbacaaf2a34889bba212efa5cf27362c39a9c68762ec6c5ff0ab58d643346d46d68df0a93ea06cef1e81fc556a9781e12f46d64c726ef9870794f036b22be5409a08353e1d8c26011e43bed7f96351460581da7adf6d8ccfacacdd3b1096fe5ec3297855c375f370f9165d6c896d69762aae751a101977ed5c5604f039eeb67e4450327105f0041c1e1dd28c44535f1d49eab2c8a1c124175eac8ab78a7e4858ab4c545713f5f0d267a844575dc02fd2a0fba8566b45940ff42873c45a4393add94580a8fdf78ef2c75a21887f410e03eaa07a554ce64e5a562923f62e622133198ae74405c09fb661351ffc269ec7c538bf42a1312ddac6146ca2ee7c3e027f266ccb88108793b2b6b38330ce871a2e535f26feb0702b9a899ee691163120612072aaa77a4af2adcdbcec96da005ae1ef6ffe01494371633e7706fb370eb27ae90b59dc5ae7c514999a47063943ff20a9ee5e255abca56422d1c850a4590d03e3c29feb530babb414074ef6f54b7b69ac2f3d23df3477e36253fb5a937f04abe28daa77d5f62e55fec75786f9c252e12e21cc635826d956c4e60e9929c86c80cfeebe37c01fd61119e728a9d76782691c37afb5c261694b5e5f6c75db866fddd35391a597274fbe2e44c3ae5e7c84e8af4cbea288128cd6fac1fa6a70f2d4343bc1c2601d180b9cb7a6922d98f63163ade9490e771a33dcaf0aa6a611fc4e9aaabe116cc38b4aab538726944035b7301e70d8eb3012ef5768a1ace58ac915823585c473e8d0f7ec6dab86a38ca12505035d990f2e3694f69d777d2026339eab840e7125b5d7f1f66b0fb8c26bf0d953f0100160251a61e3a1d16f9895d09b080211837e80d6227cb59e0d3634f077468dcab00d5509ebc816087cd36504353fb5f027a922ad61d9bf76d4e0d5e53dbf79a5b851fa00b1d214587fd35af4d4cff9bdba9e8f9a97e8fcc04aa81f867c19b6133bb1ad52b4f7a17fd69cd34ccbb992d8c1eef981494552fc255a12979ddf3282a62886e44498ace8b293a1a4b5da62a9cdfeca227b5a8775154e64634b6701543eee76c6c424b11f5d337d59e74cbb54cb0e99a50a801459ce6b26bfdfd1e98cad4d821892aac2e9035858190573cf2e1cc83043702ca6957777c81080d00f7345a390db7b8712076bb4ddfd90764770fd1eb1cf1eb4f408f6e667ac1837872f9c91cb434cd72f0c5073e8b185e620aabd332d00c66e0560e2237d496fe28f461d89bd0af179f2a901d27630782162af4526820c445ec28648b22573b3f685dee8f5af58ef79907e9db0a94c6cb7cf6c6e1d2eb4e629ae00f48d6dadba57345acd4840300565d6520d17b2b3f55fbb4eb9c3f337290bbc7de51bdcc5fe9a1a2052a2e61dc0160eb5e15b7d075ca8cbe22bccdc12113ab8ef68599c5dd4ddd8dd24530b75fb7f170df9b3486ba52a99b7483c4f30f335980b3c792a914f2bfe28225358a901485e72562efee83eed1afe45cd6c45dfb635e91fb23de3b2c03a1641271820c04e05d1155faa0c633fcd4ab08387e59889d0bd8569f695a2b2a7de8119184d2dec070ca3ad19a89620f27c9cc8b9974f72285d358be60910')

        blinded_tx = CMutableTransaction.deserialize(blinded_tx_raw)
        self.assertEqual(blinded_tx.serialize(), blinded_tx_raw)
        unblinded_tx = CMutableTransaction.deserialize(unblinded_tx_raw)
        self.assertEqual(unblinded_tx.serialize(), unblinded_tx_raw)

        def rand_func(n):
            return bytes([random.randint(0, 255) for _ in range(n)])

        output_pubkeys = []
        for vout in unblinded_tx.vout:
            if not vout.nNonce.is_null():
                output_pubkeys.append(CPubKey(vout.nNonce.commitment))
            else:
                output_pubkeys.append(CPubKey())

        random.seed(7)
        blind_result = unblinded_tx.blind(
            input_blinding_factors=blinders,
            input_asset_blinding_factors=assetblinders,
            input_assets=assets,
            input_amounts=amounts,
            output_pubkeys=output_pubkeys,
            _rand_func=rand_func
        )

        self.assertIsNotNone(blind_result)

        num_successfully_blinded, _ = blind_result
        self.assertEqual(num_successfully_blinded, 1)

        self.assertNotEqual(unblinded_tx_raw, unblinded_tx.serialize())
        self.assertEqual(blinded_tx_raw, unblinded_tx.serialize())
