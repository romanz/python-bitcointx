# Copyright (C) 2013-2015 The python-bitcoinlib developers
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

import hashlib
import unittest

from bitcointx.core import b2x, x
from bitcointx.core.script import CScript, IsLowDERSignature
from bitcointx.core.key import CPubKey
from bitcointx.wallet import *


class Test_CBitcoinAddress(unittest.TestCase):
    def test_create_from_string(self):
        """Create CBitcoinAddress's from strings"""

        def T(str_addr, expected_bytes, expected_version, expected_class):
            addr = CBitcoinAddress(str_addr)
            self.assertEqual(addr.to_bytes(), expected_bytes)
            self.assertEqual(addr.__class__, expected_class)
            if isinstance(addr, CBase58BitcoinAddress):
                self.assertEqual(addr.base58_prefix[0], expected_version)
            elif isinstance(addr, CBech32BitcoinAddress):
                self.assertEqual(addr.witver, expected_version)

        T('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
          x('62e907b15cbf27d5425399ebf6f0fb50ebb88f18'), 0,
          P2PKHBitcoinAddress)

        T('37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP',
          x('4266fc6f2c2861d7fe229b279a79803afca7ba34'), 5,
          P2SHBitcoinAddress)

        T('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4',
          x('751e76e8199196d454941c45d1b3a323f1433bd6'), 0,
          P2WPKHBitcoinAddress)

        T('bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9',
          x('c7a1f1a4d6b4c1802a59631966a18359de779e8a6a65973735a3ccdfdabc407d'), 0,
          P2WSHBitcoinAddress)

    def test_wrong_nVersion(self):
        """Creating a CBitcoinAddress from a unknown nVersion fails"""

        # tests run in mainnet, so both of the following should fail
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress('mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt')

        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress('2MyJKxYR2zNZZsZ39SgkCXWCfQtXKhnWSWq')

    def test_from_scriptPubKey(self):
        def T(hex_scriptpubkey, expected_str_address, expected_class):
            scriptPubKey = CScript(x(hex_scriptpubkey))
            addr = CBitcoinAddress.from_scriptPubKey(scriptPubKey)
            self.assertEqual(str(addr), expected_str_address)
            self.assertEqual(addr.__class__, expected_class)

        T('a914000000000000000000000000000000000000000087', '31h1vYVSYuKP6AhS86fbRdMw9XHieotbST',
          P2SHBitcoinAddress)
        T('76a914000000000000000000000000000000000000000088ac', '1111111111111111111114oLvT2',
          P2PKHBitcoinAddress)
        T('0014751e76e8199196d454941c45d1b3a323f1433bd6',
          'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
          P2WPKHBitcoinAddress)
        T('0020c7a1f1a4d6b4c1802a59631966a18359de779e8a6a65973735a3ccdfdabc407d',
          'bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9',
          P2WSHBitcoinAddress)

    def test_from_nonstd_scriptPubKey(self):
        """CBitcoinAddress.from_scriptPubKey() with non-standard scriptPubKeys"""

        # Bad P2SH scriptPubKeys

        # non-canonical pushdata
        scriptPubKey = CScript(x('a94c14000000000000000000000000000000000000000087'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # Bad P2PKH scriptPubKeys

        # Missing a byte
        scriptPubKey = CScript(x('76a914000000000000000000000000000000000000000088'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # One extra byte
        scriptPubKey = CScript(x('76a914000000000000000000000000000000000000000088acac'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # One byte changed
        scriptPubKey = CScript(x('76a914000000000000000000000000000000000000000088ad'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

    def test_from_invalid_scriptPubKey(self):
        """CBitcoinAddress.from_scriptPubKey() with invalid scriptPubKeys"""

        # We should raise a CBitcoinAddressError, not any other type of error

        # Truncated P2SH
        scriptPubKey = CScript(x('a91400000000000000000000000000000000000000'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # Truncated P2PKH
        scriptPubKey = CScript(x('76a91400000000000000000000000000000000000000'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

    def test_to_redeemScript(self):
        def T(str_addr, expected_scriptPubKey_hexbytes):
            addr = CBitcoinAddress(str_addr)

            actual_scriptPubKey = addr.to_redeemScript()
            self.assertEqual(b2x(actual_scriptPubKey),
                             expected_scriptPubKey_hexbytes)

        T('31h1vYVSYuKP6AhS86fbRdMw9XHieotbST',
          'a914000000000000000000000000000000000000000087')

        T('1111111111111111111114oLvT2',
          '76a914000000000000000000000000000000000000000088ac')

        T('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
          '76a914751e76e8199196d454941c45d1b3a323f1433bd688ac')

    def test_to_scriptPubKey(self):
        """CBitcoinAddress.to_scriptPubKey() works"""
        def T(str_addr, expected_scriptPubKey_hexbytes):
            addr = CBitcoinAddress(str_addr)

            actual_scriptPubKey = addr.to_scriptPubKey()
            self.assertEqual(b2x(actual_scriptPubKey), expected_scriptPubKey_hexbytes)

        T('31h1vYVSYuKP6AhS86fbRdMw9XHieotbST',
          'a914000000000000000000000000000000000000000087')

        T('1111111111111111111114oLvT2',
          '76a914000000000000000000000000000000000000000088ac')


class Test_P2SHBitcoinAddress(unittest.TestCase):
    def test_from_redeemScript(self):
        def T(script, expected_str_address):
            addr = P2SHBitcoinAddress.from_redeemScript(script)
            self.assertEqual(str(addr), expected_str_address)

        T(CScript(), '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy')
        T(CScript(x('76a914751e76e8199196d454941c45d1b3a323f1433bd688ac')),
          '3LRW7jeCvQCRdPF8S3yUCfRAx4eqXFmdcr')


class Test_P2PKHBitcoinAddress(unittest.TestCase):
    def test_from_non_canonical_scriptPubKey(self):
        def T(hex_scriptpubkey, expected_str_address):
            scriptPubKey = CScript(x(hex_scriptpubkey))
            addr = P2PKHBitcoinAddress.from_scriptPubKey(scriptPubKey)
            self.assertEqual(str(addr), expected_str_address)

            # now test that CBitcoinAddressError is raised with accept_non_canonical_pushdata=False
            with self.assertRaises(CBitcoinAddressError):
                P2PKHBitcoinAddress.from_scriptPubKey(scriptPubKey, accept_non_canonical_pushdata=False)

        T('76a94c14000000000000000000000000000000000000000088ac', '1111111111111111111114oLvT2')
        T('76a94d1400000000000000000000000000000000000000000088ac', '1111111111111111111114oLvT2'),
        T('76a94e14000000000000000000000000000000000000000000000088ac', '1111111111111111111114oLvT2')

        # make sure invalid scripts raise CBitcoinAddressError
        with self.assertRaises(CBitcoinAddressError):
            P2PKHBitcoinAddress.from_scriptPubKey(x('76a94c14'))

    def test_from_bare_checksig_scriptPubKey(self):
        def T(hex_scriptpubkey, expected_str_address):
            scriptPubKey = CScript(x(hex_scriptpubkey))
            addr = P2PKHBitcoinAddress.from_scriptPubKey(scriptPubKey)
            self.assertEqual(str(addr), expected_str_address)

            # now test that CBitcoinAddressError is raised with accept_non_canonical_pushdata=False
            with self.assertRaises(CBitcoinAddressError):
                P2PKHBitcoinAddress.from_scriptPubKey(scriptPubKey, accept_bare_checksig=False)

        # compressed
        T('21000000000000000000000000000000000000000000000000000000000000000000ac', '14p5cGy5DZmtNMQwTQiytBvxMVuTmFMSyU')

        # uncompressed
        T('410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ac', '13VmALKHkCdSN1JULkP6RqW3LcbpWvgryV')

        # non-canonical encoding
        T('4c21000000000000000000000000000000000000000000000000000000000000000000ac', '14p5cGy5DZmtNMQwTQiytBvxMVuTmFMSyU')

        # odd-lengths are *not* accepted
        with self.assertRaises(CBitcoinAddressError):
            P2PKHBitcoinAddress.from_scriptPubKey(x('2200000000000000000000000000000000000000000000000000000000000000000000ac'))

    def test_from_valid_pubkey(self):
        """Create P2PKHBitcoinAddress's from valid pubkeys"""

        def T(pubkey, expected_str_addr):
            addr = P2PKHBitcoinAddress.from_pubkey(pubkey)
            self.assertEqual(str(addr), expected_str_addr)

        T(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'),
          '1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8')
        T(x('0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455'),
          '1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T')

        T(CPubKey(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71')),
          '1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8')
        T(CPubKey(x('0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455')),
          '1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T')

    def test_from_invalid_pubkeys(self):
        """Create P2PKHBitcoinAddress's from invalid pubkeys"""

        # first test with accept_invalid=True
        def T(invalid_pubkey, expected_str_addr):
            addr = P2PKHBitcoinAddress.from_pubkey(invalid_pubkey, accept_invalid=True)
            self.assertEqual(str(addr), expected_str_addr)

        T(x(''),
          '1HT7xU2Ngenf7D4yocz2SAcnNLW7rK8d4E')
        T(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c72'),
          '1L9V4NXbNtZsLjrD3nkU7gtEYLWRBWXLiZ')

        # With accept_invalid=False we should get CBitcoinAddressError's
        with self.assertRaises(CBitcoinAddressError):
            P2PKHBitcoinAddress.from_pubkey(x(''))
        with self.assertRaises(CBitcoinAddressError):
            P2PKHBitcoinAddress.from_pubkey(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c72'))
        with self.assertRaises(CBitcoinAddressError):
            P2PKHBitcoinAddress.from_pubkey(CPubKey(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c72')))


class Test_CBitcoinSecret(unittest.TestCase):
    def test(self):
        def T(base58_privkey, expected_hex_pubkey, expected_is_compressed_value):
            key = CBitcoinSecret(base58_privkey)
            self.assertEqual(b2x(key.pub), expected_hex_pubkey)
            self.assertEqual(key.is_compressed, expected_is_compressed_value)

        T('5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS',
          '0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455',
          False)
        T('L3p8oAcQTtuokSCRHQ7i4MhjWc9zornvpJLfmg62sYpLRJF9woSu',
          '0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71',
          True)

    def test_sign(self):
        key = CBitcoinSecret('5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS')
        hash = b'\x00' * 32
        sig = key.sign(hash)

        # Check a valid signature
        self.assertTrue(key.pub.verify(hash, sig))
        self.assertTrue(IsLowDERSignature(sig))

        # Check that invalid hash returns false
        self.assertFalse(key.pub.verify(b'\xFF'*32, sig))

        # Check that invalid signature returns false.
        #
        # Note the one-in-four-billion chance of a false positive :)
        self.assertFalse(key.pub.verify(hash, sig[0:-4] + b'\x00\x00\x00\x00'))

    def test_sign_invalid_hash(self):
        key = CBitcoinSecret('5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS')
        with self.assertRaises(TypeError):
            key.sign('0' * 32)

        hash = b'\x00' * 32
        with self.assertRaises(ValueError):
            key.sign(hash[0:-2])

    def test_from_to_compressed(self):
        def T(keydata, compressed, uncompressed):
            k = CBitcoinSecret.from_secret_bytes(x(keydata))
            k_u = CBitcoinSecret.from_secret_bytes(x(keydata), False)

            self.assertTrue(k.is_compressed)
            self.assertEqual(k.pub, x(compressed))

            k2 = CBitcoinSecret(str(k))
            self.assertTrue(k2.is_compressed)
            self.assertEqual(k, k2)

            k = k.to_uncompressed()
            self.assertEqual(k, k_u)
            self.assertEqual(len(k), 32)
            self.assertFalse(k.is_compressed)
            self.assertEqual(k.pub, x(uncompressed))

            k2 = CBitcoinSecret(str(k))
            self.assertFalse(k2.is_compressed)
            self.assertEqual(k, k2)

            k = k.to_compressed()
            self.assertEqual(len(k), 33)
            self.assertEqual(k[-1], 1)
            self.assertTrue(k.is_compressed)
            self.assertEqual(k.pub, x(compressed))

        T('0de5306487851213f0aae1454f4e4449949a755802b60f6eb47906149395d080',
          '023bd76d581c4823f66d8f3f6462dfdb3c8823ba77c7e8b5284d04b41b83659811',
          '043bd76d581c4823f66d8f3f6462dfdb3c8823ba77c7e8b5284d04b41b836598111af4e26a83ff8e3e0eef15eca09953f9a3d3c2c15807c5ef68a180fb8d4260c6')
        T('c9ff05edfbfb4710267ccf212fbb0414284b09fce621f8ab61a5b1cf0f3a5bf2',
          '029925633a4ba7d5f6f60d94213f65dfc482aa9b0f3cadb1ce20d7b7d792428209',
          '049925633a4ba7d5f6f60d94213f65dfc482aa9b0f3cadb1ce20d7b7d792428209973a2e2e14e13d6263c894fefd5374d1d2b0e637b2215209b55604c0bb4f1196')


class Test_RFC6979(unittest.TestCase):
    def test(self):
        # Test Vectors for RFC 6979 ECDSA, secp256k1, SHA-256
        # (private key, message, expected k, expected signature)
        test_vectors = [
            (0x1, "Satoshi Nakamoto", 0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15, "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d82442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"),
            (0x1, "All those moments will be lost in time, like tears in rain. Time to die...", 0x38AA22D72376B4DBC472E06C3BA403EE0A394DA63FC58D88686C611ABA98D6B3, "8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21"),
            (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140, "Satoshi Nakamoto", 0x33A19B60E25FB6F4435AF53A3D42D493644827367E6453928554F43E49AA6F90, "fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d06b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5"),
            (0xf8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181, "Alan Turing", 0x525A82B70E67874398067543FD84C83D30C175FDC45FDEEE082FE13B1D7CFDF1, "7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c58dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea"),
            (0xe91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2, "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!", 0x1F4B84C23A86A221D233F2521BE018D9318639D5B8BBD6374A8A59232D16AD3D, "b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6")
        ]
        for vector in test_vectors:
            secret = CBitcoinSecret.from_secret_bytes(x('{:064x}'.format(vector[0])))
            encoded_sig = secret.sign(hashlib.sha256(vector[1].encode('utf8')).digest())

            assert(encoded_sig[0] == 0x30)
            assert(encoded_sig[1] == len(encoded_sig)-2)
            assert(encoded_sig[2] == 0x02)

            rlen = encoded_sig[3]
            rpos = 4
            assert(rlen in (32, 33))

            if rlen == 33:
                assert(encoded_sig[rpos] == 0)
                rpos += 1
                rlen -= 1

            rval = encoded_sig[rpos:rpos+rlen]
            spos = rpos+rlen
            assert(encoded_sig[spos] == 0x02)

            spos += 1
            slen = encoded_sig[spos]
            assert(slen in (32, 33))

            spos += 1
            if slen == 33:
                assert(encoded_sig[spos] == 0)
                spos += 1
                slen -= 1

            sval = encoded_sig[spos:spos+slen]
            sig = b2x(rval + sval)
            assert(str(sig) == vector[3])
