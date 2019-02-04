# Copyright (C) 2012-2014 The python-bitcoinlib developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

"""Wallet-related functionality

Includes things like representing addresses and converting them to/from
scriptPubKeys; currently there is no actual wallet support implemented.
"""

# pylama:ignore=E501,E221

import bitcointx
import bitcointx.base58
import bitcointx.bech32
import bitcointx.core
import bitcointx.core.key
import bitcointx.core.script as script


class CBitcoinAddress(object):

    def __new__(cls, s):
        try:
            return CBech32BitcoinAddress(s)
        except bitcointx.bech32.Bech32Error:
            pass

        try:
            return CBase58BitcoinAddress(s)
        except bitcointx.base58.Base58Error:
            pass

        raise CBitcoinAddressError('Unrecognized encoding for bitcoin address')

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a subclass of CBitcoinAddress"""
        try:
            return CBech32BitcoinAddress.from_scriptPubKey(scriptPubKey)
        except CBitcoinAddressError:
            pass

        try:
            return CBase58BitcoinAddress.from_scriptPubKey(scriptPubKey)
        except CBitcoinAddressError:
            pass

        raise CBitcoinAddressError('scriptPubKey is not in a recognized address format')


class CBitcoinAddressError(Exception):
    """Raised when an invalid Bitcoin address is encountered"""


class CBech32BitcoinAddress(bitcointx.bech32.CBech32Data, CBitcoinAddress):
    """A Bech32-encoded Bitcoin address"""

    @classmethod
    def from_bytes(cls, witver, witprog):

        assert witver == 0
        self = super(CBech32BitcoinAddress, cls).from_bytes(
            witver,
            bytes(witprog)
        )

        if len(self) == 32:
            self.__class__ = P2WSHBitcoinAddress
        elif len(self) == 20:
            self.__class__ = P2WPKHBitcoinAddress
        else:
            raise CBitcoinAddressError('witness program does not match any known segwit address format')

        return self

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a CBech32BitcoinAddress

        Returns a CBech32BitcoinAddress subclass, either P2WSHBitcoinAddress or
        P2WPKHBitcoinAddress. If the scriptPubKey is not recognized
        CBitcoinAddressError will be raised.
        """
        try:
            return P2WSHBitcoinAddress.from_scriptPubKey(scriptPubKey)
        except CBitcoinAddressError:
            pass

        try:
            return P2WPKHBitcoinAddress.from_scriptPubKey(scriptPubKey)
        except CBitcoinAddressError:
            pass

        raise CBitcoinAddressError('scriptPubKey not a valid bech32-encoded address')


class CBase58BitcoinAddress(bitcointx.base58.CBase58PrefixedData, CBitcoinAddress):
    """A Base58-encoded Bitcoin address"""

    # allow for CBase58PrefixedData to get length,
    # but prevent any matches with real prefixes
    base58_prefix = [None]
    base58_prefix_check_always = False
    base58_prefix_alias = {}

    @classmethod
    def from_bytes(cls, data, prefix=None):

        if prefix is None:
            prefix = cls.base58_prefix
            assert prefix[0] is not None
        else:
            if prefix in cls.base58_prefix_alias:
                prefix = cls.base58_prefix_alias[prefix]
            cls.check_base58_prefix_correct(prefix)

        nVersion = prefix[0]

        matching_class = cls
        if cls not in CBase58BitcoinAddress.__subclasses__():
            for subclass in CBase58BitcoinAddress.__subclasses__():
                prefix = subclass.base58_prefix
                if prefix is not None and nVersion == prefix[0]:
                    matching_class, data, prefix = subclass._base58_submatch(data, prefix)
                    break
            else:
                raise CBitcoinAddressError('Version %d not a recognized Bitcoin Address' % nVersion)

        self = super(CBase58BitcoinAddress, cls).from_bytes(data, prefix)
        self.__class__ = matching_class
        return self

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a CBitcoinAddress

        Returns a CBitcoinAddress subclass, either P2SHBitcoinAddress or
        P2PKHBitcoinAddress. If the scriptPubKey is not recognized
        CBitcoinAddressError will be raised.
        """
        try:
            return P2SHBitcoinAddress.from_scriptPubKey(scriptPubKey)
        except CBitcoinAddressError:
            pass

        try:
            return P2PKHBitcoinAddress.from_scriptPubKey(scriptPubKey)
        except CBitcoinAddressError:
            pass

        raise CBitcoinAddressError('scriptPubKey not a valid base58-encoded address')

    @classmethod
    def _base58_submatch(cls, data, prefix):
        return cls, data, prefix


class P2SHBitcoinAddress(CBase58BitcoinAddress):

    @classmethod
    def from_redeemScript(cls, redeemScript):
        """Convert a redeemScript to a P2SH address

        Convenience function: equivalent to P2SHBitcoinAddress.from_scriptPubKey(redeemScript.to_p2sh_scriptPubKey())
        """
        return cls.from_scriptPubKey(redeemScript.to_p2sh_scriptPubKey())

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a P2SH address

        Raises CBitcoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_p2sh():
            return cls.from_bytes(scriptPubKey[2:22])

        else:
            raise CBitcoinAddressError('not a P2SH scriptPubKey')

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        return script.CScript([script.OP_HASH160, self, script.OP_EQUAL])

    def to_redeemScript(self):
        return self.to_scriptPubKey()


class P2PKHBitcoinAddress(CBase58BitcoinAddress):

    @classmethod
    def from_pubkey(cls, pubkey, accept_invalid=False):
        """Create a P2PKH bitcoin address from a pubkey

        Raises CBitcoinAddressError if pubkey is invalid, unless accept_invalid
        is True.

        The pubkey must be a bytes instance;
        """
        if not isinstance(pubkey, bytes):
            raise TypeError('pubkey must be bytes instance; got %r' % pubkey.__class__)

        if not accept_invalid:
            if not isinstance(pubkey, bitcointx.core.key.CPubKey):
                pubkey = bitcointx.core.key.CPubKey(pubkey)
            if not pubkey.is_fullyvalid:
                raise CBitcoinAddressError('invalid pubkey')

        pubkey_hash = bitcointx.core.Hash160(pubkey)
        return cls.from_bytes(pubkey_hash)

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey, accept_non_canonical_pushdata=True, accept_bare_checksig=True):
        """Convert a scriptPubKey to a P2PKH address

        Raises CBitcoinAddressError if the scriptPubKey isn't of the correct
        form.

        accept_non_canonical_pushdata - Allow non-canonical pushes (default True)

        accept_bare_checksig          - Treat bare-checksig as P2PKH scriptPubKeys (default True)
        """
        if accept_non_canonical_pushdata:
            # Canonicalize script pushes
            scriptPubKey = script.CScript(scriptPubKey)  # in case it's not a CScript instance yet

            try:
                scriptPubKey = script.CScript(tuple(scriptPubKey))  # canonicalize
            except bitcointx.core.script.CScriptInvalidError:
                raise CBitcoinAddressError('not a P2PKH scriptPubKey: script is invalid')

        if scriptPubKey.is_witness_v0_keyhash():
            return cls.from_bytes(scriptPubKey[2:22])
        elif scriptPubKey.is_witness_v0_nested_keyhash():
            return cls.from_bytes(scriptPubKey[3:23])
        elif (len(scriptPubKey) == 25
                and scriptPubKey[0]  == script.OP_DUP
                and scriptPubKey[1]  == script.OP_HASH160
                and scriptPubKey[2]  == 0x14
                and scriptPubKey[23] == script.OP_EQUALVERIFY
                and scriptPubKey[24] == script.OP_CHECKSIG):
            return cls.from_bytes(scriptPubKey[3:23])

        elif accept_bare_checksig:
            pubkey = None

            # We can operate on the raw bytes directly because we've
            # canonicalized everything above.
            if (len(scriptPubKey) == 35  # compressed
                    and scriptPubKey[0]  == 0x21
                    and scriptPubKey[34] == script.OP_CHECKSIG):

                pubkey = scriptPubKey[1:34]

            elif (len(scriptPubKey) == 67  # uncompressed
                    and scriptPubKey[0] == 0x41
                    and scriptPubKey[66] == script.OP_CHECKSIG):

                pubkey = scriptPubKey[1:66]

            if pubkey is not None:
                return cls.from_pubkey(pubkey, accept_invalid=True)

        raise CBitcoinAddressError('not a P2PKH scriptPubKey')

    def to_scriptPubKey(self, nested=False):
        """Convert an address to a scriptPubKey"""
        return script.CScript([script.OP_DUP, script.OP_HASH160, self, script.OP_EQUALVERIFY, script.OP_CHECKSIG])

    def to_redeemScript(self):
        return self.to_scriptPubKey()


class P2WSHBitcoinAddress(CBech32BitcoinAddress):

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a P2WSH address

        Raises CBitcoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_witness_v0_scripthash():
            return cls.from_bytes(0, scriptPubKey[2:34])
        else:
            raise CBitcoinAddressError('not a P2WSH scriptPubKey')

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        assert self.witver == 0
        return script.CScript([0, self])

    def to_redeemScript(self):
        raise NotImplementedError("not enough data in p2wsh address to reconstruct redeem script")


class P2WPKHBitcoinAddress(CBech32BitcoinAddress):

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a P2WSH address

        Raises CBitcoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_witness_v0_keyhash():
            return cls.from_bytes(0, scriptPubKey[2:22])
        else:
            raise CBitcoinAddressError('not a P2WSH scriptPubKey')

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        assert self.witver == 0
        return script.CScript([0, self])

    def to_redeemScript(self):
        return script.CScript([script.OP_DUP, script.OP_HASH160, self, script.OP_EQUALVERIFY, script.OP_CHECKSIG])


class CBitcoinSecretError(bitcointx.base58.Base58Error):
    pass


class CBitcoinSecret(bitcointx.base58.CBase58PrefixedData, bitcointx.core.key.CKeyMixin):
    """A base58-encoded secret key

    Attributes: (inherited from CKeyMixin):

    pub           - The corresponding CPubKey for this private key
    secret_bytes  - Secret data, 32 bytes

    is_compressed - True if compressed

    Note that CBitcoinSecret instance is 33 bytes long if compressed, 32 bytes otherwise
    (due to WIF format that states b'\x01' should be appended for compressed keys).
    secret_bytes property is 32 bytes long in both cases.

    """

    @classmethod
    def from_bytes(cls, data, prefix=None):
        if len(data) > 33:
            raise ValueError('data size must not exceed 33 bytes')
        compressed = (len(data) > 32 and data[32] == 1)
        self = super(CBitcoinSecret, cls).from_bytes(data, prefix)
        bitcointx.core.key.CKeyMixin.__init__(self, None, compressed=compressed)
        return self

    @classmethod
    def from_secret_bytes(cls, secret, compressed=True):
        """Create a secret key from a 32-byte secret"""
        if len(secret) != 32:
            raise ValueError('secret size must be exactly 32 bytes')
        self = super(CBitcoinSecret, cls).from_bytes(secret + (b'\x01' if compressed else b''))
        bitcointx.core.key.CKeyMixin.__init__(self, None, compressed=compressed)
        return self

    def to_compressed(self):
        if self.is_compressed:
            return self
        return self.__class__.from_secret_bytes(self[:32], True)

    def to_uncompressed(self):
        if not self.is_compressed:
            return self
        return self.__class__.from_secret_bytes(self[:32], False)


class CBitcoinExtPubKey(bitcointx.base58.CBase58PrefixedData, bitcointx.core.key.CExtPubKeyMixin):
    """A base58-encoded extended public key

    Attributes (inherited from CExtPubKeyMixin):

    pub           - The corresponding CPubKey for extended pubkey
    """

    @classmethod
    def from_bytes(cls, data, prefix=None):
        self = super(CBitcoinExtPubKey, cls).from_bytes(data, prefix)
        self.__init__(None)
        return self

    def __init__(self, _s):
        bitcointx.core.key.CExtPubKey.__init__(self, None)


class CBitcoinExtKey(bitcointx.base58.CBase58PrefixedData, bitcointx.core.key.CExtKeyMixin):
    """A base58-encoded extended key.

    Attributes (inherited from CExtKeyMixin):

    priv          - The corresponding CBitcoinSecret for extended privkey
    pub           - shortcut property for priv.pub

    Note that priv is an instance of CBitcoinSecret (vs CKey for standalone CExtKey)
    """

    _xpub_class = CBitcoinExtPubKey
    _key_class = CBitcoinSecret

    @classmethod
    def from_bytes(cls, data, prefix=None):
        self = super(CBitcoinExtKey, cls).from_bytes(data, prefix)
        self.__init__(None)
        return self

    def __init__(self, _s):
        bitcointx.core.key.CExtKey.__init__(self, None)


_Base58PrefixMap = {
    P2PKHBitcoinAddress: 'PUBKEY_ADDR',
    P2SHBitcoinAddress: 'SCRIPT_ADDR',
    CBitcoinSecret: 'SECRET_KEY',
    CBitcoinExtKey: 'EXTENDED_PRIVKEY',
    CBitcoinExtPubKey: 'EXTENDED_PUBKEY',
}


def _SetBase58Prefixes(extra_base58_prefix_map=None):

    def ensure_pfx_bytes(prefix):
        if isinstance(prefix, int):
            prefix = bytes([prefix])
        assert isinstance(prefix, bytes)
        return prefix

    base58_prefix_map = _Base58PrefixMap.copy()
    if extra_base58_prefix_map is not None:
        base58_prefix_map.update(extra_base58_prefix_map)

    for cls, pname in base58_prefix_map.items():
        prefix = bitcointx.params.BASE58_PREFIXES.get(pname)
        if prefix is not None:
            prefix = ensure_pfx_bytes(prefix)
        cls.base58_prefix = prefix
        CBase58BitcoinAddress.base58_prefix_alias = {}
        for pfx_from, pfx_to in getattr(bitcointx.params, 'BASE58_PREFIX_ALIAS', {}).items():
            pfx_from = ensure_pfx_bytes(pfx_from)
            pfx_to = ensure_pfx_bytes(pfx_to)
            CBase58BitcoinAddress.base58_prefix_alias[pfx_from] = pfx_to


_SetBase58Prefixes()

__all__ = (
    'CBitcoinAddressError',
    'CBitcoinAddress',
    '_SetBase58Prefixes',
    'CBase58BitcoinAddress',
    'CBech32BitcoinAddress',
    'P2SHBitcoinAddress',
    'P2PKHBitcoinAddress',
    'P2WSHBitcoinAddress',
    'P2WPKHBitcoinAddress',
    'CBitcoinSecretError',
    'CBitcoinSecret',
    'CBitcoinExtKey',
    'CBitcoinExtPubKey',
)
