# Copyright (C) 2011 Sam Rushing
# Copyright (C) 2012-2015 The python-bitcoinlib developers
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

# pylama:ignore=E501,E261,E221

"""ECC secp256k1 crypto routines

WARNING: This module does not mlock() secrets; your private keys may end up on
disk in swap! Use with caution!
"""

import hmac
import struct
import ctypes
import ctypes.util
import hashlib

from bitcointx.core import Hash160
from bitcointx.core.secp256k1 import (
    secp256k1, secp256k1_context_sign, secp256k1_context_verify,
    SIGNATURE_SIZE, COMPACT_SIGNATURE_SIZE,
    PUBLIC_KEY_SIZE, COMPRESSED_PUBLIC_KEY_SIZE,
    SECP256K1_EC_COMPRESSED, SECP256K1_EC_UNCOMPRESSED,
    secp256k1_has_pubkey_recovery
)

try:
    _ssl = ctypes.cdll.LoadLibrary(ctypes.util.find_library('ssl') or 'libeay32')
    if not getattr(_ssl, 'EC_KEY_new_by_curve_name', None):
        _ssl = None
except OSError:
    _ssl = None


class OpenSSLException(EnvironmentError):
    pass


class KeyDerivationFailException(RuntimeError):
    pass


# Thx to Sam Devlin for the ctypes magic 64-bit fix (FIXME: should this
# be applied to every OpenSSL call whose return type is a pointer?)
def _check_res_openssl_void_p(val, func, args): # pylint: disable=unused-argument
    if val == 0:
        errno = _ssl.ERR_get_error()
        errmsg = ctypes.create_string_buffer(120)
        _ssl.ERR_error_string_n(errno, errmsg, 120)
        raise OpenSSLException(errno, str(errmsg.value))

    return ctypes.c_void_p(val)

if _ssl:
    _ssl.EC_KEY_new_by_curve_name.errcheck = _check_res_openssl_void_p
    _ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
    _ssl.EC_KEY_new_by_curve_name.argtypes = [ctypes.c_int]

    _ssl.ECDSA_SIG_free.restype = None
    _ssl.ECDSA_SIG_free.argtypes = [ctypes.c_void_p]

    _ssl.ERR_error_string_n.restype = None
    _ssl.ERR_error_string_n.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t]

    _ssl.ERR_get_error.restype = ctypes.c_ulong
    _ssl.ERR_get_error.argtypes = []

    _ssl.d2i_ECDSA_SIG.restype = ctypes.c_void_p
    _ssl.d2i_ECDSA_SIG.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]

    _ssl.i2d_ECDSA_SIG.restype = ctypes.c_int
    _ssl.i2d_ECDSA_SIG.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    # this specifies the curve used with ECDSA.
    _NIDsecp256k1 = 714 # from openssl/obj_mac.h

    # test that OpenSSL supports secp256k1
    _ssl.EC_KEY_new_by_curve_name(_NIDsecp256k1)


class CKeyMixin():
    """An encapsulated private key

    Attributes:

    pub           - The corresponding CPubKey for this private key
    secret_bytes  - Secret data, 32 bytes (needed because subclasses may have trailing data)

    is_compressed - True if compressed

    """

    def __init__(self, s, compressed=True):
        raw_pubkey = ctypes.create_string_buffer(64)

        # no need for explicit secp256k1_ec_seckey_verify()
        # because secp256k1_ec_pubkey_create() will do
        # the same checks and ensure that secret data is valid
        result = secp256k1.secp256k1_ec_pubkey_create(
            secp256k1_context_sign, raw_pubkey, self.secret_bytes)

        if result != 1:
            raise ValueError('Invalid private key data')

        self.pub = CPubKey._from_raw(raw_pubkey, compressed=compressed)

    @property
    def is_compressed(self):
        return self.pub.is_compressed

    @property
    def secret_bytes(self):
        return self[:32]

    def sign(self, hash):
        if not isinstance(hash, bytes):
            raise TypeError('Hash must be bytes instance; got %r' % hash.__class__)
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        raw_sig = ctypes.create_string_buffer(64)
        result = secp256k1.secp256k1_ecdsa_sign(
            secp256k1_context_sign, raw_sig, hash, self.secret_bytes, None, None)
        assert 1 == result
        sig_size0 = ctypes.c_size_t()
        sig_size0.value = SIGNATURE_SIZE
        mb_sig = ctypes.create_string_buffer(sig_size0.value)
        result = secp256k1.secp256k1_ecdsa_signature_serialize_der(
            secp256k1_context_sign, mb_sig, ctypes.byref(sig_size0), raw_sig)
        assert 1 == result
        # secp256k1 creates signatures already in lower-S form, no further
        # conversion needed.
        return mb_sig.raw[:sig_size0.value]

    def sign_compact(self, hash): # pylint: disable=redefined-builtin
        if not isinstance(hash, bytes):
            raise TypeError('Hash must be bytes instance; got %r' % hash.__class__)
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        if not secp256k1_has_pubkey_recovery:
            raise RuntimeError('secp256k1 compiled without pubkey recovery functions. '
                               'sign_compact is not functional.')

        recoverable_sig = ctypes.create_string_buffer(COMPACT_SIGNATURE_SIZE)

        result = secp256k1.secp256k1_ecdsa_sign_recoverable(
            secp256k1_context_sign, recoverable_sig, hash, self.secret_bytes, None, None)

        assert 1 == result

        recid = ctypes.c_int()
        recid.value = 0
        output = ctypes.create_string_buffer(64)
        result = secp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact(
            secp256k1_context_sign, output, ctypes.byref(recid), recoverable_sig)

        assert 1 == result

        return bytes(output), recid.value

    def verify(self, hash, sig):
        return self.pub.verify(hash, sig)

    def verify_nonstrict(self, hash, sig):
        return self.pub.verify_nonstrict(hash, sig)


class CKey(bytes, CKeyMixin):
    "Standalone privkey class"

    def __new__(cls, secret, compressed=True):
        if len(secret) != 32:
            raise ValueError('secret size must be exactly 32 bytes')
        return super(CKey, cls).__new__(cls, secret)

    @classmethod
    def from_secret_bytes(cls, secret, compressed=True):
        return cls(secret, compressed=compressed)


class CPubKey(bytes):
    """An encapsulated public key

    Attributes:

    is_valid      - Corresponds to CPubKey.IsValid()

    is_fullyvalid - Corresponds to CPubKey.IsFullyValid()

    is_compressed - Corresponds to CPubKey.IsCompressed()

    key_id        - Hash160(pubkey)
    """

    def __new__(cls, buf):
        self = super(CPubKey, cls).__new__(cls, buf)

        self.is_fullyvalid = False
        if self.is_valid:
            tmp_pub = ctypes.create_string_buffer(64)
            result = secp256k1.secp256k1_ec_pubkey_parse(
                secp256k1_context_verify, tmp_pub, self, len(self))
            self.is_fullyvalid = (result == 1)

        self.key_id = Hash160(self)

        return self

    @classmethod
    def _from_raw(cls, raw_pubkey, compressed=True):
        if len(raw_pubkey) != 64:
            raise ValueError('raw pubkey must be 64 bytes')
        pub_size0 = ctypes.c_size_t()
        pub_size0.value = PUBLIC_KEY_SIZE
        pub = ctypes.create_string_buffer(pub_size0.value)

        secp256k1.secp256k1_ec_pubkey_serialize(
            secp256k1_context_verify, pub, ctypes.byref(pub_size0), raw_pubkey,
            SECP256K1_EC_COMPRESSED if compressed else SECP256K1_EC_UNCOMPRESSED)

        return CPubKey(bytes(pub)[:pub_size0.value])

    def _to_raw(self):
        assert self.is_valid
        raw_pub = ctypes.create_string_buffer(64)
        result = secp256k1.secp256k1_ec_pubkey_parse(
            secp256k1_context_verify, raw_pub, self, len(self))
        assert 1 == result
        return raw_pub

    @classmethod
    def recover_compact(cls, hash, sig): # pylint: disable=redefined-builtin
        """Recover a public key from a compact signature."""
        if len(sig) != COMPACT_SIGNATURE_SIZE:
            raise ValueError("Signature should be %d characters, not [%d]" % (COMPACT_SIGNATURE_SIZE, len(sig)))

        if not secp256k1_has_pubkey_recovery:
            raise RuntimeError('secp256k1 compiled without pubkey recovery functions. '
                               'recover_compact is not functional.')

        recid = (sig[0] - 27) & 3
        compressed = ((sig[0] - 27) & 4) != 0

        rec_sig = ctypes.create_string_buffer(COMPACT_SIGNATURE_SIZE)

        result = secp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact(
            secp256k1_context_verify, rec_sig, sig[1:], recid)

        if result != 1:
            return False

        raw_pubkey = ctypes.create_string_buffer(64)

        result = secp256k1.secp256k1_ecdsa_recover(
            secp256k1_context_verify, raw_pubkey, rec_sig, hash)

        if result != 1:
            return False

        return cls._from_raw(raw_pubkey, compressed=compressed)

    @property
    def is_valid(self):
        return len(self) > 0

    @property
    def is_compressed(self):
        return len(self) == COMPRESSED_PUBLIC_KEY_SIZE

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, super(CPubKey, self).__repr__())

    def verify(self, hash, sig): # pylint: disable=redefined-builtin
        """Verify a DER signature"""
        if not sig:
            return False

        if not self.is_fullyvalid:
            return False

        raw_sig = ctypes.create_string_buffer(64)
        result = secp256k1.secp256k1_ecdsa_signature_parse_der(
            secp256k1_context_verify, raw_sig, sig, len(sig))

        if result != 1:
            return False

        secp256k1.secp256k1_ecdsa_signature_normalize(
            secp256k1_context_verify, raw_sig, raw_sig)

        raw_pub = self._to_raw()
        result = secp256k1.secp256k1_ecdsa_verify(
            secp256k1_context_verify, raw_sig, hash, raw_pub)

        return result == 1

    def verify_nonstrict(self, hash, sig): # pylint: disable=redefined-builtin
        """Verify a non-strict DER signature"""

        if not _ssl:
            raise RuntimeError('openssl library is not available. verify_nonstrict is not functional.')

        if not sig:
            return False

        # bitcoind uses ecdsa_signature_parse_der_lax() to load signatures that
        # may be not properly encoded, but is still accepted by openssl.
        # it allows a strict subset of violations what OpenSSL will accept.
        # ecdsa_signature_parse_der_lax() is present in secp256k1 contrib/
        # directory, but is not compiled by default. Bundling it with this
        # library will mean that it have to use C compiler at build stage, and
        # I would like to avoid this build-dependency.
        #
        # secp256k1_ecdsa_verify won't accept encoding violations for
        # signatures, so instead of ecdsa_signature_parse_der_lax() we use
        # decode-openssl/encode-openssl/decode-secp256k cycle
        # this means that we allow all encoding violatons that openssl allows.
        #
        # extra encode/decode is wasteful, but the result is that verification
        # is still roughly 4 times faster than with openssl's ECDSA_verify()
        norm_sig = ctypes.c_void_p(0)
        result = _ssl.d2i_ECDSA_SIG(ctypes.byref(norm_sig), ctypes.byref(ctypes.c_char_p(sig)), len(sig))
        if not result:
            return False

        derlen = _ssl.i2d_ECDSA_SIG(norm_sig, 0)
        if derlen == 0:
            _ssl.ECDSA_SIG_free(norm_sig)
            return False

        norm_der = ctypes.create_string_buffer(derlen)
        result = _ssl.i2d_ECDSA_SIG(norm_sig, ctypes.byref(ctypes.pointer(norm_der)))

        _ssl.ECDSA_SIG_free(norm_sig)

        if not result:
            return False

        return self.verify(hash, norm_der)


class CExtKeyBase():

    def _check_length(self):
        if len(self) != 74:
            raise ValueError('Invalid length for extended key')

    @property
    def depth(self):
        return self[0]

    @property
    def parent_fp(self):
        return self[1:5]

    @property
    def child_number(self):
        return struct.unpack(">L", self.child_number_bytes)[0]

    @property
    def child_number_bytes(self):
        return self[5:9]

    @property
    def chaincode(self):
        return self[9:41]

    @property
    def key_bytes(self):
        return self[41:74]


class CExtKeyMixin(CExtKeyBase):
    """An encapsulated extended private key

    Attributes:

    priv          - The corresponding CKey for extended privkey
    pub           - shortcut property for priv.pub
    """

    def __init__(self, _s):

        self._check_length()

        # NOTE: we ignore first byte - for xpubkey,
        # this is pubkey prefix byte.
        # For xprivkey, this byte is supposed to be zero,
        # but Bitcoin Core ignores that and do not check.
        # We also do not check, to be compatible.
        raw_priv = self.key_bytes[1:]

        # NOTE: cannot make self.priv a @property method
        # because we need to check if the privkey is valid
        # CKey() will do this for us.
        self.priv = self._key_class.from_secret_bytes(raw_priv)

    @property
    def pub(self):
        return self.priv.pub

    @classmethod
    def from_seed(cls, seed):
        if len(seed) not in (128//8, 256//8, 512//8):
            raise ValueError('Unexpected seed length')

        hmac_hash = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
        depth = 0
        parent_fp = child_number_packed = b'\x00\x00\x00\x00'
        privkey = hmac_hash[:32]
        chaincode = hmac_hash[32:]
        return cls.from_bytes(bytes([depth]) + parent_fp + child_number_packed + chaincode + bytes([0]) + privkey)

    def derive(self, child_number):
        if self.depth >= 255:
            raise ValueError('Maximum derivation path length is reached')

        if (child_number >> 32) != 0:
            raise ValueError('Child number is too big')

        depth = self.depth + 1

        child_number_packed = struct.pack(">L", child_number)

        if (child_number >> 31) == 0:
            bip32_hash = hmac.new(self.chaincode, self.pub + child_number_packed,
                                  hashlib.sha512).digest()
        else:
            bip32_hash = hmac.new(self.chaincode,
                                  bytes([0]) + self.priv.secret_bytes + child_number_packed,
                                  hashlib.sha512).digest()

        chaincode = bip32_hash[32:]

        child_privkey = ctypes.create_string_buffer(self.priv.secret_bytes, size=32)

        result = secp256k1.secp256k1_ec_privkey_tweak_add(
            secp256k1_context_sign, child_privkey, bip32_hash)

        if result != 1:
            raise KeyDerivationFailException('extended privkey derivation failed')

        parent_fp = self.pub.key_id[:4]
        cls = self.__class__
        return cls.from_bytes(bytes([depth]) + parent_fp + child_number_packed + chaincode + bytes([0]) + child_privkey)

    def neuter(self):
        return self._xpub_class.from_bytes(
            bytes([self.depth]) + self.parent_fp + self.child_number_bytes + self.chaincode + self.pub)


class CExtPubKeyMixin(CExtKeyBase):
    """An encapsulated extended public key

    Attributes:

    pub           - The corresponding CPubKey for extended pubkey

    """

    def __init__(self, _s):

        self._check_length()

        self.pub = CPubKey(self.key_bytes)
        if not self.pub.is_fullyvalid:
            raise ValueError('pubkey part of xpubkey is not valid')

    @classmethod
    def from_bytes(cls, data):
        return cls(data)

    def derive(self, child_number):
        if (child_number >> 31) != 0:
            if (child_number >> 32) != 0:
                raise ValueError('Child number is too big')
            else:
                raise ValueError('Hardened derivation not possible')
        if self.depth >= 255:
            raise ValueError('Maximum derivation path length is reached')
        assert self.pub.is_fullyvalid
        assert self.pub.is_compressed

        child_number_packed = struct.pack(">L", child_number)

        depth = self.depth + 1
        bip32_hash = hmac.new(self.chaincode, self.pub + child_number_packed,
                              hashlib.sha512).digest()
        chaincode = bip32_hash[32:]

        raw_pub = self.pub._to_raw()

        result = secp256k1.secp256k1_ec_pubkey_tweak_add(
            secp256k1_context_verify, raw_pub, bip32_hash)

        if result != 1:
            raise KeyDerivationFailException('extended pubkey derivation failed')

        child_pubkey_size0 = ctypes.c_size_t()
        child_pubkey_size0.value = COMPRESSED_PUBLIC_KEY_SIZE
        child_pubkey = ctypes.create_string_buffer(child_pubkey_size0.value)

        result = secp256k1.secp256k1_ec_pubkey_serialize(
            secp256k1_context_verify, child_pubkey, ctypes.byref(child_pubkey_size0), raw_pub,
            SECP256K1_EC_COMPRESSED)

        assert 1 == result

        parent_fp = self.pub.key_id[:4]
        cls = self.__class__
        return cls.from_bytes(bytes([depth]) + parent_fp + child_number_packed + chaincode + child_pubkey)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, super(CExtPubKey, self).__repr__())


class CExtPubKey(bytes, CExtPubKeyMixin):
    "Standalone extended pubkey class"


class CExtKey(bytes, CExtKeyMixin):
    "Standalone extended key class"
    _key_class = CKey
    _xpub_class = CExtPubKey

    @classmethod
    def from_bytes(cls, data):
        return cls(data)


__all__ = (
    'CKey',
    'CPubKey',
    'CExtKey',
    'CExtPubKey',
    'CKeyMixin',
    'CExtKeyMixin',
    'CExtPubKeyMixin'
)
