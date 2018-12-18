# Copyright (C) 2012-2017 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

# pylama:ignore=E501

import binascii
import struct
from abc import ABCMeta, abstractmethod

from .script import CScript, CScriptWitness, OP_RETURN

from .serialize import *

# Core definitions
COIN = 100000000
MAX_BLOCK_SIZE = 1000000
MAX_BLOCK_WEIGHT = 4000000
MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50
WITNESS_COINBASE_SCRIPTPUBKEY_MAGIC = bytes([OP_RETURN, 0x24, 0xaa, 0x21, 0xa9, 0xed])
BIP32_HARDENED_KEY_LIMIT = 0x80000000

# Elements sidechain definitions

# If this flag is set, the CTxIn including this COutPoint has a CAssetIssuance object.
OUTPOINT_ISSUANCE_FLAG = (1 << 31)
# If this flag is set, the CTxIn including this COutPoint is a peg-in input.
OUTPOINT_PEGIN_FLAG = (1 << 30)
# The inverse of the combination of the preceeding flags. Used to
# extract the original meaning of `n` as the index into the
# transaction's output array. */
OUTPOINT_INDEX_MASK = 0x3fffffff


_transaction_class_params = {}  # to be filled by _SetTransactionClassParams()


def MoneyRange(nValue, params=None):
    global coreparams
    if not params:
        params = coreparams

    return 0 <= nValue <= params.MAX_MONEY


def x(h):
    """Convert a hex string to bytes"""
    return binascii.unhexlify(h.encode('utf8'))


def b2x(b):
    """Convert bytes to a hex string"""
    return binascii.hexlify(b).decode('utf8')


def lx(h):
    """Convert a little-endian hex string to bytes

    Lets you write uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.unhexlify(h.encode('utf8'))[::-1]


def b2lx(b):
    """Convert bytes to a little-endian hex string

    Lets you show uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.hexlify(b[::-1]).decode('utf8')


def str_money_value(value):
    """Convert an integer money value to a fixed point string"""
    r = '%i.%08i' % (value // COIN, value % COIN)
    r = r.rstrip('0')
    if r[-1] == '.':
        r += '0'
    return r


def _str_money_value_for_repr(nValue):
    if nValue >= 0:
        "%s*COIN" % (str_money_value(nValue), )
    else:
        "%d" % (self.nValue,)


def _bytes_for_repr(buf, hexfun_name='x'):
    if len(buf) > 0 and all(b == buf[0] for b in buf):
        return "{}('{}')*{}".format(hexfun_name, b2x(buf[:1]), len(buf))
    return "{}('{}')".format(hexfun_name, b2lx(buf))


class ValidationError(Exception):
    """Base class for all blockchain validation errors

    Everything that is related to validating the blockchain, blocks,
    transactions, scripts, etc. is derived from this class.
    """


def __make_mutable(cls):
    # For speed we use a class decorator that removes the immutable
    # restrictions directly. In addition the modified behavior of GetHash() and
    # hash() is undone.
    cls.__setattr__ = object.__setattr__
    cls.__delattr__ = object.__delattr__
    cls.GetHash = Serializable.GetHash
    cls.__hash__ = Serializable.__hash__
    cls._immutable_restriction_lifted = True
    return cls


class _ReprOrStrMixin(metaclass=ABCMeta):

    @abstractmethod
    def _repr_or_str(self, strfn):
        ...

    def __str__(self):
        return self._repr_or_str(str)

    def __repr__(self):
        return self._repr_or_str(repr)


class _UintBitVectorMeta(type):
    def __init__(self, name, bases, dct):
        if self._UINT_WIDTH_BITS is not None:
            self._UINT_WIDTH_BYTES = self._UINT_WIDTH_BITS // 8
            assert self._UINT_WIDTH_BITS == self._UINT_WIDTH_BYTES * 8
            self.null_instance = bytes([0 for _ in range(self._UINT_WIDTH_BYTES)])


class _UintBitVector(ImmutableSerializable, metaclass=_UintBitVectorMeta):
    # should be specified by subclasses
    _UINT_WIDTH_BITS = None
    # to be set automatically by _UintBitVectorMeta
    _UINT_WIDTH_BYTES = None

    def __init__(self, data=b'\x00'*32):
        if len(data) != self._UINT_WIDTH_BYTES:
            raise ValueError('invalid data length, should be {}'
                             .format(self._UINT_WIDTH_BYTES))
        object.__setattr__(self, 'data', data)

    def is_null():
        return all(b == 0 for b in self.data)

    @classmethod
    def stream_deserialize(cls, f):
        data = ser_read(f, cls._UINT_WIDTH_BYTES)
        return cls(data)

    def stream_serialize(self, f):
        f.write(self.data)


class _Uint256(_UintBitVector):
    _UINT_WIDTH_BITS = 256

    def to_int(self):
        return uint256_from_str(self)


class COutPoint(ImmutableSerializable):
    """The combination of a transaction hash and an index n into its vout"""
    __slots__ = ['hash', 'n']

    def __init__(self, hash=b'\x00'*32, n=0xffffffff):
        if not len(hash) == 32:
            raise ValueError('COutPoint: hash must be exactly 32 bytes; got %d bytes' % len(hash))
        object.__setattr__(self, 'hash', hash)
        if not (0 <= n <= 0xffffffff):
            raise ValueError('COutPoint: n must be in range 0x0 to 0xffffffff; got %x' % n)
        object.__setattr__(self, 'n', n)

    @classmethod
    def stream_deserialize(cls, f):
        hash = ser_read(f, 32)
        n = struct.unpack(b"<I", ser_read(f, 4))[0]
        return cls(hash, n)

    def stream_serialize(self, f):
        assert len(self.hash) == 32
        f.write(self.hash)
        f.write(struct.pack(b"<I", self.n))

    def is_null(self):
        return ((self.hash == b'\x00'*32) and (self.n == 0xffffffff))

    def __repr__(self):
        if self.is_null():
            return 'COutPoint()'
        else:
            return 'COutPoint(lx(%r), %i)' % (b2lx(self.hash), self.n)

    def __str__(self):
        return '%s:%i' % (b2lx(self.hash), self.n)

    @classmethod
    def from_outpoint(cls, outpoint):
        """Create an immutable copy of an existing OutPoint

        If outpoint is already immutable, it is returned directly.
        """
        if not outpoint._immutable_restriction_lifted:
            return outpoint
        else:
            return cls(outpoint.hash, outpoint.n)


@__make_mutable
class CMutableOutPoint(COutPoint):
    """A mutable COutPoint"""
    __slots__ = []

    @classmethod
    def from_outpoint(cls, outpoint):
        """Create a mutable copy of an existing COutPoint"""
        return cls(outpoint.hash, outpoint.n)


class CTxInBase(ImmutableSerializable):
    """An input of a transaction

    Contains the location of the previous transaction's output that it claims,
    and a signature that matches the output's public key.
    """
    __slots__ = ['prevout', 'scriptSig', 'nSequence']

    def __init__(self, prevout=COutPoint(), scriptSig=CScript(), nSequence=0xffffffff):
        if not (0 <= nSequence <= 0xffffffff):
            raise ValueError('CTxIn: nSequence must be an integer between 0x0 and 0xffffffff; got %x' % nSequence)
        object.__setattr__(self, 'nSequence', nSequence)
        object.__setattr__(self, 'prevout', prevout)
        object.__setattr__(self, 'scriptSig', scriptSig)

    @classmethod
    def stream_deserialize(cls, f):
        prevout = COutPoint.stream_deserialize(f)
        scriptSig = script.CScript(BytesSerializer.stream_deserialize(f))
        nSequence = struct.unpack(b"<I", ser_read(f, 4))[0]
        return cls(prevout, scriptSig, nSequence)

    def stream_serialize(self, f):
        COutPoint.stream_serialize(self.prevout, f)
        BytesSerializer.stream_serialize(self.scriptSig, f)
        f.write(struct.pack(b"<I", self.nSequence))

    def is_final(self):
        return (self.nSequence == 0xffffffff)


class CBitcoinTxIn(CTxInBase):
    @classmethod
    def from_txin(cls, txin):
        """Create an immutable copy of an existing TxIn

        If txin is already immutable, it is returned directly.
        """
        if not txin._immutable_restriction_lifted:
            # txin is immutable, therefore returning same txin is OK
            return txin
        else:
            return cls(COutPoint.from_outpoint(txin.prevout), txin.scriptSig, txin.nSequence)

    def __repr__(self):
        return "CTxIn(%s, %s, 0x%x)" % (repr(self.prevout), repr(self.scriptSig), self.nSequence)


@__make_mutable
class CBitcoinMutableTxIn(CBitcoinTxIn):
    """A mutable CTxIn"""
    __slots__ = []

    def __init__(self, prevout=None, scriptSig=CScript(), nSequence=0xffffffff):
        if not (0 <= nSequence <= 0xffffffff):
            raise ValueError('CTxIn: nSequence must be an integer between 0x0 and 0xffffffff; got %x' % nSequence)
        self.nSequence = nSequence

        if prevout is None:
            prevout = CMutableOutPoint()
        self.prevout = prevout
        self.scriptSig = scriptSig

    @classmethod
    def from_txin(cls, txin):
        """Create a fully mutable copy of an existing TxIn"""
        prevout = CMutableOutPoint.from_outpoint(txin.prevout)
        return cls(prevout, txin.scriptSig, txin.nSequence)


class CTxOutBase(ImmutableSerializable):
    pass


class CBitcoinTxOut(CTxOutBase):
    """An output of a transaction

    Contains the public key that the next input must be able to sign with to
    claim it.
    """
    __slots__ = ['nValue', 'scriptPubKey']

    def __init__(self, nValue=-1, scriptPubKey=script.CScript()):
        object.__setattr__(self, 'nValue', int(nValue))
        object.__setattr__(self, 'scriptPubKey', scriptPubKey)

    @classmethod
    def stream_deserialize(cls, f):
        nValue = struct.unpack(b"<q", ser_read(f, 8))[0]
        scriptPubKey = script.CScript(BytesSerializer.stream_deserialize(f))
        return cls(nValue, scriptPubKey)

    def stream_serialize(self, f):
        f.write(struct.pack(b"<q", self.nValue))
        BytesSerializer.stream_serialize(self.scriptPubKey, f)

    def is_valid(self):
        if not MoneyRange(self.nValue):
            return False
        if not self.scriptPubKey.is_valid():
            return False
        return True

    def __repr__(self):
        return "CTxOut(%s, %r)" % (_str_money_value_for_repr(self.nValue), self.scriptPubKey)

    @classmethod
    def from_txout(cls, txout):
        """Create an immutable copy of an existing TxOut

        If txout is already immutable, then it will be returned directly.
        """
        if not txout._immutable_restriction_lifted:
            return txout
        else:
            return cls(txout.nValue, txout.scriptPubKey)


@__make_mutable
class CBitcoinMutableTxOut(CBitcoinTxOut):
    """A mutable CTxOut"""
    __slots__ = []

    @classmethod
    def from_txout(cls, txout):
        """Create a fullly mutable copy of an existing TxOut"""
        return cls(txout.nValue, txout.scriptPubKey)


class CTxInWitnessBase(ImmutableSerializable):
    pass


class CBitcoinTxInWitness(CTxInWitnessBase):
    """Witness data for a single transaction input"""
    __slots__ = ['scriptWitness']

    def __init__(self, scriptWitness=CScriptWitness()):
        object.__setattr__(self, 'scriptWitness', scriptWitness)

    def is_null(self):
        return self.scriptWitness.is_null()

    @classmethod
    def stream_deserialize(cls, f):
        scriptWitness = CScriptWitness.stream_deserialize(f)
        return cls(scriptWitness)

    def stream_serialize(self, f):
        self.scriptWitness.stream_serialize(f)

    def __repr__(self):
        return "CTxInWitness(%s)" % (repr(self.scriptWitness))


class CTxOutWitnessBase(ImmutableSerializable):
    pass


class _CBitcoinDummyTxOutWitness(CTxOutWitnessBase):
    pass


class CTxWitnessBase(ImmutableSerializable):
    pass


class CBitcoinTxWitness(CTxWitnessBase):
    """Witness data for all inputs to a transaction"""
    __slots__ = ['vtxinwit']
    _txin_witness_class = CBitcoinTxInWitness
    _txout_witness_class = _CBitcoinDummyTxOutWitness

    def __init__(self, vtxinwit=(), vtxoutwit=None):
        # Note: vtxoutwit is ignored, does not exist for bitcon tx witness
        object.__setattr__(self, 'vtxinwit', tuple(vtxinwit))

    def is_null(self):
        for n in range(len(self.vtxinwit)):
            if not self.vtxinwit[n].is_null():
                return False
        return True

    # NOTE: this cannot be a @classmethod like the others because we need to
    # know how many items to deserialize, which comes from len(vin)
    def stream_deserialize(self, f):
        vtxinwit = tuple(self._txin_witness_class.stream_deserialize(f)
                         for dummy in range(len(self.vtxinwit)))
        return self.__class__(vtxinwit)

    def stream_serialize(self, f):
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].stream_serialize(f)

    @classmethod
    def from_witness(cls, witness):
        if not cls._immutable_restriction_lifted:
            return witness
        return cls(witness.vtxinwit)

    def __repr__(self):
        return "CTxWitness([%s])" % (','.join(repr(w) for w in self.vtxinwit))


@__make_mutable
class CBitcoinMutableTxWitness(CBitcoinTxWitness):
    """Witness data for all inputs to a transaction, mutable version"""
    __slots__ = []

    def __init__(self, vtxinwit=(), vtxoutwit=None):
        # Note: vtxoutwit is ignored, does not exist for bitcon tx witness
        self.vtxinwit = list(vtxinwit)

    @classmethod
    def from_witness(cls, witness):
        return cls(witness.vtxinwit)


class CTransactionBase(ImmutableSerializable, _ReprOrStrMixin):
    """A transaction"""
    __slots__ = ['nVersion', 'vin', 'vout', 'nLockTime', 'wit']

    _witness_class = None
    _txin_class = None
    _txout_class = None

    CURRENT_VERSION = 2

    def __init__(self, vin=(), vout=(), nLockTime=0, nVersion=None, witness=None):
        """Create a new transaction

        vin and vout are iterables of transaction inputs and outputs
        respectively. If their contents are not already immutable, immutable
        copies will be made.
        """
        if not (0 <= nLockTime <= 0xffffffff):
            raise ValueError('CTransaction: nLockTime must be in range 0x0 to 0xffffffff; got %x' % nLockTime)

        if witness is None:
            witness = self._witness_class()

        if nVersion is None:
            nVersion = self.CURRENT_VERSION

        object.__setattr__(self, 'nLockTime', nLockTime)
        object.__setattr__(self, 'nVersion', nVersion)
        object.__setattr__(self, 'vin', tuple(self._txin_class.from_txin(txin) for txin in vin))
        object.__setattr__(self, 'vout', tuple(self._txout_class.from_txout(txout) for txout in vout))
        object.__setattr__(self, 'wit', self._witness_class.from_witness(witness))

    @classmethod
    def stream_deserialize(cls, f):
        """Deserialize transaction

        This implementation corresponds to Bitcoin's SerializeTransaction() and
        consensus behavior. Note that Bitcoin's DecodeHexTx() also has the
        option to attempt deserializing as a non-witness transaction first,
        falling back to the consensus behavior if it fails. The difference lies
        in transactions which have zero inputs: they are invalid but may be
        (de)serialized anyway for the purpose of signing them and adding
        inputs. If the behavior of DecodeHexTx() is needed it could be added,
        but not here.
        """
        # FIXME can't assume f is seekable
        nVersion = struct.unpack(b"<i", ser_read(f, 4))[0]
        pos = f.tell()

        markerbyte = 0
        if not issubclass(cls, CElementsSidechainTransaction):
            markerbyte = struct.unpack(b'B', ser_read(f, 1))[0]
        flagbyte = struct.unpack(b'B', ser_read(f, 1))[0]
        if markerbyte == 0 and flagbyte == 1:
            vin = VectorSerializer.stream_deserialize(cls._txin_class, f)
            vout = VectorSerializer.stream_deserialize(cls._txout_class, f)
            wit = cls._witness_class(tuple(0 for dummy in range(len(vin))),
                                     tuple(0 for dummy in range(len(vout))))
            wit = wit.stream_deserialize(f)
            nLockTime = struct.unpack(b"<I", ser_read(f, 4))[0]
            return cls(vin, vout, nLockTime, nVersion, wit)
        else:
            if not issubclass(cls, CElementsSidechainTransaction):
                f.seek(pos)  # put marker and flag bytes back, since we don't have peek
            vin = VectorSerializer.stream_deserialize(cls._txin_class, f)
            vout = VectorSerializer.stream_deserialize(cls._txout_class, f)
            nLockTime = struct.unpack(b"<I", ser_read(f, 4))[0]
            return cls(vin, vout, nLockTime, nVersion)

    def stream_serialize(self, f, include_witness=True):
        f.write(struct.pack(b"<i", self.nVersion))
        if include_witness and not self.wit.is_null():
            assert(len(self.wit.vtxinwit) == len(self.vin))
            if not isinstance(self, CElementsSidechainTransaction):
                f.write(b'\x00')  # Marker
            f.write(b'\x01')  # Flag
            VectorSerializer.stream_serialize(self._txin_class, self.vin, f)
            VectorSerializer.stream_serialize(self._txout_class, self.vout, f)
            self.wit.stream_serialize(f)
        else:
            if isinstance(self, CElementsSidechainTransaction):
                f.write(b'\x00')  # Flag is needed in Elements sidechain
            VectorSerializer.stream_serialize(self._txin_class, self.vin, f)
            VectorSerializer.stream_serialize(self._txout_class, self.vout, f)
        f.write(struct.pack(b"<I", self.nLockTime))

    def is_coinbase(self):
        return len(self.vin) == 1 and self.vin[0].prevout.is_null()

    def has_witness(self):
        """True if witness"""
        return not self.wit.is_null()

    def _repr_or_str(self, strfn):
        return "CTransaction(%r, %r, %i, %i, %r)" % ([strfn(v) for v in self.vin],
                                                     [strfn(v) for v in self.vout],
                                                     self.nLockTime, self.nVersion, strfn(self.wit))

    def GetTxid(self):
        """Get the transaction ID.  This differs from the transactions hash as
            given by GetHash.  GetTxid excludes witness data, while GetHash
            includes it. """

        if not self.wit.is_null():
            txid = Hash(CTransaction(self.vin, self.vout, self.nLockTime,
                                     self.nVersion).serialize())
        else:
            txid = Hash(self.serialize())
        return txid

    def to_mutable(self):
        if self._immutable_restriction_lifted:
            return self.__class__.from_tx(self)
        return self._inverted_mutability_class.from_tx(self)

    def to_immutable(self):
        if not self._immutable_restriction_lifted:
            return self.__class__.from_tx(self)
        return self._inverted_mutability_class.from_tx(self)


class CImmutableTransactionBase(CTransactionBase):
    @classmethod
    def from_tx(cls, tx):
        """Create an immutable copy of a pre-existing transaction

        If tx is already immutable, then it will be returned directly.
        """

        if not tx._immutable_restriction_lifted:
            # tx is immutable, therefore returning same tx is OK
            return tx

        return cls(tx.vin, tx.vout, tx.nLockTime, tx.nVersion, tx.wit)


@__make_mutable
class CMutableTransactionBase(CTransactionBase):
    """A mutable transaction"""
    __slots__ = []

    def __init__(self, vin=None, vout=None, nLockTime=0, nVersion=None, witness=None):
        if not (0 <= nLockTime <= 0xffffffff):
            raise ValueError('CTransaction: nLockTime must be in range 0x0 to 0xffffffff; got %x' % nLockTime)

        if nVersion is None:
            nVersion = self.CURRENT_VERSION

        self.nLockTime = nLockTime

        if vin is None:
            vin = []
        self.vin = vin

        if vout is None:
            vout = []
        self.vout = vout
        self.nVersion = nVersion

        if witness is None:
            wclass = self._witness_class
            witness = wclass([wclass._txin_witness_class() for dummy in range(len(vin))],
                             [wclass._txout_witness_class() for dummy in range(len(vout))])
        self.wit = witness

    @classmethod
    def from_tx(cls, tx):
        """Create a fully mutable copy of a pre-existing transaction"""

        # tx is mutable, we should always return new instance
        vin = [CMutableTxIn.from_txin(txin) for txin in tx.vin]
        vout = [CMutableTxOut.from_txout(txout) for txout in tx.vout]
        return cls(vin, vout, tx.nLockTime, tx.nVersion, tx.wit)


class CBitcoinMutableTransaction(CMutableTransactionBase):
    # _inverted_mutability_class will be set in _SelectAlternativeCoreParams
    _witness_class = CBitcoinMutableTxWitness
    _txin_class = CBitcoinMutableTxIn
    _txout_class = CBitcoinMutableTxOut


class CBitcoinTransaction(CImmutableTransactionBase):
    _inverted_mutability_class = CBitcoinMutableTransaction
    _witness_class = CBitcoinTxWitness
    _txin_class = CBitcoinTxIn
    _txout_class = CBitcoinTxOut


class WitnessSerializationError(SerializationError):
    pass


class TxInSerializationError(SerializationError):
    pass


class CConfidentialCommitmentBase(ImmutableSerializable):
    _explicitSize = None
    _prefixA = None
    _prefixB = None

    _committedSize = 33

    __slots__ = ['commitment']

    def __init__(self, commitment=b''):
        object.__setattr__(self, 'commitment', commitment)

    @classmethod
    def stream_deserialize(cls, f):
        version = ser_read(f, 1)[0]
        read_size = 0
        if version == 0:
            read_size = 0
        elif version == 1:
            read_size = cls._explicitSize
        elif version in (cls._prefixA, cls._prefixB):
            read_size = cls._committedSize
        else:
            raise WitnessSerializationError('Unrecognized serialization prefix')

        if read_size > 0:
            commitment = bytes([version]) + ser_read(f, read_size-1)
        else:
            commitment = b''

        return cls(commitment)

    def stream_serialize(self, f):
        if len(self.commitment):
            f.write(self.commitment)
        else:
            f.write(bytes([0]))

    def is_null(self):
        return not len(self.commitment)

    def is_explicit(self):
        return (len(self.commitment) == self._explicitSize
                and self.commitment[0] == 1)

    def is_commitment(self):
        return (len(self.commitment) == self._committedSize
                and self.commitment[0] in (self._prefixB, self._prefixB))

    def is_valid(self):
        return self.is_null() or self.is_explicit() or self.is_commitment()

    def _get_explicit(self):
        raise NotImplementedError

    def __str__(self):
        if self.is_explicit():
            v = str(self._get_explicit())
        else:
            v = 'CONFIDENTIAL'
        return "{}({})".format(self.__class__.__name__, v)

    def __repr__(self):
        if self.is_explicit():
            v = repr(self._get_explicit())
        else:
            v = _bytes_for_repr(self.commitment)
        return "{}({})".format(self.__class__.__name__, v)


class CAsset(_Uint256):
    @property
    def id(self):
        return self.data

    def __repr__(self):
        return "CAsset({})".format(_bytes_for_repr(self.id, hexfun_name='lx'))


class CConfidentialAsset(CConfidentialCommitmentBase):
    _explicitSize = 33
    _prefixA = 10
    _prefixB = 11

    def __init__(self, asset_or_commitment=b''):
        if isinstance(asset_or_commitment, CAsset):
            commitment = bytes([1]) + asset_or_commitment
        else:
            commitment = asset_or_commitment
        super(CConfidentialAsset, self).__init__(commitment)

    @classmethod
    def from_asset(cls, asset):
        assert isinstance(asset, CAsset)
        return cls(asset)

    def to_asset(self):
        assert self.is_explicit()
        return CAsset(self.commitment[1:])

    def _get_explicit(self):
        return self.to_asset()


class CConfidentialValue(CConfidentialCommitmentBase):
    _explicitSize = 9
    _prefixA = 8
    _prefixB = 9

    def __init__(self, value_or_commitment=b''):
        if isinstance(value_or_commitment, int):
            commitment = bytes([1]) + struct.pack(b"<q", value_or_commitment)
        else:
            commitment = value_or_commitment
        super(CConfidentialValue, self).__init__(commitment)

    @classmethod
    def from_amount(cls, amount):
        assert isinstance(amount, int)
        return cls(amount)

    def to_amount(self):
        assert self.is_explicit()
        return struct.unpack(b"<q", self.commitment[1:])[0]

    def _get_explicit(self):
        return self.to_amount()


class CConfidentialNonce(CConfidentialCommitmentBase):
    _explicitSize = 33
    _prefixA = 2
    _prefixB = 3

    def _get_explicit(self):
        return 'CONFIDENTIAL'

    def __repr__(self):
        v = "x('{}')".format(b2x(self.commitment))
        return "{}({})".format(self.__class__.__name__, v)


class CElementsSidechainTxInWitness(CTxInWitnessBase, _ReprOrStrMixin):
    """Witness data for a single transaction input of elements sidechain transaction"""
    __slots__ = ['scriptWitness',
                 'issuanceAmountRangeproof', 'inflationKeysRangeproof', 'pegin_witness']

    # put scriptWitness first for CTxInWitness(script_witness) to work
    # the same as with CBitcoinTxInWitness.
    def __init__(self, scriptWitness=CScriptWitness(),
                 issuanceAmountRangeproof=b'', inflationKeysRangeproof=b'',
                 pegin_witness=CScriptWitness()):
        assert isinstance(issuanceAmountRangeproof, bytes)
        assert isinstance(inflationKeysRangeproof, bytes)
        object.__setattr__(self, 'scriptWitness', scriptWitness)
        object.__setattr__(self, 'issuanceAmountRangeproof', CScript(issuanceAmountRangeproof))
        object.__setattr__(self, 'inflationKeysRangeproof', CScript(inflationKeysRangeproof))
        object.__setattr__(self, 'pegin_witness', pegin_witness)

    def is_null(self):
        return (not len(self.issuanceAmountRangeproof)
                and not len(self.inflationKeysRangeproof)
                and self.scriptWitness.is_null()
                and self.pegin_witness.is_null())

    @classmethod
    def stream_deserialize(cls, f):
        issuanceAmountRangeproof = script.CScript(BytesSerializer.stream_deserialize(f))
        inflationKeysRangeproof = script.CScript(BytesSerializer.stream_deserialize(f))
        scriptWitness = CScriptWitness.stream_deserialize(f)
        pegin_witness = CScriptWitness.stream_deserialize(f)
        return cls(scriptWitness, issuanceAmountRangeproof, inflationKeysRangeproof,
                   pegin_witness)

    def stream_serialize(self, f):
        BytesSerializer.stream_serialize(self.issuanceAmountRangeproof, f)
        BytesSerializer.stream_serialize(self.inflationKeysRangeproof, f)
        self.scriptWitness.stream_serialize(f)
        self.pegin_witness.stream_serialize(f)

    def _repr_or_str(self, strfn):
        return "CTxInWitness({}, {}, {}, {})".format(
            strfn(self.scriptWitness), _bytes_for_repr(self.issuanceAmountRangeproof),
            _bytes_for_repr(self.inflationKeysRangeproof), strfn(self.pegin_witness))


class CElementsSidechainTxOutWitness(CTxOutWitnessBase):
    """Witness data for a single transaction output of elements sidechain transaction"""
    __slots__ = ['surjectionProof', 'rangeproof']

    def __init__(self, surjectionProof=b'', rangeproof=b''):
        assert isinstance(surjectionProof, bytes)
        assert isinstance(rangeproof, bytes)
        object.__setattr__(self, 'surjectionProof', CScript(surjectionProof))
        object.__setattr__(self, 'rangeproof', CScript(rangeproof))

    def is_null(self):
        return not len(self.surjectionProof) and not len(self.rangeproof)

    @classmethod
    def stream_deserialize(cls, f):
        surjectionProof = script.CScript(BytesSerializer.stream_deserialize(f))
        rangeproof = script.CScript(BytesSerializer.stream_deserialize(f))
        return cls(surjectionProof, rangeproof)

    def stream_serialize(self, f):
        BytesSerializer.stream_serialize(self.surjectionProof, f)
        BytesSerializer.stream_serialize(self.rangeproof, f)

    def __repr__(self):
        return "CTxOutWitness({}, {})".format(
            _bytes_for_repr(self.surjectionProof),
            _bytes_for_repr(self.rangeproof))


class CElementsSidechainTxWitness(CTxWitnessBase, _ReprOrStrMixin):
    _txin_witness_class = CElementsSidechainTxInWitness
    _txout_witness_class = CElementsSidechainTxOutWitness

    __slots__ = ['vtxinwit', 'vtxoutwit']

    def __init__(self, vtxinwit=(), vtxoutwit=()):
        object.__setattr__(self, 'vtxinwit', tuple(vtxinwit))
        object.__setattr__(self, 'vtxoutwit', tuple(vtxoutwit))

    def is_null(self):
        for n in range(len(self.vtxinwit)):
            if not self.vtxinwit[n].is_null():
                return False
        for n in range(len(self.vtxoutwit)):
            if not self.vtxoutwit[n].is_null():
                return False
        return True

    # NOTE: this cannot be a @classmethod like the others because we need to
    # know how many items to deserialize, which comes from len(vin)
    def stream_deserialize(self, f):
        vtxinwit = tuple(self._txin_witness_class.stream_deserialize(f) for dummy in
                         range(len(self.vtxinwit)))
        vtxoutwit = tuple(self._txout_witness_class.stream_deserialize(f) for dummy in
                          range(len(self.vtxoutwit)))
        return self.__class__(vtxinwit, vtxoutwit)

    def stream_serialize(self, f):
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].stream_serialize(f)
        for i in range(len(self.vtxoutwit)):
            self.vtxoutwit[i].stream_serialize(f)

    @classmethod
    def from_witness(cls, witness):
        if not cls._immutable_restriction_lifted:
            return witness
        return cls(witness.vtxinwit, witness.vtxoutwit)

    def _repr_or_str(self, strfn):
        return "CTxWitness([%s], [%s])" % (','.join(strfn(w) for w in self.vtxinwit),
                                           (','.join(strfn(w) for w in self.vtxoutwit)))


@__make_mutable
class CElementsSidechainMutableTxWitness(CElementsSidechainTxWitness):
    __slots__ = []

    def __init__(self, vtxinwit=(), vtxoutwit=()):
        self.vtxinwit = list(vtxinwit)
        self.vtxoutwit = list(vtxoutwit)

    @classmethod
    def from_witness(cls, witness):
        return cls(witness.vtxinwit, witness.vtxoutwit)


class CAssetIssuance(ImmutableSerializable, _ReprOrStrMixin):
    __slots__ = ['assetBlindingNonce', 'assetEntropy', 'nAmount', 'nInflationKeys']

    def __init__(self, assetBlindingNonce=_Uint256(), assetEntropy=_Uint256(),
                 nAmount=CConfidentialValue(), nInflationKeys=CConfidentialValue()):
        object.__setattr__(self, 'assetBlindingNonce', assetBlindingNonce)
        object.__setattr__(self, 'assetEntropy', assetEntropy)
        object.__setattr__(self, 'nAmount', nAmount)
        object.__setattr__(self, 'nInflationKeys', nInflationKeys)

    def is_null(self):
        return self.nAmount.is_null() and self.nInflationKeys.is_null()

    @classmethod
    def stream_deserialize(cls, f):
        assetBlindingNonce = _Uint256.stream_deserialize(f)
        assetEntropy = _Uint256.stream_deserialize(f)
        nAmount = CConfidentialValue.stream_deserialize(f)
        nInflationKeys = CConfidentialValue.stream_deserialize(f)
        return cls(assetBlindingNonce, assetEntropy, nAmount, nInflationKeys)

    def stream_serialize(self, f):
        self.assetBlindingNonce.stream_serialize(f)
        self.assetEntropy.stream_serialize(f)
        self.nAmount.stream_serialize(f)
        self.nInflationKeys.stream_serialize(f)

    def _repr_or_str(self, strfn):
        r = ["CAssetIssuance({}, {}".format(
            _bytes_for_repr(self.assetBlindingNonce.data),
            _bytes_for_repr(self.assetEntropy.data))]
        if not self.nAmount.is_null():
            r.append(', nAmount={}'.format(strfn(self.nAmount)))
        if not self.nInflationKeys.is_null():
            r.append(', nInflationKeys={}'.format(strfn(self.nInflationKeys)))
        r.append(')')
        return ''.join(r)


class CElementsSidechainTxIn(CTxInBase, _ReprOrStrMixin):
    """An input of an Elements sidechain transaction
    """
    __slots__ = ['prevout', 'scriptSig', 'nSequence', 'assetIssuance', 'is_pegin']

    def __init__(self, prevout=COutPoint(), scriptSig=CScript(), nSequence=0xffffffff,
                 assetIssuance=CAssetIssuance(), is_pegin=False):
        super(CElementsSidechainTxIn, self).__init__(prevout, scriptSig, nSequence)
        object.__setattr__(self, 'assetIssuance', assetIssuance)
        object.__setattr__(self, 'is_pegin', is_pegin)

    @classmethod
    def stream_deserialize(cls, f):
        base = CTxInBase.stream_deserialize(f)
        if base.prevout.n == 0xffffffff:
            # No asset issuance for Coinbase inputs.
            has_asset_issuance = False
            is_pegin = False
            prevout = base.prevout
        else:
            # The presence of the asset issuance object is indicated by
            # a bit set in the outpoint index field.
            has_asset_issuance = bool(base.prevout.n & OUTPOINT_ISSUANCE_FLAG)
            # The interpretation of this input as a peg-in is indicated by
            # a bit set in the outpoint index field.
            is_pegin = bool(base.prevout.n & OUTPOINT_PEGIN_FLAG)
            # The mode, if set, must be masked out of the outpoint so
            # that the in-memory index field retains its traditional
            # meaning of identifying the index into the output array
            # of the previous transaction.
            prevout = COutPoint(base.prevout.hash,
                                base.prevout.n & OUTPOINT_INDEX_MASK)

        if has_asset_issuance:
            assetIssuance = CAssetIssuance.stream_deserialize(f)
        else:
            assetIssuance = CAssetIssuance()

        return cls(prevout, base.scriptSig, base.nSequence, assetIssuance, is_pegin)

    def stream_serialize(self, f):
        if self.prevout.n == 0xffffffff:
            has_asset_issuance = False
            outpoint = self.prevout
        else:
            if self.prevout.n & ~OUTPOINT_INDEX_MASK:
                raise TxInSerializationError('High bits of prevout.n should not be set')

            has_asset_issuance = not self.assetIssuance.is_null()
            n = self.prevout.n & OUTPOINT_INDEX_MASK
            if has_asset_issuance:
                n |= OUTPOINT_ISSUANCE_FLAG
            if self.is_pegin:
                n |= OUTPOINT_PEGIN_FLAG
            outpoint = COutPoint(self.prevout.hash, n)

        COutPoint.stream_serialize(outpoint, f)
        BytesSerializer.stream_serialize(self.scriptSig, f)
        f.write(struct.pack(b"<I", self.nSequence))

        if has_asset_issuance:
            self.assetIssuance.stream_serialize(f)

    @classmethod
    def from_txin(cls, txin):
        """Create an immutable copy of an existing TxIn

        If txin is already immutable, it is returned directly.
        """
        if not txin._immutable_restriction_lifted:
            # txin is immutable, therefore returning same txin is OK
            return txin
        else:
            return cls(COutPoint.from_outpoint(txin.prevout), txin.scriptSig, txin.nSequence,
                       txin.assetIssuance)

    def _repr_or_str(self, strfn):
        return "CTxIn(%s, %s, 0x%x, %s)" % (strfn(self.prevout), repr(self.scriptSig),
                                            self.nSequence, strfn(self.assetIssuance))


@__make_mutable
class CElementsSidechainMutableTxIn(CElementsSidechainTxIn):
    """A mutable Elements sidechain CTxIn"""
    __slots__ = []

    def __init__(self, prevout=None, scriptSig=CScript(), nSequence=0xffffffff,
                 assetIssuance=CAssetIssuance):
        super(CElementsSidechainTxIn, self).__init__(prevout, scriptSig, nSequence)
        self.assetIssuance = assetIssuance

    @classmethod
    def from_txin(cls, txin):
        """Create a fully mutable copy of an existing Elements sidechain TxIn"""
        prevout = CMutableOutPoint.from_outpoint(txin.prevout)
        return cls(prevout, txin.scriptSig, txin.nSequence, txin.assetIssuance)


class CElementsSidechainTxOut(CTxOutBase, _ReprOrStrMixin):
    """An output of an Elements sidechain transaction
    """
    __slots__ = ['nValue', 'scriptPubKey', 'nAsset', 'nNonce']

    # nValue and scriptPubKey is first to be compatible with
    # CTxOut(nValue, scriptPubKey) calls
    def __init__(self, nValue=CConfidentialValue, scriptPubKey=script.CScript(),
                 nAsset=CConfidentialAsset, nNonce=CConfidentialNonce):
        assert isinstance(nValue, CConfidentialValue)
        assert isinstance(nAsset, CConfidentialAsset)
        assert isinstance(nNonce, CConfidentialNonce)
        object.__setattr__(self, 'nAsset', nAsset)
        object.__setattr__(self, 'nValue', nValue)
        object.__setattr__(self, 'nNonce', nNonce)
        object.__setattr__(self, 'scriptPubKey', scriptPubKey)

    @classmethod
    def stream_deserialize(cls, f):
        nAsset = CConfidentialAsset.stream_deserialize(f)
        nValue = CConfidentialValue.stream_deserialize(f)
        nNonce = CConfidentialNonce.stream_deserialize(f)
        scriptPubKey = script.CScript(BytesSerializer.stream_deserialize(f))
        return cls(nValue, scriptPubKey, nAsset, nNonce)

    def stream_serialize(self, f):
        self.nAsset.stream_serialize(f)
        self.nValue.stream_serialize(f)
        self.nNonce.stream_serialize(f)
        BytesSerializer.stream_serialize(self.scriptPubKey, f)

    def is_null(self):
        return (self.nAsset.is_null() and self.nValue.is_null()
                and self.nNonce.is_null() and not len(self.scriptPubKey))

    def is_fee(self):
        return (not len(self.scriptPubKey)
                and self.nValue.is_explicit()
                and self.nAsset.is_explicit())

    def _repr_or_str(self, strfn):
        return "CTxOut({}, {}, {})".format(
            strfn(self.nValue), repr(self.scriptPubKey), strfn(self.nAsset))

    @classmethod
    def from_txout(cls, txout):
        """Create an immutable copy of an existing Elements sidechain TxOut

        If txout is already immutable, then it will be returned directly.
        """
        if not txout._immutable_restriction_lifted:
            return txout
        else:
            return cls(txout.nValue, txout.scriptPubKey,
                       txout.nAsset, txout.nNonce)


@__make_mutable
class CElementsSidechainMutableTxOut(CElementsSidechainTxOut):
    __slots__ = []

    @classmethod
    def from_txout(cls, txout):
        """Create a fullly mutable copy of an existing Elements sidechain TxOut"""
        return cls(txout.nValue, txout.scriptPubKey,
                   txout.nAsset, txout.nNonce)


class CElementsSidechainMutableTransaction(CMutableTransactionBase):
    # _inverted_mutability_class will be set in _SelectAlternativeCoreParams
    _witness_class = CElementsSidechainTxWitness
    _txin_class = CElementsSidechainMutableTxIn
    _txout_class = CElementsSidechainMutableTxOut


class CElementsSidechainTransaction(CImmutableTransactionBase):
    _inverted_mutability_class = CElementsSidechainMutableTransaction
    _witness_class = CElementsSidechainMutableTxWitness
    _txin_class = CElementsSidechainTxIn
    _txout_class = CElementsSidechainTxOut


class _ParamsTag():
    pass


class CoreChainParams(object):
    """Define consensus-critical parameters of a given instance of the Bitcoin system"""
    MAX_MONEY = None
    GENESIS_BLOCK = None
    PROOF_OF_WORK_LIMIT = None
    SUBSIDY_HALVING_INTERVAL = None
    NAME = None


class CoreMainParams(CoreChainParams, _ParamsTag):
    MAX_MONEY = 21000000 * COIN
    NAME = 'mainnet'
    SUBSIDY_HALVING_INTERVAL = 210000
    PROOF_OF_WORK_LIMIT = 2**256-1 >> 32
    TRANSACTION_CLASS = CBitcoinTransaction


class CoreElementsSidechainParams(CoreMainParams, _ParamsTag):
    NAME = 'elements-sidechain'
    GENESIS_BLOCK = None
    SUBSIDY_HALVING_INTERVAL = None
    PROOF_OF_WORK_LIMIT = None
    TRANSACTION_CLASS = CElementsSidechainTransaction


class CoreTestNetParams(CoreMainParams, _ParamsTag):
    NAME = 'testnet'


class CoreRegTestParams(CoreTestNetParams, _ParamsTag):
    NAME = 'regtest'
    SUBSIDY_HALVING_INTERVAL = 150
    PROOF_OF_WORK_LIMIT = 2**256-1 >> 1

"""Master global setting for what core chain params we're using"""
coreparams = CoreMainParams()


def _SelectAlternativeCoreParams(alt_core_params):
    """Select the core chain parameters to use

    Don't use this directly, use bitcointx.SelectAlternativeParams()
    """
    global coreparams

    assert(issubclass(alt_core_params, CoreChainParams))

    coreparams = alt_core_params()

    _SetTransactionClassParams()


def _SelectCoreParams(name):
    """Select the core chain parameters to use

    Don't use this directly, use bitcointx.SelectParams() instead so both
    consensus-critical and general parameters are set properly.
    """
    global coreparams

    for cls in _ParamsTag.__subclasses__():
        if name == cls.NAME:
            coreparams = cls()
            break
    else:
        raise ValueError('Unknown chain %r' % name)

    _SetTransactionClassParams()


class CheckTransactionError(ValidationError):
    pass


def CheckTransaction(tx):
    """Basic transaction checks that don't depend on any context.

    Raises CheckTransactionError
    """
    global coreparams

    if not tx.vin:
        raise CheckTransactionError("CheckTransaction() : vin empty")
    if not tx.vout:
        raise CheckTransactionError("CheckTransaction() : vout empty")

    # Size limits
    base_tx = tx.to_immutable()
    if len(base_tx.serialize()) > MAX_BLOCK_SIZE:
        raise CheckTransactionError("CheckTransaction() : size limits failed")

    # Check for negative or overflow output values
    nValueOut = 0
    for txout in tx.vout:
        if txout.nValue < 0:
            raise CheckTransactionError("CheckTransaction() : txout.nValue negative")
        if txout.nValue > coreparams.MAX_MONEY:
            raise CheckTransactionError("CheckTransaction() : txout.nValue too high")
        nValueOut += txout.nValue
        if not MoneyRange(nValueOut):
            raise CheckTransactionError("CheckTransaction() : txout total out of range")

    # Check for duplicate inputs
    vin_outpoints = set()
    for txin in tx.vin:
        if txin.prevout in vin_outpoints:
            raise CheckTransactionError("CheckTransaction() : duplicate inputs")
        vin_outpoints.add(txin.prevout)

    if tx.is_coinbase():
        if not (2 <= len(tx.vin[0].scriptSig) <= 100):
            raise CheckTransactionError("CheckTransaction() : coinbase script size")

    else:
        for txin in tx.vin:
            if txin.prevout.is_null():
                raise CheckTransactionError("CheckTransaction() : prevout is null")


def GetLegacySigOpCount(tx):
    nSigOps = 0
    for txin in tx.vin:
        nSigOps += txin.scriptSig.GetSigOpCount(False)
    for txout in tx.vout:
        nSigOps += txout.scriptPubKey.GetSigOpCount(False)
    return nSigOps


class _TransactionClassParamsBase():
    def __new__(cls, *args, **kwargs):
        real_class = _transaction_class_params[cls]
        return real_class(*args, **kwargs)


class _TransactionClassParamsMeta(type):
    def __new__(cls, name, bases, dct):
        bases = [_TransactionClassParamsBase] + list(bases)
        return super(_TransactionClassParamsMeta, cls).__new__(cls, name, tuple(bases), dct)

    def __getattr__(cls, name):
        real_class = _transaction_class_params[cls]
        return getattr(real_class, name)


class CTransaction(metaclass=_TransactionClassParamsMeta):
    pass


class CMutableTransaction(metaclass=_TransactionClassParamsMeta):
    pass


class CTxWitness(metaclass=_TransactionClassParamsMeta):
    pass


class CMutableTxWitness(metaclass=_TransactionClassParamsMeta):
    pass


class CTxInWitness(metaclass=_TransactionClassParamsMeta):
    pass


class CTxOutWitness(metaclass=_TransactionClassParamsMeta):
    pass


class CTxIn(metaclass=_TransactionClassParamsMeta):
    pass


class CMutableTxIn(metaclass=_TransactionClassParamsMeta):
    pass


class CTxOut(metaclass=_TransactionClassParamsMeta):
    pass


class CMutableTxOut(metaclass=_TransactionClassParamsMeta):
    pass


def _SetTransactionClassParams():
    imm_class = coreparams.TRANSACTION_CLASS
    mut_class = coreparams.TRANSACTION_CLASS._inverted_mutability_class
    mut_class._inverted_mutability_class = imm_class

    _transaction_class_params[CTransaction] = imm_class
    _transaction_class_params[CMutableTransaction] = mut_class
    _transaction_class_params[CTxWitness] = imm_class._witness_class
    _transaction_class_params[CMutableTxWitness] = imm_class._witness_class
    _transaction_class_params[CTxInWitness] = imm_class._witness_class._txin_witness_class
    _transaction_class_params[CTxOutWitness] = imm_class._witness_class._txout_witness_class
    _transaction_class_params[CTxIn] = imm_class._txin_class
    _transaction_class_params[CMutableTxIn] = mut_class._txin_class
    _transaction_class_params[CTxOut] = imm_class._txout_class
    _transaction_class_params[CMutableTxOut] = mut_class._txout_class


_SetTransactionClassParams()

__all__ = (
        'Hash',
        'Hash160',
        'COIN',
        'MAX_BLOCK_SIZE',
        'MAX_BLOCK_SIGOPS',
        'MoneyRange',
        'x',
        'b2x',
        'lx',
        'b2lx',
        'str_money_value',
        'ValidationError',
        'COutPoint',
        'CMutableOutPoint',
        'CAssetIssuance',
        'CTxIn',
        'CMutableTxIn',
        'CTxOut',
        'CMutableTxOut',
        'CTransaction',
        'CMutableTransaction',
        'CTxWitness',
        'CTxInWitness',
        'CTxOutWitness',
        'CoreChainParams',
        'CoreMainParams',
        'CoreTestNetParams',
        'CoreRegTestParams',
        'CheckTransactionError',
        'CheckTransaction',
        'GetLegacySigOpCount',
        'CAsset',
        'CConfidentialAsset',
        'CConfidentialValue',
        'CConfidentialNonce',
)
