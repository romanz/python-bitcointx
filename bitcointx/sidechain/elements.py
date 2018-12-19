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

# If this flag is set, the CTxIn including this COutPoint has a CAssetIssuance object.
OUTPOINT_ISSUANCE_FLAG = (1 << 31)
# If this flag is set, the CTxIn including this COutPoint is a peg-in input.
OUTPOINT_PEGIN_FLAG = (1 << 30)
# The inverse of the combination of the preceeding flags. Used to
# extract the original meaning of `n` as the index into the
# transaction's output array. */
OUTPOINT_INDEX_MASK = 0x3fffffff

import struct

from bitcointx.core import (
    CoreMainParams, Uint256,
    bytes_for_repr, ReprOrStrMixin, b2x,
    CTxWitnessBase, CTxInWitnessBase, CTxOutWitnessBase,
    CTxInBase, CTxOutBase, COutPoint, CMutableOutPoint,
    CImmutableTransactionBase, CMutableTransactionBase
)
from bitcointx.core.script import CScript, CScriptWitness
from bitcointx.core.sha256 import CSHA256
from bitcointx.core.serialize import (
    ImmutableSerializable, SerializationError,
    BytesSerializer, VectorSerializer,
    ser_read, make_mutable
)


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
            v = bytes_for_repr(self.commitment)
        return "{}({})".format(self.__class__.__name__, v)


class CAsset():
    __slots__ = ['id']

    def __init__(self, id=Uint256()):
        if not isinstance(id, Uint256):
            id = Uint256(id)
        object.__setattr__(self, 'id', id)

    def __repr__(self):
        return "CAsset({})".format(self.id)


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
            commitment = bytes([1]) + struct.pack(b">q", value_or_commitment)
        else:
            commitment = value_or_commitment
        super(CConfidentialValue, self).__init__(commitment)

    @classmethod
    def from_amount(cls, amount):
        assert isinstance(amount, int)
        return cls(amount)

    def to_amount(self):
        assert self.is_explicit()
        return struct.unpack(b">q", self.commitment[1:])[0]

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


class CElementsSidechainTxInWitness(CTxInWitnessBase, ReprOrStrMixin):
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
        # Note that scriptWitness/pegin_witness naming convention mismatch
        # exists in reference client code, and is retained here.
        object.__setattr__(self, 'pegin_witness', pegin_witness)

    def is_null(self):
        return (not len(self.issuanceAmountRangeproof)
                and not len(self.inflationKeysRangeproof)
                and self.scriptWitness.is_null()
                and self.pegin_witness.is_null())

    @classmethod
    def stream_deserialize(cls, f):
        issuanceAmountRangeproof = CScript(BytesSerializer.stream_deserialize(f))
        inflationKeysRangeproof = CScript(BytesSerializer.stream_deserialize(f))
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
        if self.is_null():
            return "CTxInWitness()"
        return "CTxInWitness({}, {}, {}, {})".format(
            strfn(self.scriptWitness), bytes_for_repr(self.issuanceAmountRangeproof),
            bytes_for_repr(self.inflationKeysRangeproof), strfn(self.pegin_witness))


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
        surjectionProof = CScript(BytesSerializer.stream_deserialize(f))
        rangeproof = CScript(BytesSerializer.stream_deserialize(f))
        return cls(surjectionProof, rangeproof)

    def stream_serialize(self, f):
        BytesSerializer.stream_serialize(self.surjectionProof, f)
        BytesSerializer.stream_serialize(self.rangeproof, f)

    def __repr__(self):
        if self.is_null():
            return "CTxOutWitness()"
        return "CTxOutWitness({}, {})".format(
            bytes_for_repr(self.surjectionProof),
            bytes_for_repr(self.rangeproof))


class CElementsSidechainTxWitness(CTxWitnessBase, ReprOrStrMixin):
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


@make_mutable
class CElementsSidechainMutableTxWitness(CElementsSidechainTxWitness):
    __slots__ = []

    def __init__(self, vtxinwit=(), vtxoutwit=()):
        self.vtxinwit = list(vtxinwit)
        self.vtxoutwit = list(vtxoutwit)

    @classmethod
    def from_witness(cls, witness):
        return cls(witness.vtxinwit, witness.vtxoutwit)


class CAssetIssuance(ImmutableSerializable, ReprOrStrMixin):
    __slots__ = ['assetBlindingNonce', 'assetEntropy', 'nAmount', 'nInflationKeys']

    def __init__(self, assetBlindingNonce=Uint256(), assetEntropy=Uint256(),
                 nAmount=CConfidentialValue(), nInflationKeys=CConfidentialValue()):
        object.__setattr__(self, 'assetBlindingNonce', assetBlindingNonce)
        object.__setattr__(self, 'assetEntropy', assetEntropy)
        object.__setattr__(self, 'nAmount', nAmount)
        object.__setattr__(self, 'nInflationKeys', nInflationKeys)

    def is_null(self):
        return self.nAmount.is_null() and self.nInflationKeys.is_null()

    @classmethod
    def stream_deserialize(cls, f):
        assetBlindingNonce = Uint256.stream_deserialize(f)
        assetEntropy = Uint256.stream_deserialize(f)
        nAmount = CConfidentialValue.stream_deserialize(f)
        nInflationKeys = CConfidentialValue.stream_deserialize(f)
        return cls(assetBlindingNonce, assetEntropy, nAmount, nInflationKeys)

    def stream_serialize(self, f):
        self.assetBlindingNonce.stream_serialize(f)
        self.assetEntropy.stream_serialize(f)
        self.nAmount.stream_serialize(f)
        self.nInflationKeys.stream_serialize(f)

    def _repr_or_str(self, strfn):
        r = []
        if self.assetBlindingNonce.to_int():
            r.append(bytes_for_repr(self.assetBlindingNonce.data))
        if self.assetEntropy.to_int():
            r.append(bytes_for_repr(self.assetEntropy.data))
        if not self.nAmount.is_null():
            r.append(strfn(self.nAmount))
        if not self.nInflationKeys.is_null():
            r.append(strfn(self.nInflationKeys))
        return 'CAssetIssuance({})'.format(', '.join(r))


class CElementsSidechainTxIn(CTxInBase, ReprOrStrMixin):
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
        return "CTxIn(%s, %s, 0x%x, %s, %r)" % (strfn(self.prevout), repr(self.scriptSig),
                                                self.nSequence, strfn(self.assetIssuance),
                                                self.is_pegin)


@make_mutable
class CElementsSidechainMutableTxIn(CElementsSidechainTxIn):
    """A mutable Elements sidechain CTxIn"""
    __slots__ = []

    def __init__(self, prevout=None, scriptSig=CScript(), nSequence=0xffffffff,
                 assetIssuance=CAssetIssuance(), is_pegin=False):
        if prevout is None:
            prevout = CMutableOutPoint()
        super(CElementsSidechainMutableTxIn, self).__init__(prevout, scriptSig, nSequence,
                                                            assetIssuance, is_pegin)

    @classmethod
    def from_txin(cls, txin):
        """Create a fully mutable copy of an existing Elements sidechain TxIn"""
        prevout = CMutableOutPoint.from_outpoint(txin.prevout)
        return cls(prevout, txin.scriptSig, txin.nSequence, txin.assetIssuance)


class CElementsSidechainTxOut(CTxOutBase, ReprOrStrMixin):
    """An output of an Elements sidechain transaction
    """
    __slots__ = ['nValue', 'scriptPubKey', 'nAsset', 'nNonce']

    # nValue and scriptPubKey is first to be compatible with
    # CTxOut(nValue, scriptPubKey) calls
    def __init__(self, nValue=CConfidentialValue(), scriptPubKey=CScript(),
                 nAsset=CConfidentialAsset(), nNonce=CConfidentialNonce()):
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
        scriptPubKey = CScript(BytesSerializer.stream_deserialize(f))
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


@make_mutable
class CElementsSidechainMutableTxOut(CElementsSidechainTxOut):
    __slots__ = []

    @classmethod
    def from_txout(cls, txout):
        """Create a fullly mutable copy of an existing Elements sidechain TxOut"""
        return cls(txout.nValue, txout.scriptPubKey,
                   txout.nAsset, txout.nNonce)


class CElementsSidechainTransactionCommon():

    @classmethod
    def stream_deserialize(cls, f):
        """Deserialize transaction

        This implementation corresponds to Elements's SerializeTransaction() and
        consensus behavior. Note that Elements's DecodeHexTx() also has the
        option to attempt deserializing as a non-witness transaction first,
        falling back to the consensus behavior if it fails. The difference lies
        in transactions which have zero inputs: they are invalid but may be
        (de)serialized anyway for the purpose of signing them and adding
        inputs. If the behavior of DecodeHexTx() is needed it could be added,
        but not here.
        """
        # FIXME can't assume f is seekable
        nVersion = struct.unpack(b"<i", ser_read(f, 4))[0]

        markerbyte = 0
        flagbyte = struct.unpack(b'B', ser_read(f, 1))[0]
        if markerbyte == 0 and flagbyte == 1:
            vin = VectorSerializer.stream_deserialize(cls._txin_class, f)
            vout = VectorSerializer.stream_deserialize(cls._txout_class, f)
            wit = cls._witness_class(tuple(0 for dummy in range(len(vin))),
                                     tuple(0 for dummy in range(len(vout))))
            # Note: nLockTime goes before witness in Elements sidechain transactions
            nLockTime = struct.unpack(b"<I", ser_read(f, 4))[0]
            wit = wit.stream_deserialize(f)
            return cls(vin, vout, nLockTime, nVersion, wit)
        else:
            vin = VectorSerializer.stream_deserialize(cls._txin_class, f)
            vout = VectorSerializer.stream_deserialize(cls._txout_class, f)
            nLockTime = struct.unpack(b"<I", ser_read(f, 4))[0]
            return cls(vin, vout, nLockTime, nVersion)

    def stream_serialize(self, f, include_witness=True):
        f.write(struct.pack(b"<i", self.nVersion))
        if include_witness and not self.wit.is_null():
            assert(len(self.wit.vtxinwit) == len(self.vin))
            f.write(b'\x01')  # Flag
            VectorSerializer.stream_serialize(self._txin_class, self.vin, f)
            VectorSerializer.stream_serialize(self._txout_class, self.vout, f)
            # Note: nLockTime goes before witness in Elements sidechain transactions
            f.write(struct.pack(b"<I", self.nLockTime))
            self.wit.stream_serialize(f)
        else:
            f.write(b'\x00')  # Flag is needed in Elements sidechain
            VectorSerializer.stream_serialize(self._txin_class, self.vin, f)
            VectorSerializer.stream_serialize(self._txout_class, self.vout, f)
            f.write(struct.pack(b"<I", self.nLockTime))


class CElementsSidechainMutableTransaction(CElementsSidechainTransactionCommon, CMutableTransactionBase):
    # _inverted_mutability_class will be set in _SelectAlternativeCoreParams
    _witness_class = CElementsSidechainTxWitness
    _txin_class = CElementsSidechainMutableTxIn
    _txout_class = CElementsSidechainMutableTxOut


class CElementsSidechainTransaction(CElementsSidechainTransactionCommon, CImmutableTransactionBase):
    _inverted_mutability_class = CElementsSidechainMutableTransaction
    _witness_class = CElementsSidechainMutableTxWitness
    _txin_class = CElementsSidechainTxIn
    _txout_class = CElementsSidechainTxOut


class CoreElementsSidechainParams(CoreMainParams):
    NAME = 'sidechain/elements'
    TRANSACTION_CLASS = CElementsSidechainTransaction


class ElementsSidechainParams(CoreElementsSidechainParams):
    RPC_PORT = 7041
    BASE58_PREFIXES = {'PUBKEY_ADDR': 235,
                       'SCRIPT_ADDR': 75,
                       'CONFIDENTIAL_ADDR': b'\x04',
                       'CONFIDENTIAL_PUBKEY_ADDR': b'\x04\xEB',
                       'CONFIDENTIAL_SCRIPT_ADDR': b'\x04\x4B',

                       # Note: these are the same as for Bitcoin testnet
                       'SECRET_KEY': 239,
                       'EXTENDED_PUBKEY': b'\x04\x35\x87\xCF',
                       'EXTENDED_PRIVKEY': b'\x04\x35\x83\x94'}

    BECH32_HRP = None


def GenerateAssetEntropy(prevout, contracthash):
    assert isinstance(prevout, COutPoint)
    assert isinstance(contracthash, (bytes, Uint256))
    if isinstance(contracthash, Uint256):
        contracthash = contracthash.data
    assert len(contracthash) == 32
    return Uint256(CSHA256().Write(prevout.GetHash()).Write(contracthash).Midstate())


def CalculateAsset(entropy):
    assert isinstance(entropy, (bytes, Uint256))
    if isinstance(entropy, Uint256):
        entropy = entropy.data
    assert len(entropy) == 32
    return CAsset(CSHA256().Write(entropy).Write(Uint256().data).Midstate())


def CalculateReissuanceToken(entropy, is_confidential):
    assert isinstance(entropy, (bytes, Uint256))
    if isinstance(entropy, Uint256):
        entropy = entropy.data
    assert len(entropy) == 32
    if is_confidential:
        k = Uint256.from_int(2)
    else:
        k = Uint256.from_int(1)
    return CAsset(CSHA256().Write(entropy).Write(k.data).Midstate())


def GetChainParams(name):
    assert name == CoreElementsSidechainParams.NAME
    return CoreElementsSidechainParams, ElementsSidechainParams


__all__ = (
    'GetChainParams',
    'CAsset',
    'CAssetIssuance',
    'CConfidentialAsset',
    'CConfidentialValue',
    'CConfidentialNonce',
    'GenerateAssetEntropy',
    'CalculateAsset',
    'CalculateReissuanceToken',
)
