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

from __future__ import absolute_import, division, print_function, unicode_literals

from bitcointx.core.key import CPubKey
from bitcointx.core.serialize import ImmutableSerializable
from bitcointx.wallet import P2PKHBitcoinAddress
import bitcointx
import base64

# pylama:ignore=E501


def VerifyMessage(address, message, sig):
    sig = base64.b64decode(sig)
    hash = message.GetHash()

    pubkey = CPubKey.recover_compact(hash, sig)

    if pubkey is False:
        return False

    return str(P2PKHBitcoinAddress.from_pubkey(pubkey)) == str(address)


def SignMessage(key, message):
    sig, i = key.sign_compact(message.GetHash())

    meta = 27 + i
    if key.is_compressed:
        meta += 4

    return base64.b64encode(bytes([meta]) + sig)


class BitcoinMessage(ImmutableSerializable):
    __slots__ = ['magic', 'message']

    def __init__(self, message="", magic="Bitcoin Signed Message:\n"):
        object.__setattr__(self, 'message', message.encode("utf-8"))
        object.__setattr__(self, 'magic', magic.encode("utf-8"))

    @classmethod
    def stream_deserialize(cls, f):
        magic = bitcointx.core.serialize.BytesSerializer.stream_deserialize(f)
        message = bitcointx.core.serialize.BytesSerializer.stream_deserialize(f)
        return cls(message, magic)

    def stream_serialize(self, f):
        bitcointx.core.serialize.BytesSerializer.stream_serialize(self.magic, f)
        bitcointx.core.serialize.BytesSerializer.stream_serialize(self.message, f)

    def __str__(self):
        return self.message.decode('ascii')

    def __repr__(self):
        return 'BitcoinMessage(%s, %s)' % (self.magic, self.message)
