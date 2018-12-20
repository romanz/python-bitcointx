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

# pylama:ignore=E501,E221

import os
import ctypes
import ctypes.util
import threading

secp256k1 = ctypes.cdll.LoadLibrary(ctypes.util.find_library('secp256k1'))

PUBLIC_KEY_SIZE             = 65
COMPRESSED_PUBLIC_KEY_SIZE  = 33
SIGNATURE_SIZE              = 72
COMPACT_SIGNATURE_SIZE      = 65


class Libsecp256k1Exception(EnvironmentError):
    pass


SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0)
SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9)
SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8)

SECP256K1_CONTEXT_SIGN = \
    (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
SECP256K1_CONTEXT_VERIFY = \
    (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)

SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1)
SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8)

SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
SECP256K1_EC_UNCOMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION)

_secp256k1_error_storage = threading.local()

_ctypes_functype = getattr(ctypes, 'WINFUNCTYPE', getattr(ctypes, 'CFUNCTYPE'))


@_ctypes_functype(ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p)
def _secp256k1_error_callback_fn(error_str, _data):
    _secp256k1_error_storage.last_error = {'code': -1, 'type': 'internal_error', 'message': str(error_str)}


@_ctypes_functype(ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p)
def _secp256k1_illegal_callback_fn(error_str, _data):
    _secp256k1_error_storage.last_error = {'code': -2, 'type': 'illegal_argument', 'message': str(error_str)}


def secp256k1_get_last_error():
    return getattr(_secp256k1_error_storage, 'last_error', None)


def _check_ressecp256k1_void_p(val, _func, _args):
    if val == 0:
        err = _secp256k1_error_storage.last_error
        raise Libsecp256k1Exception(err['code'], err['message'])
    return ctypes.c_void_p(val)


secp256k1.secp256k1_context_create.restype = ctypes.c_void_p
secp256k1.secp256k1_context_create.errcheck = _check_ressecp256k1_void_p
secp256k1.secp256k1_context_create.argtypes = [ctypes.c_uint]

secp256k1.secp256k1_context_randomize.restype = ctypes.c_int
secp256k1.secp256k1_context_randomize.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

secp256k1.secp256k1_context_set_illegal_callback.restype = None
secp256k1.secp256k1_context_set_illegal_callback.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

secp256k1.secp256k1_context_set_error_callback.restype = None
secp256k1.secp256k1_context_set_error_callback.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

secp256k1.secp256k1_ecdsa_sign.restype = ctypes.c_int
secp256k1.secp256k1_ecdsa_sign.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]

secp256k1.secp256k1_ecdsa_signature_serialize_der.restype = ctypes.c_int
secp256k1.secp256k1_ecdsa_signature_serialize_der.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p]

secp256k1_has_pubkey_recovery = False
if getattr(secp256k1, 'secp256k1_ecdsa_sign_recoverable', None):
    secp256k1_has_pubkey_recovery = True
    secp256k1.secp256k1_ecdsa_sign_recoverable.restype = ctypes.c_int
    secp256k1.secp256k1_ecdsa_sign_recoverable.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]

    secp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact.restype = ctypes.c_int
    secp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p]

    secp256k1.secp256k1_ecdsa_recover.restype = ctypes.c_int
    secp256k1.secp256k1_ecdsa_recover.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

    secp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact.restype = ctypes.c_int
    secp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]

secp256k1_has_zkp = False
if getattr(secp256k1, 'secp256k1_rangeproof_info', None):
    secp256k1_has_zkp = True
    secp256k1.secp256k1_rangeproof_info.restype = ctypes.c_int
    secp256k1.secp256k1_rangeproof_info.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64),
        ctypes.c_char_p, ctypes.c_size_t
    ]

secp256k1.secp256k1_ec_pubkey_serialize.restype = ctypes.c_int
secp256k1.secp256k1_ec_pubkey_serialize.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_uint]

secp256k1.secp256k1_ec_pubkey_create.restype = ctypes.c_int
secp256k1.secp256k1_ec_pubkey_create.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

secp256k1.secp256k1_ecdsa_signature_parse_der.restype = ctypes.c_int
secp256k1.secp256k1_ecdsa_signature_parse_der.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]

secp256k1.secp256k1_ecdsa_signature_normalize.restype = ctypes.c_int
secp256k1.secp256k1_ecdsa_signature_normalize.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

secp256k1.secp256k1_ecdsa_verify.restype = ctypes.c_int
secp256k1.secp256k1_ecdsa_verify.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

secp256k1.secp256k1_ec_pubkey_parse.restype = ctypes.c_int
secp256k1.secp256k1_ec_pubkey_parse.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]

secp256k1.secp256k1_ec_pubkey_tweak_add.restype = ctypes.c_int
secp256k1.secp256k1_ec_pubkey_tweak_add.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

secp256k1.secp256k1_ec_privkey_tweak_add.restype = ctypes.c_int
secp256k1.secp256k1_ec_privkey_tweak_add.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

secp256k1_context_sign = secp256k1.secp256k1_context_create(SECP256K1_CONTEXT_SIGN)
assert secp256k1_context_sign is not None
secp256k1_context_verify = secp256k1.secp256k1_context_create(SECP256K1_CONTEXT_VERIFY)
assert secp256k1_context_verify is not None


def _set_error_callback(ctx):
    secp256k1.secp256k1_context_set_error_callback(ctx, _secp256k1_error_callback_fn, 0)
    secp256k1.secp256k1_context_set_illegal_callback(ctx, _secp256k1_illegal_callback_fn, 0)

_set_error_callback(secp256k1_context_sign)
_set_error_callback(secp256k1_context_verify)


def randomize_context(ctx):
    seed = os.urandom(32)
    assert(secp256k1.secp256k1_context_randomize(ctx, seed) == 1)

randomize_context(secp256k1_context_sign)

secp256k1_context_blind = None
if secp256k1_has_zkp:
    secp256k1_context_blind = secp256k1.secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
    assert secp256k1_context_blind is not None
    _set_error_callback(secp256k1_context_blind)
    randomize_context(secp256k1_context_blind)


__all__ = (
    'secp256k1',
    'secp256k1_context_sign',
    'secp256k1_context_verify',
    'secp256k1_context_blind',
    'SIGNATURE_SIZE',
    'COMPACT_SIGNATURE_SIZE',
    'PUBLIC_KEY_SIZE',
    'COMPRESSED_PUBLIC_KEY_SIZE',
    'SECP256K1_EC_COMPRESSED',
    'SECP256K1_EC_UNCOMPRESSED',
    'secp256k1_has_pubkey_recovery',
    'secp256k1_has_zkp',
)
