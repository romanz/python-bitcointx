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

# NOTE: for simplicity, when we need to pass an array of structs to secp256k1
# function, we will build an array of bytes out of elements, and than pass
# this array. we are dealing with 32 or 64-byte aligned data,
# so this should be safe. You can use build_aligned_data_array() for this.

# NOTE: special care should be taken with functions that may write to parts
# of their arguments, like secp256k1_pedersen_blind_generator_blind_sum,
# which will overwrite the element pointed to by blinding_factor.
# python's byte instance is supposed to be immutable, and for mutable byte
# buffers you should use ctypes.create_string_buffer().

import os
import ctypes
import ctypes.util
import threading

secp256k1 = ctypes.cdll.LoadLibrary(ctypes.util.find_library('secp256k1'))

class LibWrapper:
    def __init__(self, lib):
        self.__lib = lib

    def __getattr__(self, name):
        # print(name)
        return FuncWrapper(getattr(self.__lib, name), name)
        return getattr(self.__lib, name)

class FuncWrapper:
    def __init__(self, func, name):
        self.__func = func
        self.__name = name

    def __call__(self, *args, **kw):
        print(f'{self.__name:40}', end='')
        if args:
            # TODO: dump arguments in sensible format
            print('\t', format_args(args), end='')
        assert not kw
        result = self.__func(*args, **kw)
        print(f'\n--> {result}')
        return result

    def __getattr__(self, name):
        print(self.__func, name)
        return getattr(self.__func, name)

    def __setattr__(self, name, value):
        if name.startswith('_FuncWrapper__'):
            super().__setattr__(name, value)
        else:
            setattr(self.__func, name, value)

def format_args(args):
    types = tuple(map(type, args))
    return ''.join('\n\t' + format_arg(a) for a in args)

def format_arg(arg):
    if isinstance(arg, bytes):
        return f'bytes({arg})'
    if hasattr(arg, 'raw'):
        return f'Array({len(arg.raw)})'
    if hasattr(arg, '_obj'):
        return f'Ref({arg._obj})'
    return f'{str(arg)}'

secp256k1 = LibWrapper(secp256k1)

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


def _set_zkp_func_types():
    secp256k1.secp256k1_rangeproof_info.restype = ctypes.c_int
    secp256k1.secp256k1_rangeproof_info.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64),
        ctypes.c_char_p, ctypes.c_size_t
    ]
    secp256k1.secp256k1_generator_parse.restype = ctypes.c_int
    secp256k1.secp256k1_generator_parse.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    secp256k1.secp256k1_generator_generate.restype = ctypes.c_int
    secp256k1.secp256k1_generator_generate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    secp256k1.secp256k1_generator_generate_blinded.restype = ctypes.c_int
    secp256k1.secp256k1_generator_generate_blinded.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    secp256k1.secp256k1_generator_serialize.restype = ctypes.c_int
    secp256k1.secp256k1_generator_serialize.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    secp256k1.secp256k1_pedersen_commit.restype = ctypes.c_int
    secp256k1.secp256k1_pedersen_commit.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint64, ctypes.c_char_p]
    secp256k1.secp256k1_pedersen_commitment_serialize.restype = ctypes.c_int
    secp256k1.secp256k1_pedersen_commitment_serialize.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    secp256k1.secp256k1_pedersen_commitment_parse.restype = ctypes.c_int
    secp256k1.secp256k1_pedersen_commitment_parse.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    secp256k1.secp256k1_pedersen_blind_generator_blind_sum.restype = ctypes.c_int
    secp256k1.secp256k1_pedersen_blind_generator_blind_sum.argtypes = [
        ctypes.c_void_p,  # const secp256k1_context* ctx
        ctypes.POINTER(ctypes.c_uint64),  # const uint64_t *value
        ctypes.POINTER(ctypes.c_char_p),  # const unsigned char* const* generator_blind
        ctypes.POINTER(ctypes.c_char_p),  # unsigned char* const* blinding_factor
        ctypes.c_size_t,  # size_t n_total
        ctypes.c_size_t   # size_t n_inputs
    ]
    secp256k1.secp256k1_rangeproof_sign.restype = ctypes.c_int
    secp256k1.secp256k1_rangeproof_sign.argtypes = [
        ctypes.c_void_p,  # const secp256k1_context* ctx
        ctypes.c_char_p,  # unsigned char *proof
        ctypes.POINTER(ctypes.c_size_t),  # size_t *plen
        ctypes.c_uint64,   # uint64_t min_value,
        ctypes.c_char_p,  # const secp256k1_pedersen_commitment *commit,
        ctypes.c_char_p,  # const unsigned char *blind,
        ctypes.c_char_p,  # const unsigned char *nonce,
        ctypes.c_int,     # int exp,
        ctypes.c_int,     # int min_bits,
        ctypes.c_uint64,  # uint64_t value,
        ctypes.c_char_p,  # const unsigned char *message,
        ctypes.c_size_t,  # size_t msg_len,
        ctypes.c_char_p,  # const unsigned char *extra_commit,
        ctypes.c_size_t,  # size_t extra_commit_len,
        ctypes.c_char_p   # const secp256k1_generator* gen
    ]
    secp256k1.secp256k1_rangeproof_rewind.restype = ctypes.c_int
    secp256k1.secp256k1_rangeproof_rewind.argtypes = [
        ctypes.c_void_p,  # const secp256k1_context* ctx
        ctypes.c_char_p,  # unsigned char *blind_out
        ctypes.POINTER(ctypes.c_uint64),  # uint64_t *value_out
        ctypes.c_char_p,  # unsigned char *message_out,
        ctypes.POINTER(ctypes.c_size_t),  # size_t *outlen
        ctypes.c_char_p,  # const unsigned char *nonce
        ctypes.POINTER(ctypes.c_uint64),  # uint64_t *min_value
        ctypes.POINTER(ctypes.c_uint64),  # uint64_t *max_value
        ctypes.c_char_p,  # const secp256k1_pedersen_commitment *commit
        ctypes.c_char_p,  # const unsigned char *proof
        ctypes.c_size_t,  # size_t plen
        ctypes.c_char_p,  # const unsigned char *extra_commit
        ctypes.c_size_t,  # size_t extra_commit_len,
        ctypes.c_char_p   # const secp256k1_generator* gen
    ]
    secp256k1.secp256k1_surjectionproof_initialize.restype = ctypes.c_int
    secp256k1.secp256k1_surjectionproof_initialize.argtypes = [
        ctypes.c_void_p,  # const secp256k1_context* ctx
        ctypes.c_char_p,  # secp256k1_surjectionproof* proof // proof size in bytes is not specified
        ctypes.POINTER(ctypes.c_size_t),  # size_t *input_index
        #                   NOTE: use build_aligned_data_array()
        ctypes.c_char_p,  # const secp256k1_fixed_asset_tag* fixed_input_tags
        ctypes.c_size_t,  # const size_t n_input_tags
        ctypes.c_size_t,  # const size_t n_input_tags_to_use
        ctypes.c_char_p,  # const secp256k1_fixed_asset_tag* fixed_output_tag
        ctypes.c_size_t,  # const size_t n_max_iterations
        ctypes.c_char_p   # const unsigned char *random_seed32
    ]

    secp256k1.secp256k1_surjectionproof_generate.restype = ctypes.c_int
    secp256k1.secp256k1_surjectionproof_generate.argtypes = [
        ctypes.c_void_p,  # const secp256k1_context* ctx
        ctypes.c_char_p,  # secp256k1_surjectionproof* proof
        #                   NOTE: use build_aligned_data_array()
        ctypes.c_char_p,  # const secp256k1_generator* ephemeral_input_tags
        ctypes.c_size_t,  # size_t n_ephemeral_input_tags
        ctypes.c_char_p,  # const secp256k1_generator* ephemeral_output_tag
        ctypes.c_size_t,  # size_t input_index
        ctypes.c_char_p,  # const unsigned char *input_blinding_key
        ctypes.c_char_p   # const unsigned char *output_blinding_key
    ]

    secp256k1.secp256k1_surjectionproof_verify.restype = ctypes.c_int
    secp256k1.secp256k1_surjectionproof_verify.argtypes = [
        ctypes.c_void_p,  # const secp256k1_context* ctx
        ctypes.c_char_p,  # const secp256k1_surjectionproof* proof
        #                   NOTE: use build_aligned_data_array()
        ctypes.c_char_p,  # const secp256k1_generator* ephemeral_input_tags
        ctypes.c_size_t,  # size_t n_ephemeral_input_tags
        ctypes.c_char_p   # const secp256k1_generator* ephemeral_output_tag
    ]
    secp256k1.secp256k1_surjectionproof_serialized_size.restype = ctypes.c_int
    secp256k1.secp256k1_surjectionproof_serialized_size.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    secp256k1.secp256k1_ec_pubkey_serialize.restype = ctypes.c_int
    secp256k1.secp256k1_ec_pubkey_serialize.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_uint]

    secp256k1.secp256k1_surjectionproof_serialize.restype = ctypes.c_int
    secp256k1.secp256k1_surjectionproof_serialize.argtypes = [
        ctypes.c_void_p,  # const secp256k1_context* ctx
        ctypes.c_char_p,  # unsigned char *output
        ctypes.POINTER(ctypes.c_size_t),  # size_t *outputlen
        ctypes.c_char_p   # const secp256k1_surjectionproof *proof
    ]

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
    _set_zkp_func_types()

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

secp256k1.secp256k1_ec_pubkey_create.restype = ctypes.c_int
secp256k1.secp256k1_ec_pubkey_create.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

secp256k1.secp256k1_ec_seckey_verify.restype = ctypes.c_int
secp256k1.secp256k1_ec_seckey_verify.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

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

secp256k1_has_ecdh = False
if getattr(secp256k1, 'secp256k1_ecdh', None):
    secp256k1_has_ecdh = True
    secp256k1.secp256k1_ecdh.restype = ctypes.c_int
    secp256k1.secp256k1_ecdh.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]

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

secp256k1_blind_context = None
if secp256k1_has_zkp:
    secp256k1_blind_context = secp256k1.secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
    assert secp256k1_blind_context is not None
    _set_error_callback(secp256k1_blind_context)
    randomize_context(secp256k1_blind_context)


def build_aligned_data_array(data_list, expected_len):
    assert expected_len % 32 == 0, "we only deal with 32-byte aligned data"
    # It is much simpler to just build buffer by concatenating the data,
    # than create a ctypes array of N-byte arrays.
    # with fixed byte size, we do not need to bother about alignment.
    buf = b''.join(data_list)
    # but we must check that our expectation of the data size is correct
    assert len(buf) % expected_len == 0
    assert len(buf) // expected_len == len(data_list)

    return buf

SECP256K1_GENERATOR_SIZE = 64
SECP256K1_PEDERSEN_COMMITMENT_SIZE = 64

__all__ = (
    'secp256k1',
    'secp256k1_context_sign',
    'secp256k1_context_verify',
    'secp256k1_blind_context',
    'SIGNATURE_SIZE',
    'COMPACT_SIGNATURE_SIZE',
    'PUBLIC_KEY_SIZE',
    'COMPRESSED_PUBLIC_KEY_SIZE',
    'SECP256K1_EC_COMPRESSED',
    'SECP256K1_EC_UNCOMPRESSED',
    'secp256k1_has_pubkey_recovery',
    'secp256k1_has_zkp',
    'build_aligned_data_array',
)
