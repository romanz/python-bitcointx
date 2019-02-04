# Copyright (C) 2012-2017 The python-bitcoinlib developers
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

"""Script evaluation

Be warned that there are highly likely to be consensus bugs in this code; it is
unlikely to match Satoshi Bitcoin exactly. Think carefully before using this
module.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import hashlib

import bitcointx.core
import bitcointx.core._bignum
import bitcointx.core.key
import bitcointx.core.serialize

# Importing everything for simplicity; note that we use __all__ at the end so
# we're not exporting the whole contents of the script module.
from bitcointx.core.script import *

MAX_NUM_SIZE = 4
MAX_STACK_ITEMS = 1000

SCRIPT_VERIFY_P2SH = object()
SCRIPT_VERIFY_STRICTENC = object()
SCRIPT_VERIFY_DERSIG = object()
SCRIPT_VERIFY_LOW_S = object()
SCRIPT_VERIFY_NULLDUMMY = object()
SCRIPT_VERIFY_SIGPUSHONLY = object()
SCRIPT_VERIFY_MINIMALDATA = object()
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = object()
SCRIPT_VERIFY_CLEANSTACK = object()
SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = object()
SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = object()
SCRIPT_VERIFY_MINIMALIF = object()
SCRIPT_VERIFY_NULLFAIL = object()
SCRIPT_VERIFY_WITNESS = object()
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = object()
SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = object()
SCRIPT_VERIFY_CONST_SCRIPTCODE = object()

_STRICT_ENCODING_FLAGS = set((SCRIPT_VERIFY_DERSIG, SCRIPT_VERIFY_LOW_S, SCRIPT_VERIFY_STRICTENC))

UNHANDLED_SCRIPT_VERIFY_FLAGS = set((
    SCRIPT_VERIFY_SIGPUSHONLY,
    SCRIPT_VERIFY_MINIMALDATA,
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SCRIPT_VERIFY_CONST_SCRIPTCODE,
))

MANDATORY_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH

STANDARD_SCRIPT_VERIFY_FLAGS = set((
    MANDATORY_SCRIPT_VERIFY_FLAGS,
    SCRIPT_VERIFY_DERSIG,
    SCRIPT_VERIFY_STRICTENC,
    SCRIPT_VERIFY_MINIMALDATA,
    SCRIPT_VERIFY_NULLDUMMY,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    SCRIPT_VERIFY_CLEANSTACK,
    SCRIPT_VERIFY_MINIMALIF,
    SCRIPT_VERIFY_NULLFAIL,
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    SCRIPT_VERIFY_LOW_S,
    SCRIPT_VERIFY_WITNESS,
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
    SCRIPT_VERIFY_CONST_SCRIPTCODE))


SCRIPT_VERIFY_FLAGS_BY_NAME = {
    'P2SH': SCRIPT_VERIFY_P2SH,
    'STRICTENC': SCRIPT_VERIFY_STRICTENC,
    'DERSIG': SCRIPT_VERIFY_DERSIG,
    'LOW_S': SCRIPT_VERIFY_LOW_S,
    'NULLDUMMY': SCRIPT_VERIFY_NULLDUMMY,
    'SIGPUSHONLY': SCRIPT_VERIFY_SIGPUSHONLY,
    'MINIMALDATA': SCRIPT_VERIFY_MINIMALDATA,
    'DISCOURAGE_UPGRADABLE_NOPS': SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    'CLEANSTACK': SCRIPT_VERIFY_CLEANSTACK,
    'CHECKLOCKTIMEVERIFY': SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    'CHECKSEQUENCEVERIFY': SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    'MINIMALIF': SCRIPT_VERIFY_MINIMALIF,
    'NULLFAIL': SCRIPT_VERIFY_NULLFAIL,
    'WITNESS': SCRIPT_VERIFY_WITNESS,
    'DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM': SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    'WITNESS_PUBKEYTYPE': SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
    'CONST_SCRIPTCODE': SCRIPT_VERIFY_CONST_SCRIPTCODE,
}

SCRIPT_VERIFY_FLAGS_NAMES = {v: k for k, v in SCRIPT_VERIFY_FLAGS_BY_NAME.items()}


def _flags_set_str(flags):
    return ",".join(SCRIPT_VERIFY_FLAGS_NAMES[f] for f in flags)


class EvalScriptError(bitcointx.core.ValidationError):
    """Base class for exceptions raised when a script fails during EvalScript()

    The execution state just prior the opcode raising the is saved. (if
    available)
    """
    def __init__(self,
                 msg,
                 sop=None, sop_data=None, sop_pc=None,
                 stack=None, scriptIn=None, txTo=None, inIdx=None, flags=None,
                 altstack=None, vfExec=None, pbegincodehash=None, nOpCount=None):
        super(EvalScriptError, self).__init__('EvalScript: %s' % msg)

        self.sop = sop
        self.sop_data = sop_data
        self.sop_pc = sop_pc
        self.stack = stack
        self.scriptIn = scriptIn
        self.txTo = txTo
        self.inIdx = inIdx
        self.flags = flags
        self.altstack = altstack
        self.vfExec = vfExec
        self.pbegincodehash = pbegincodehash
        self.nOpCount = nOpCount


class MaxOpCountError(EvalScriptError):
    def __init__(self, **kwargs):
        super(MaxOpCountError, self).__init__('max opcode count exceeded', **kwargs)


class MissingOpArgumentsError(EvalScriptError):
    """Missing arguments"""
    def __init__(self, opcode, s, n, **kwargs):
        super(MissingOpArgumentsError, self).__init__(
            'missing arguments for %s; need %d items, but only %d on stack' %
            (OPCODE_NAMES[opcode], n, len(s)), **kwargs)


class ArgumentsInvalidError(EvalScriptError):
    """Arguments are invalid"""
    def __init__(self, opcode, msg, **kwargs):
        super(ArgumentsInvalidError, self).__init__(
            '%s args invalid: %s' % (OPCODE_NAMES[opcode], msg),
            **kwargs)


class VerifyOpFailedError(EvalScriptError):
    """A VERIFY opcode failed"""
    def __init__(self, opcode, **kwargs):
        super(VerifyOpFailedError, self).__init__('%s failed' % OPCODE_NAMES[opcode],
                                                  **kwargs)


# A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
# Where R and S are not negative (their first byte has its highest bit not set), and not
# excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
# in which case a single 0 byte is necessary and even required).
#
# See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
#
# This function is consensus-critical since BIP66.
#
# ported from bitcoind's src/script/interpreter.cpp
#
def _IsValidSignatureEncoding(sig):
    # Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    # * total-length: 1-byte length descriptor of everything that follows,
    #   excluding the sighash byte.
    # * R-length: 1-byte length descriptor of the R value that follows.
    # * R: arbitrary-length big-endian encoded R value. It must use the shortest
    #   possible encoding for a positive integers (which means no null bytes at
    #   the start, except a single one when the next byte has its highest bit set).
    # * S-length: 1-byte length descriptor of the S value that follows.
    # * S: arbitrary-length big-endian encoded S value. The same rules apply.
    # * sighash: 1-byte value indicating what data is hashed (not part of the DER
    #   signature)

    # Minimum and maximum size constraints.
    if (len(sig) < 9):
        return False

    if len(sig) > 73:
        return False

    # A signature is of type 0x30 (compound).
    if sig[0] != 0x30:
        return False

    # Make sure the length covers the entire signature.
    if sig[1] != len(sig) - 3:
        return False

    # Extract the length of the R element.
    lenR = sig[3]

    # Make sure the length of the S element is still inside the signature.
    if 5 + lenR >= len(sig):
        return False

    # Extract the length of the S element.
    lenS = sig[5 + lenR]

    # Verify that the length of the signature matches the sum of the length
    # of the elements.
    if (lenR + lenS + 7) != len(sig):
        return False

    # Check whether the R element is an integer.
    if sig[2] != 0x02:
        return False

    # Zero-length integers are not allowed for R.
    if lenR == 0:
        return False

    # Negative numbers are not allowed for R.
    if sig[4] & 0x80:
        return False

    # Null bytes at the start of R are not allowed, unless R would
    # otherwise be interpreted as a negative number.
    if lenR > 1 and sig[4] == 0x00 and (sig[5] & 0x80) == 0:
        return False

    # Check whether the S element is an integer.
    if sig[lenR + 4] != 0x02:
        return False

    # Zero-length integers are not allowed for S.
    if lenS == 0:
        return False

    # Negative numbers are not allowed for S.
    if sig[lenR + 6] & 0x80:
        return False

    # Null bytes at the start of S are not allowed, unless S would otherwise be
    # interpreted as a negative number.
    if lenS > 1 and sig[lenR + 6] == 0x00 and (not (sig[lenR + 7] & 0x80)):
        return False

    return True


def _IsCompressedOrUncompressedPubKey(pubkey):
    if len(pubkey) < 33:
        #  Non-canonical public key: too short
        return False

    if pubkey[0] == 0x04:
        if len(pubkey) != 65:
            #  Non-canonical public key: invalid length for uncompressed key
            return False
    elif pubkey[0] == 0x02 or pubkey[0] == 0x03:
        if len(pubkey) != 33:
            #  Non-canonical public key: invalid length for compressed key
            return False
    else:
        #  Non-canonical public key: neither compressed nor uncompressed
        return False

    return True


def _IsCompressedPubKey(pubkey):
    if len(pubkey) != 33:
        #  Non-canonical public key: invalid length for compressed key
        return False

    if pubkey[0] != 0x02 and pubkey[0] != 0x03:
        #  Non-canonical public key: invalid prefix for compressed key
        return False

    return True


def VerifyWitnessProgram(witness, witversion, program, txTo, inIdx, flags=(), amount=0):
    sigversion = None

    if witversion == 0:
        sigversion = SIGVERSION_WITNESS_V0
        stack = list(witness.stack)
        if len(program) == 32:
            # Version 0 segregated witness program: SHA256(CScript) inside the program,
            # CScript + inputs in witness
            if len(stack) == 0:
                raise VerifyScriptError("witness is empty")

            scriptPubKey = stack.pop()
            hashScriptPubKey = hashlib.sha256(scriptPubKey).digest()
            if hashScriptPubKey != program:
                raise VerifyScriptError("witness program mismatch")
        elif len(program) == 20:
            # Special case for pay-to-pubkeyhash; signature + pubkey in witness
            if len(stack) != 2:
                raise VerifyScriptError("witness program mismatch")  # 2 items in witness

            scriptPubKey = CScript([OP_DUP, OP_HASH160, program, OP_EQUALVERIFY, OP_CHECKSIG])
        else:
            raise VerifyScriptError("wrong length for witness program")
    elif SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM in flags:
        raise VerifyScriptError("upgradeable witness program is not accepted")
    else:
        # Higher version witness scripts return true for future softfork compatibility
        return True

    assert sigversion is not None

    # Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
    if any(len(elt) > MAX_SCRIPT_ELEMENT_SIZE for elt in stack):
        raise VerifyScriptError("maximum push size exceeded by an item on witness stack")

    EvalScript(stack, scriptPubKey, txTo, inIdx, flags=flags, amount=amount, sigversion=sigversion)

    # Scripts inside witness implicitly require cleanstack behaviour
    if len(stack) == 0:
        raise VerifyScriptError("scriptPubKey left an empty stack")
    elif len(stack) != 1:
        raise VerifyScriptError("scriptPubKey left extra items on stack")

    if not _CastToBool(stack[-1]):
        raise VerifyScriptError("scriptPubKey returned false")

    return True


def _CastToBigNum(s, err_raiser):
    v = bitcointx.core._bignum.vch2bn(s)
    if len(s) > MAX_NUM_SIZE:
        raise err_raiser(EvalScriptError, 'CastToBigNum() : overflow')
    return v


def _CastToBool(s):
    for i in range(len(s)):
        sv = s[i]
        if sv != 0:
            if (i == (len(s) - 1)) and (sv == 0x80):
                return False
            return True

    return False


def _CheckSig(sig, pubkey, script, txTo, inIdx, flags, err_raiser,
              amount=0, sigversion=SIGVERSION_BASE):
    key = bitcointx.core.key.CPubKey(pubkey)

    if len(sig) == 0:
        return False

    hashtype = sig[-1]

    if flags & _STRICT_ENCODING_FLAGS:
        verify_fn = key.verify

        if not _IsValidSignatureEncoding(sig):
            raise VerifyScriptError("signature DER encoding is not strictly valid")

        if SCRIPT_VERIFY_STRICTENC in flags:
            low_hashtype = hashtype & (~SIGHASH_ANYONECANPAY)
            if low_hashtype < SIGHASH_ALL or low_hashtype > SIGHASH_SINGLE:
                raise VerifyScriptError("unknown hashtype in signature")

            if not _IsCompressedOrUncompressedPubKey(pubkey):
                raise VerifyScriptError("unknown pubkey type")
    else:
        verify_fn = key.verify_nonstrict

    if SCRIPT_VERIFY_WITNESS_PUBKEYTYPE in flags and sigversion == SIGVERSION_WITNESS_V0:
        if not _IsCompressedPubKey(pubkey):
            raise VerifyScriptError("witness pubkey is not compressed")

    if SCRIPT_VERIFY_LOW_S in flags and not IsLowDERSignature(sig):
        raise VerifyScriptError("signature is not low-S")

    # Raw signature hash due to the SIGHASH_SINGLE bug
    #
    # Note that we never raise an exception if RawSignatureHash() returns an
    # error code. However the first error code case, where inIdx >=
    # len(txTo.vin), shouldn't ever happen during EvalScript() as that would
    # imply the scriptSig being checked doesn't correspond to a valid txout -
    # that should cause other validation machinery to fail long before we ever
    # got here.
    (h, err) = RawSignatureHash(script, txTo, inIdx, hashtype, amount=amount, sigversion=sigversion)

    return verify_fn(h, sig[:-1])


def _CheckMultiSig(opcode, script, stack, txTo, inIdx, flags, err_raiser, nOpCount,
                   amount=0, sigversion=SIGVERSION_BASE):
    i = 1
    if len(stack) < i:
        err_raiser(MissingOpArgumentsError, opcode, stack, i)

    keys_count = _CastToBigNum(stack[-i], err_raiser)
    if keys_count < 0 or keys_count > 20:
        err_raiser(ArgumentsInvalidError, opcode, "keys count invalid")
    i += 1
    ikey = i
    # ikey2 is the position of last non-signature item in the stack. Top stack item = 1.
    # With SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if operation fails.
    ikey2 = keys_count + 2
    i += keys_count
    nOpCount[0] += keys_count
    if nOpCount[0] > MAX_SCRIPT_OPCODES:
        err_raiser(MaxOpCountError)
    if len(stack) < i:
        err_raiser(ArgumentsInvalidError, opcode, "not enough keys on stack")

    sigs_count = _CastToBigNum(stack[-i], err_raiser)
    if sigs_count < 0 or sigs_count > keys_count:
        err_raiser(ArgumentsInvalidError, opcode, "sigs count invalid")

    i += 1
    isig = i
    i += sigs_count
    if len(stack) < i-1:
        raise err_raiser(ArgumentsInvalidError, opcode, "not enough sigs on stack")
    elif len(stack) < i:
        raise err_raiser(ArgumentsInvalidError, opcode, "missing dummy value")

    if sigversion == SIGVERSION_BASE:
        # Drop the signature in pre-segwit scripts but not segwit scripts
        for k in range(sigs_count):
            sig = stack[-isig - k]
            script = FindAndDelete(script, CScript([sig]))

    success = True

    empty_sig_count = 0
    while success and sigs_count > 0:
        sig = stack[-isig]
        empty_sig_count += int(len(sig) == 0)
        pubkey = stack[-ikey]

        if _CheckSig(sig, pubkey, script, txTo, inIdx, flags, err_raiser,
                     amount=amount, sigversion=sigversion):
            isig += 1
            sigs_count -= 1

        ikey += 1
        keys_count -= 1

        if sigs_count > keys_count:
            success = False

            # with VERIFY bail now before we modify the stack
            if opcode == OP_CHECKMULTISIGVERIFY:
                err_raiser(VerifyOpFailedError, opcode)

    while i > 1:
        if not success and SCRIPT_VERIFY_NULLFAIL in flags and ikey2 == 0 and len(stack[-1]):
            raise VerifyScriptError("signature check failed, and some of the signatures are not empty")

        if ikey2 > 0:
            ikey2 -= 1

        stack.pop()
        i -= 1

    # Note how Bitcoin Core duplicates the len(stack) check, rather than
    # letting pop() handle it; maybe that's wrong?
    if len(stack) and SCRIPT_VERIFY_NULLDUMMY in flags:
        if stack[-1] != b'':
            raise err_raiser(ArgumentsInvalidError, opcode, "dummy value not OP_0")

    stack.pop()

    if opcode == OP_CHECKMULTISIG:
        if success:
            stack.append(b"\x01")
        else:
            # FIXME: this is incorrect, but not caught by existing
            # test cases
            stack.append(b"\x00")


# OP_2MUL and OP_2DIV are *not* included in this list as they are disabled
_ISA_UNOP = {
    OP_1ADD,
    OP_1SUB,
    OP_NEGATE,
    OP_ABS,
    OP_NOT,
    OP_0NOTEQUAL,
}


def _UnaryOp(opcode, stack, err_raiser):
    if len(stack) < 1:
        err_raiser(MissingOpArgumentsError, opcode, stack, 1)
    bn = _CastToBigNum(stack[-1], err_raiser)
    stack.pop()

    if opcode == OP_1ADD:
        bn += 1

    elif opcode == OP_1SUB:
        bn -= 1

    elif opcode == OP_NEGATE:
        bn = -bn

    elif opcode == OP_ABS:
        if bn < 0:
            bn = -bn

    elif opcode == OP_NOT:
        bn = int(bn == 0)

    elif opcode == OP_0NOTEQUAL:
        bn = int(bn != 0)

    else:
        raise AssertionError("Unknown unary opcode encountered; this should not happen")

    stack.append(bitcointx.core._bignum.bn2vch(bn))


# OP_LSHIFT and OP_RSHIFT are *not* included in this list as they are disabled
_ISA_BINOP = {
    OP_ADD,
    OP_SUB,
    OP_BOOLAND,
    OP_BOOLOR,
    OP_NUMEQUAL,
    OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL,
    OP_LESSTHAN,
    OP_GREATERTHAN,
    OP_LESSTHANOREQUAL,
    OP_GREATERTHANOREQUAL,
    OP_MIN,
    OP_MAX,
}


def _BinOp(opcode, stack, err_raiser):
    if len(stack) < 2:
        err_raiser(MissingOpArgumentsError, opcode, stack, 2)

    bn2 = _CastToBigNum(stack[-1], err_raiser)
    bn1 = _CastToBigNum(stack[-2], err_raiser)

    # We don't pop the stack yet so that OP_NUMEQUALVERIFY can raise
    # VerifyOpFailedError with a correct stack.

    if opcode == OP_ADD:
        bn = bn1 + bn2

    elif opcode == OP_SUB:
        bn = bn1 - bn2

    elif opcode == OP_BOOLAND:
        bn = int(bn1 != 0 and bn2 != 0)

    elif opcode == OP_BOOLOR:
        bn = int(bn1 != 0 or bn2 != 0)

    elif opcode == OP_NUMEQUAL:
        bn = int(bn1 == bn2)

    elif opcode == OP_NUMEQUALVERIFY:
        bn = int(bn1 == bn2)
        if not bn:
            err_raiser(VerifyOpFailedError, opcode)
        else:
            # No exception, so time to pop the stack
            stack.pop()
            stack.pop()
            return

    elif opcode == OP_NUMNOTEQUAL:
        bn = int(bn1 != bn2)

    elif opcode == OP_LESSTHAN:
        bn = int(bn1 < bn2)

    elif opcode == OP_GREATERTHAN:
        bn = int(bn1 > bn2)

    elif opcode == OP_LESSTHANOREQUAL:
        bn = int(bn1 <= bn2)

    elif opcode == OP_GREATERTHANOREQUAL:
        bn = int(bn1 >= bn2)

    elif opcode == OP_MIN:
        if bn1 < bn2:
            bn = bn1
        else:
            bn = bn2

    elif opcode == OP_MAX:
        if bn1 > bn2:
            bn = bn1
        else:
            bn = bn2

    else:
        raise AssertionError("Unknown binop opcode encountered; this should not happen")

    stack.pop()
    stack.pop()
    stack.append(bitcointx.core._bignum.bn2vch(bn))


def _CheckExec(vfExec):
    for b in vfExec:
        if not b:
            return False
    return True


def _EvalScript(stack, scriptIn, txTo, inIdx, flags=(), amount=0, sigversion=SIGVERSION_BASE):
    """Evaluate a script

    """
    if len(scriptIn) > MAX_SCRIPT_SIZE:
        raise EvalScriptError('script too large; got %d bytes; maximum %d bytes' %
                              (len(scriptIn), MAX_SCRIPT_SIZE),
                              stack=stack,
                              scriptIn=scriptIn,
                              txTo=txTo,
                              inIdx=inIdx,
                              flags=flags)

    altstack = []
    vfExec = []
    pbegincodehash = 0
    nOpCount = [0]
    for (sop, sop_data, sop_pc) in scriptIn.raw_iter():
        fExec = _CheckExec(vfExec)

        def err_raiser(cls, *args):
            """Helper function for raising EvalScriptError exceptions

            cls   - subclass you want to raise

            *args - arguments

            Fills in the state of execution for you.
            """
            raise cls(*args,
                      sop=sop,
                      sop_data=sop_data,
                      sop_pc=sop_pc,
                      stack=stack, scriptIn=scriptIn, txTo=txTo, inIdx=inIdx, flags=flags,
                      altstack=altstack, vfExec=vfExec, pbegincodehash=pbegincodehash, nOpCount=nOpCount[0])

        if sop in DISABLED_OPCODES:
            err_raiser(EvalScriptError, 'opcode %s is disabled' % OPCODE_NAMES[sop])

        if sop > OP_16:
            nOpCount[0] += 1
            if nOpCount[0] > MAX_SCRIPT_OPCODES:
                err_raiser(MaxOpCountError)

        def check_args(n):
            if len(stack) < n:
                err_raiser(MissingOpArgumentsError, sop, stack, n)

        if sop <= OP_PUSHDATA4:
            if len(sop_data) > MAX_SCRIPT_ELEMENT_SIZE:
                err_raiser(EvalScriptError,
                           'PUSHDATA of length %d; maximum allowed is %d' %
                           (len(sop_data), MAX_SCRIPT_ELEMENT_SIZE))

            elif fExec:
                stack.append(sop_data)
                continue

        elif fExec or (OP_IF <= sop <= OP_ENDIF):

            if sop == OP_1NEGATE or ((sop >= OP_1) and (sop <= OP_16)):
                v = sop - (OP_1 - 1)
                stack.append(bitcointx.core._bignum.bn2vch(v))

            elif sop in _ISA_BINOP:
                _BinOp(sop, stack, err_raiser)

            elif sop in _ISA_UNOP:
                _UnaryOp(sop, stack, err_raiser)

            elif sop == OP_2DROP:
                check_args(2)
                stack.pop()
                stack.pop()

            elif sop == OP_2DUP:
                check_args(2)
                v1 = stack[-2]
                v2 = stack[-1]
                stack.append(v1)
                stack.append(v2)

            elif sop == OP_2OVER:
                check_args(4)
                v1 = stack[-4]
                v2 = stack[-3]
                stack.append(v1)
                stack.append(v2)

            elif sop == OP_2ROT:
                check_args(6)
                v1 = stack[-6]
                v2 = stack[-5]
                del stack[-6]
                del stack[-5]
                stack.append(v1)
                stack.append(v2)

            elif sop == OP_2SWAP:
                check_args(4)
                tmp = stack[-4]
                stack[-4] = stack[-2]
                stack[-2] = tmp

                tmp = stack[-3]
                stack[-3] = stack[-1]
                stack[-1] = tmp

            elif sop == OP_3DUP:
                check_args(3)
                v1 = stack[-3]
                v2 = stack[-2]
                v3 = stack[-1]
                stack.append(v1)
                stack.append(v2)
                stack.append(v3)

            elif sop == OP_CHECKMULTISIG or sop == OP_CHECKMULTISIGVERIFY:
                tmpScript = CScript(scriptIn[pbegincodehash:])
                _CheckMultiSig(sop, tmpScript, stack, txTo, inIdx, flags, err_raiser, nOpCount,
                               amount=amount, sigversion=sigversion)

            elif sop == OP_CHECKSIG or sop == OP_CHECKSIGVERIFY:
                check_args(2)
                vchPubKey = stack[-1]
                vchSig = stack[-2]

                # Subset of script starting at the most recent codeseparator
                tmpScript = CScript(scriptIn[pbegincodehash:])

                if sigversion == SIGVERSION_BASE:
                    # Drop the signature in pre-segwit scripts but not segwit scripts
                    tmpScript = FindAndDelete(tmpScript, CScript([vchSig]))

                ok = _CheckSig(vchSig, vchPubKey, tmpScript, txTo, inIdx, flags,
                               err_raiser, amount=amount, sigversion=sigversion)
                if not ok and SCRIPT_VERIFY_NULLFAIL in flags and len(vchSig):
                    raise VerifyScriptError("signature check failed, and signature is not empty")
                if not ok and sop == OP_CHECKSIGVERIFY:
                    err_raiser(VerifyOpFailedError, sop)

                else:
                    stack.pop()
                    stack.pop()

                    if ok:
                        if sop != OP_CHECKSIGVERIFY:
                            stack.append(b"\x01")
                    else:
                        # FIXME: this is incorrect, but not caught by existing
                        # test cases
                        stack.append(b"\x00")

            elif sop == OP_CODESEPARATOR:
                pbegincodehash = sop_pc

            elif sop == OP_DEPTH:
                bn = len(stack)
                stack.append(bitcointx.core._bignum.bn2vch(bn))

            elif sop == OP_DROP:
                check_args(1)
                stack.pop()

            elif sop == OP_DUP:
                check_args(1)
                v = stack[-1]
                stack.append(v)

            elif sop == OP_ELSE:
                if len(vfExec) == 0:
                    err_raiser(EvalScriptError, 'ELSE found without prior IF')
                vfExec[-1] = not vfExec[-1]

            elif sop == OP_ENDIF:
                if len(vfExec) == 0:
                    err_raiser(EvalScriptError, 'ENDIF found without prior IF')
                vfExec.pop()

            elif sop == OP_EQUAL:
                check_args(2)
                v1 = stack.pop()
                v2 = stack.pop()

                if v1 == v2:
                    stack.append(b"\x01")
                else:
                    stack.append(b"")

            elif sop == OP_EQUALVERIFY:
                check_args(2)
                v1 = stack[-1]
                v2 = stack[-2]

                if v1 == v2:
                    stack.pop()
                    stack.pop()
                else:
                    err_raiser(VerifyOpFailedError, sop)

            elif sop == OP_FROMALTSTACK:
                if len(altstack) < 1:
                    err_raiser(MissingOpArgumentsError, sop, altstack, 1)
                v = altstack.pop()
                stack.append(v)

            elif sop == OP_HASH160:
                check_args(1)
                stack.append(bitcointx.core.serialize.Hash160(stack.pop()))

            elif sop == OP_HASH256:
                check_args(1)
                stack.append(bitcointx.core.serialize.Hash(stack.pop()))

            elif sop == OP_IF or sop == OP_NOTIF:
                val = False

                if fExec:
                    check_args(1)
                    vch = stack.pop()

                    if sigversion == SIGVERSION_WITNESS_V0 and SCRIPT_VERIFY_MINIMALIF in flags:
                        if len(vch) > 1:
                            raise VerifyScriptError("SCRIPT_VERIFY_MINIMALIF check failed")
                        if len(vch) == 1 and vch[0] != 1:
                            raise VerifyScriptError("SCRIPT_VERIFY_MINIMALIF check failed")

                    val = _CastToBool(vch)
                    if sop == OP_NOTIF:
                        val = not val

                vfExec.append(val)

            elif sop == OP_IFDUP:
                check_args(1)
                vch = stack[-1]
                if _CastToBool(vch):
                    stack.append(vch)

            elif sop == OP_NIP:
                check_args(2)
                del stack[-2]

            elif sop == OP_NOP:
                pass

            elif sop >= OP_NOP1 and sop <= OP_NOP10:
                if SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS in flags:
                    err_raiser(EvalScriptError, "%s reserved for soft-fork upgrades" % OPCODE_NAMES[sop])
                else:
                    pass

            elif sop == OP_OVER:
                check_args(2)
                vch = stack[-2]
                stack.append(vch)

            elif sop == OP_PICK or sop == OP_ROLL:
                check_args(2)
                n = _CastToBigNum(stack.pop(), err_raiser)
                if n < 0 or n >= len(stack):
                    err_raiser(EvalScriptError, "Argument for %s out of bounds" % OPCODE_NAMES[sop])
                vch = stack[-n-1]
                if sop == OP_ROLL:
                    del stack[-n-1]
                stack.append(vch)

            elif sop == OP_RETURN:
                err_raiser(EvalScriptError, "OP_RETURN called")

            elif sop == OP_RIPEMD160:
                check_args(1)

                h = hashlib.new('ripemd160')
                h.update(stack.pop())
                stack.append(h.digest())

            elif sop == OP_ROT:
                check_args(3)
                tmp = stack[-3]
                stack[-3] = stack[-2]
                stack[-2] = tmp

                tmp = stack[-2]
                stack[-2] = stack[-1]
                stack[-1] = tmp

            elif sop == OP_SIZE:
                check_args(1)
                bn = len(stack[-1])
                stack.append(bitcointx.core._bignum.bn2vch(bn))

            elif sop == OP_SHA1:
                check_args(1)
                stack.append(hashlib.sha1(stack.pop()).digest())

            elif sop == OP_SHA256:
                check_args(1)
                stack.append(hashlib.sha256(stack.pop()).digest())

            elif sop == OP_SWAP:
                check_args(2)
                tmp = stack[-2]
                stack[-2] = stack[-1]
                stack[-1] = tmp

            elif sop == OP_TOALTSTACK:
                check_args(1)
                v = stack.pop()
                altstack.append(v)

            elif sop == OP_TUCK:
                check_args(2)
                vch = stack[-1]
                stack.insert(len(stack) - 2, vch)

            elif sop == OP_VERIFY:
                check_args(1)
                v = _CastToBool(stack[-1])
                if v:
                    stack.pop()
                else:
                    raise err_raiser(VerifyOpFailedError, sop)

            elif sop == OP_WITHIN:
                check_args(3)
                bn3 = _CastToBigNum(stack[-1], err_raiser)
                bn2 = _CastToBigNum(stack[-2], err_raiser)
                bn1 = _CastToBigNum(stack[-3], err_raiser)
                stack.pop()
                stack.pop()
                stack.pop()
                v = (bn2 <= bn1) and (bn1 < bn3)
                if v:
                    stack.append(b"\x01")
                else:
                    # FIXME: this is incorrect, but not caught by existing
                    # test cases
                    stack.append(b"\x00")

            else:
                err_raiser(EvalScriptError, 'unsupported opcode 0x%x' % sop)

        # size limits
        if len(stack) + len(altstack) > MAX_STACK_ITEMS:
            err_raiser(EvalScriptError, 'max stack items limit reached')

    # Unterminated IF/NOTIF/ELSE block
    if len(vfExec):
        raise EvalScriptError('Unterminated IF/ELSE block',
                              stack=stack,
                              scriptIn=scriptIn,
                              txTo=txTo,
                              inIdx=inIdx,
                              flags=flags)


def EvalScript(stack, scriptIn, txTo, inIdx, flags=(), amount=0, sigversion=SIGVERSION_BASE):
    """Evaluate a script

    stack      - Initial stack

    scriptIn   - Script

    txTo       - Transaction the script is a part of

    inIdx      - txin index of the scriptSig

    flags      - SCRIPT_VERIFY_* flags to apply

    sigversion - SIGVERSION_* version (not used for now)
    """

    try:
        _EvalScript(stack, scriptIn, txTo, inIdx, flags=flags, amount=amount, sigversion=sigversion)
    except CScriptInvalidError as err:
        raise EvalScriptError(repr(err),
                              stack=stack,
                              scriptIn=scriptIn,
                              txTo=txTo,
                              inIdx=inIdx,
                              flags=flags)


class VerifyScriptError(bitcointx.core.ValidationError):
    pass


def VerifyScript(scriptSig, scriptPubKey, txTo, inIdx, flags=None, amount=0, witness=None):
    """Verify a scriptSig satisfies a scriptPubKey

    scriptSig    - Signature

    scriptPubKey - PubKey

    txTo         - Spending transaction

    inIdx        - Index of the transaction input containing scriptSig

    Raises a ValidationError subclass if the validation fails.
    """

    if flags is None:
        flags = STANDARD_SCRIPT_VERIFY_FLAGS - UNHANDLED_SCRIPT_VERIFY_FLAGS
    else:
        flags = set(flags)  # might be passed as tuple

    if flags & UNHANDLED_SCRIPT_VERIFY_FLAGS:
        raise VerifyScriptError(
            "some of the flags cannot be handled by current code: {}".format(_flags_set_str(flags)))

    stack = []
    EvalScript(stack, scriptSig, txTo, inIdx, flags=flags)
    if SCRIPT_VERIFY_P2SH in flags:
        stackCopy = list(stack)
    EvalScript(stack, scriptPubKey, txTo, inIdx, flags=flags)
    if len(stack) == 0:
        raise VerifyScriptError("scriptPubKey left an empty stack")
    if not _CastToBool(stack[-1]):
        raise VerifyScriptError("scriptPubKey returned false")

    hadWitness = False
    if witness is None:
        witness = CScriptWitness([])

    if SCRIPT_VERIFY_WITNESS in flags and scriptPubKey.is_witness_scriptpubkey():
        hadWitness = True

        if scriptSig:
            raise VerifyScriptError("scriptSig is not empty")

        VerifyWitnessProgram(witness,
                             scriptPubKey.witness_version(),
                             scriptPubKey.witness_program(),
                             txTo, inIdx, flags=flags, amount=amount)

        # Bypass the cleanstack check at the end. The actual stack is obviously not clean
        # for witness programs.
        stack = stack[:1]

    # Additional validation for spend-to-script-hash transactions
    if SCRIPT_VERIFY_P2SH in flags and scriptPubKey.is_p2sh():
        if not scriptSig.is_push_only():
            raise VerifyScriptError("P2SH scriptSig not is_push_only()")

        # restore stack
        stack = stackCopy

        # stack cannot be empty here, because if it was the
        # P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        # an empty stack and the EvalScript above would return false.
        assert len(stack)

        pubKey2 = CScript(stack.pop())

        EvalScript(stack, pubKey2, txTo, inIdx, flags=flags)

        if not len(stack):
            raise VerifyScriptError("P2SH inner scriptPubKey left an empty stack")

        if not _CastToBool(stack[-1]):
            raise VerifyScriptError("P2SH inner scriptPubKey returned false")

        # P2SH witness program
        if SCRIPT_VERIFY_WITNESS in flags and pubKey2.is_witness_scriptpubkey():
            hadWitness = True

            if scriptSig != CScript([pubKey2]):
                raise VerifyScriptError("scriptSig is not exactly a single push of the redeemScript")

            VerifyWitnessProgram(witness,
                                 pubKey2.witness_version(),
                                 pubKey2.witness_program(),
                                 txTo, inIdx, flags=flags, amount=amount)

            # Bypass the cleanstack check at the end. The actual stack is obviously not clean
            # for witness programs.
            stack = stack[:1]

    if SCRIPT_VERIFY_CLEANSTACK in flags:
        assert SCRIPT_VERIFY_P2SH in flags

        if len(stack) == 0:
            raise VerifyScriptError("scriptPubKey left an empty stack")
        elif len(stack) != 1:
            raise VerifyScriptError("scriptPubKey left extra items on stack")

    if SCRIPT_VERIFY_WITNESS in flags:
        # We can't check for correct unexpected witness data if P2SH was off, so require
        # that WITNESS implies P2SH. Otherwise, going from WITNESS->P2SH+WITNESS would be
        # possible, which is not a softfork.
        assert SCRIPT_VERIFY_P2SH in flags, "SCRIPT_VERIFY_WITNESS requires SCRIPT_VERIFY_P2SH"

        if not hadWitness and witness:
            raise VerifyScriptError("Unexpected witness")


class VerifySignatureError(bitcointx.core.ValidationError):
    pass


# XXX not tested for segwit, not covered by tests
def VerifySignature(txFrom, txTo, inIdx):
    """Verify a scriptSig signature can spend a txout

    Verifies that the scriptSig in txTo.vin[inIdx] is a valid scriptSig for the
    corresponding COutPoint in transaction txFrom.
    """
    if inIdx < 0:
        raise VerifySignatureError("inIdx negative")
    if inIdx >= len(txTo.vin):
        raise VerifySignatureError("inIdx >= len(txTo.vin)")
    txin = txTo.vin[inIdx]

    if txin.prevout.n < 0:
        raise VerifySignatureError("txin prevout.n negative")
    if txin.prevout.n >= len(txFrom.vout):
        raise VerifySignatureError("txin prevout.n >= len(txFrom.vout)")
    txout = txFrom.vout[txin.prevout.n]

    if txin.prevout.hash != txFrom.GetTxid():
        raise VerifySignatureError("prevout hash does not match txFrom")

    witness = None
    if txFrom.wit:
        witness = ctx.wit.vtxinwit[vin_index].scriptWitness

    VerifyScript(txin.scriptSig, txout.scriptPubKey, txTo, inIdx,
                 amount=txout.nValue, witness=witness or CScriptWitness([]))


__all__ = (
    'MAX_STACK_ITEMS',
    'SCRIPT_VERIFY_P2SH',
    'SCRIPT_VERIFY_STRICTENC',
    'SCRIPT_VERIFY_DERSIG',
    'SCRIPT_VERIFY_LOW_S',
    'SCRIPT_VERIFY_NULLDUMMY',
    'SCRIPT_VERIFY_SIGPUSHONLY',
    'SCRIPT_VERIFY_MINIMALDATA',
    'SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS',
    'SCRIPT_VERIFY_CLEANSTACK',
    'SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY',
    'SCRIPT_VERIFY_FLAGS_BY_NAME',
    'EvalScriptError',
    'MaxOpCountError',
    'MissingOpArgumentsError',
    'ArgumentsInvalidError',
    'VerifyOpFailedError',
    'EvalScript',
    'VerifyScriptError',
    'VerifyScript',
    'VerifySignatureError',
    'VerifySignature',
)
