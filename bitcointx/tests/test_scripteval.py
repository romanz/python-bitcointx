# Copyright (C) 2013-2017 The python-bitcoinlib developers
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

from __future__ import absolute_import, division, print_function, unicode_literals

import json
import os
import unittest
import logging

from binascii import unhexlify

from bitcointx.core import CTxOut, CTxIn, CTransaction, COutPoint, ValidationError, x as ParseHex
from bitcointx.core import CTxWitness, CTxInWitness
from bitcointx.core.script import OPCODES_BY_NAME, CScript, CScriptWitness
from bitcointx.core.script import OP_0
from bitcointx.core.scripteval import VerifyScript
from bitcointx.core.scripteval import SCRIPT_VERIFY_FLAGS_BY_NAME


def parse_script(s):
    def ishex(s):
        return set(s).issubset(set('0123456789abcdefABCDEF'))

    r = []

    # Create an opcodes_by_name table with both OP_ prefixed names and
    # shortened ones with the OP_ dropped.
    opcodes_by_name = {}
    for name, code in OPCODES_BY_NAME.items():
        opcodes_by_name[name] = code
        opcodes_by_name[name[3:]] = code

    for word in s.split():
        if word.isdigit() or (word[0] == '-' and word[1:].isdigit()):
            r.append(CScript([int(word)]))
        elif word.startswith('0x') and ishex(word[2:]):
            # Raw ex data, inserted NOT pushed onto stack:
            r.append(unhexlify(word[2:].encode('utf8')))
        elif len(word) >= 2 and word[0] == "'" and word[-1] == "'":
            r.append(CScript([bytes(word[1:-1].encode('utf8'))]))
        elif word in opcodes_by_name:
            r.append(CScript([opcodes_by_name[word]]))
        else:
            raise ValueError("Error parsing script: %r" % s)

    return CScript(b''.join(r))


def load_test_vectors(name):
    logging.basicConfig()
    log = logging.getLogger("Test_EvalScript")
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        fixme_comment = None
        num_skipped = 0
        for test_case in json.load(fd):
            if len(test_case) == 1:
                continue  # comment

            if len(test_case) == 2:
                if test_case[0] == 'FIXME':
                    fixme_comment = test_case[1]
                    continue
                if test_case[0] == 'FIXME_END':
                    log.warning("SKIPPED {} tests: {}"
                                .format(num_skipped, fixme_comment))
                    fixme_comment = None
                    num_skipped = 0
                    continue

            if fixme_comment:
                num_skipped += 1
                continue

            to_unpack = test_case.copy()

            witness = CScriptWitness()
            nValue = 0
            if isinstance(to_unpack[0], list):
                wdata = to_unpack.pop(0)
                stack = [CScript(ParseHex(d)) for d in wdata[:-1]]
                witness = CScriptWitness(stack)
                nValue = int(round(wdata[-1] * 1e8))

            if len(to_unpack) == 4:
                to_unpack.append('')  # add missing comment

            assert len(to_unpack) == 5, "unexpected test data format: {}".format(to_unpack)

            scriptSig, scriptPubKey, flags, expected_result, comment = to_unpack

            scriptSig = parse_script(scriptSig)
            scriptPubKey = parse_script(scriptPubKey)

            flag_set = set()
            for flag in flags.split(','):
                if flag == '' or flag == 'NONE':
                    pass

                else:
                    try:
                        flag = SCRIPT_VERIFY_FLAGS_BY_NAME[flag]
                    except IndexError:
                        raise Exception('Unknown script verify flag %r' % flag)

                    flag_set.add(flag)

            yield (scriptSig, scriptPubKey, witness, nValue,
                   flag_set, expected_result, comment, test_case)

        if fixme_comment is not None:
            raise Exception('Unbalanced FIXME blocks in test data')


class Test_EvalScript(unittest.TestCase):
    def create_test_txs(self, scriptSig, scriptPubKey, witness, nValue):
        txCredit = CTransaction([CTxIn(COutPoint(), CScript([OP_0, OP_0]), nSequence=0xFFFFFFFF)],
                                [CTxOut(nValue, scriptPubKey)],
                                witness=CTxWitness(),
                                nLockTime=0, nVersion=1)
        txSpend = CTransaction([CTxIn(COutPoint(txCredit.GetTxid(), 0), scriptSig, nSequence=0xFFFFFFFF)],
                               [CTxOut(nValue, CScript())],
                               nLockTime=0, nVersion=1,
                               witness=CTxWitness([CTxInWitness(witness)]))
        return (txCredit, txSpend)

    def test_script(self):
        for t in load_test_vectors('script_tests.json'):
            (scriptSig, scriptPubKey, witness, nValue,
             flags, expected_result, comment, test_case) = t
            (txCredit, txSpend) = self.create_test_txs(scriptSig, scriptPubKey, witness, nValue)

            try:
                VerifyScript(scriptSig, scriptPubKey, txSpend, 0, flags, amount=nValue, witness=witness)
            except ValidationError as err:
                if expected_result == 'OK':
                    self.fail('Script FAILED: %r %r %r with exception %r\n\nTest data: %r' % (scriptSig, scriptPubKey, comment, err, test_case))
                continue

            if expected_result != 'OK':
                self.fail('Expected %r to fail (%s)' % (test_case, expected_result))
