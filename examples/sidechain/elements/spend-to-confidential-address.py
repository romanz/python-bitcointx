#!/usr/bin/env python3
#
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

# This code loads raw transaction and the key from two separate files,
# seeks for the output of the loaded transaction that it could spend with
# this key, unblinds it, and then creates a new transaction that spends
# this output to the provided destination address.
# If the destination address is confidential, the resulting transaction
# will be blinded.

import os
import sys

from bitcointx import SelectParams
from bitcointx.core import (
    x, b2x, Uint256,
    CTransaction, CTxIn, CTxOut, COutPoint,
    CMutableTxOut
)
from bitcointx.core.key import CPubKey
from bitcointx.core.scripteval import VerifyScript
from bitcointx.wallet import (
    # The address classes will use base58 prefixes for Elements
    # sidechain after we call SelectParams('sidechain/elements')
    CBitcoinSecret, CBitcoinAddress, P2PKHBitcoinAddress,
)
from bitcointx.core.script import (
    CScript, OP_RETURN, SignatureHash,
    SIGHASH_ALL, SIGVERSION_BASE
)
from bitcointx.sidechain.elements import (
    CConfidentialValue, CConfidentialAsset, CConfidentialAddress,
    BlindingInputDescriptor
)


if __name__ == '__main__':
    if len(sys.argv) != 5:
        sys.stderr.write(
            "usage: {} <raw-hex-tx-file> <spending-key-wif-file> <unblinding-key-hex-file> <destination-address>\n"
            .format(sys.argv[0]))
        sys.exit(-1)

    # Switch the chain parameters to Elements sidechain
    SelectParams('sidechain/elements')

    # Read in and decode the blinded transaction.
    # expected to be hex-encoded as one line.
    with open(sys.argv[1]) as f:
        input_tx = CTransaction.deserialize(x(f.readline().rstrip()))

    # Read in the key, expected to be in WIF format.
    with open(sys.argv[2]) as f:
        key = CBitcoinSecret(f.readline().rstrip())

    # Read in the unblinding key, expected to be in HEX format.
    with open(sys.argv[3]) as f:
        bkey = CBitcoinSecret.from_secret_bytes(x(f.readline().rstrip()))

    dst_addr = CBitcoinAddress(sys.argv[4])

    # Construct an address from the loaded key
    src_addr = P2PKHBitcoinAddress.from_pubkey(key.pub)

    sys.stderr.write('\nSearching for ouptut with address {}\n'.format(src_addr))

    utxo = None
    fee_asset = None
    # Search for output in the transaction that spends to the address that
    # we have. We are going to spend the first output that we find.
    for in_n, in_vout in enumerate(input_tx.vout):
        if utxo is None and in_vout.scriptPubKey == src_addr.to_scriptPubKey():
            utxo = in_vout
            utxo_n = in_n
        if in_vout.is_fee():
            assert fee_asset is None or fee_asset == in_vout.nAsset,\
                "expecting only one fee asset"
            fee_asset = in_vout.nAsset
            # For simplicity, we will use the same fee value as in input tx
            fee_value = in_vout.nValue.to_amount()

    if utxo is None:
        sys.stderr.write('Not found\n')
        sys.exit(-1)

    sys.stderr.write("Found at index {}\n".format(utxo_n))

    if fee_asset is None:
        sys.stderr.write('Cannot proceed: Input transaction does not have fee ouptut\n')
        sys.exit(-1)

    # Note that nValue of vout in Elements is not a simple int,
    # but CConfidentialValue, which can either be explicit, and can be
    # converted to satoshis with to_amount(), or it can be blinded, in
    # which case you need to unblind the output to know its value.
    if utxo.nValue.is_explicit():
        amount_to_spend = utxo.nValue.to_amount()
        # If the value is explicit, asset should be explicit too
        assert utxo.nAsset.is_explicit()
        asset_to_spend = utxo.nAsset
        # No blinding
        blinding_factor = Uint256()
        asset_blinding_factor = Uint256()
    else:
        ok, result = utxo.unblind(
            bkey, input_tx.wit.vtxoutwit[utxo_n].rangeproof)

        if not ok:
            sys.stderr.write('Cannot unblind vout {} with provided unblinding key: {}\n'
                             .format(utxo_n, result))
            sys.exit(-1)

        amount_to_spend = result.amount
        asset_to_spend = result.asset
        blinding_factor = result.blinding_factor
        asset_blinding_factor = result.asset_blinding_factor

    sys.stderr.write("  amount: {}\n".format(amount_to_spend))
    sys.stderr.write("  asset:  {}\n".format(asset_to_spend.to_hex()))

    # For simplicity, to not deal with dust threshold, we just require
    # the spend amount to be at least 2x of the fee of the input transaction
    if amount_to_spend < fee_value * 2:
        sys.stderr.write('Value of txout {} is too small '
                         '(expecting at least 2x fee value of input transaction)\n'
                         .format(utxo_n))
        sys.exit(-1)

    dst_value = amount_to_spend - fee_value

    # An array of blinding pubkeys that we will supply to tx.blind()
    # It should cover all the outputs of the resulting transaction.
    output_pubkeys = []

    if isinstance(dst_addr, CConfidentialAddress):
        output_pubkeys.append(dst_addr.blinding_pubkey)
    else:
        output_pubkeys.append(CPubKey())

    # Construct a transaction that spends the output we found
    # to the given destination address.
    # Note that the CTransaction is just a frontend for convenience,
    # and the created object will be the instance of the
    # CElementsSidechainTransaction class. The same with CTxIn, CTxOut, etc.
    tx = CTransaction(
        vin=[CTxIn(prevout=COutPoint(hash=input_tx.GetTxid(),
                                     n=utxo_n))],
        vout=[CTxOut(nValue=CConfidentialValue(dst_value),
                     nAsset=CConfidentialAsset(asset_to_spend),
                     scriptPubKey=dst_addr.to_scriptPubKey()),
              # Fee output must be explicit in Elements
              CTxOut(nValue=CConfidentialValue(fee_value),
                     nAsset=fee_asset)])

    # Add empty pubkey for fee output
    output_pubkeys.append(CPubKey())

    # We cannot blind an immutable transaction. Make it mutable.
    tx = tx.to_mutable()

    if not utxo.nValue.is_explicit() and\
            not isinstance(dst_addr, CConfidentialAddress):
        # If we are spending a blinded utxo, at least one of the outputs
        # of the resulting transaction should be blinded.
        # If dst_addr is not confidential, we need to add dummy blinded output.
        dummy_blinding_key = CBitcoinSecret.from_secret_bytes(os.urandom(32))
        tx.vout.append(
            CMutableTxOut(
                nValue=CConfidentialValue(0),
                nAsset=CConfidentialAsset(asset_to_spend),
                scriptPubKey=CScript([OP_RETURN])))

        # Append dummy blinding pubkey to be used by tx.blind()
        output_pubkeys.append(dummy_blinding_key.pub)

    # Save unblinded serialized tx so if the tx is not to be blinded,
    # we can check that tx.blind() did not actually change anything
    unblinded_serialized = tx.serialize()

    # input_* arrays contain one element because
    # our transaction only have one input.
    # output_pubkeys may contain 2 or 3 elements
    # (3 if we added dummy OP_RETURN above)
    ok, blind_result = tx.blind(
        input_descriptors=[
            BlindingInputDescriptor(
                asset=asset_to_spend,
                amount=amount_to_spend,
                blinding_factor=blinding_factor,
                asset_blinding_factor=asset_blinding_factor
            )
        ],
        output_pubkeys=output_pubkeys)

    if not ok:
        sys.stderr.write('unable to blind: {}'.format(blind_result))
        sys.exit(-1)

    num_expected_to_blind = sum(int(pub.is_valid) for pub in output_pubkeys)
    assert blind_result.num_successfully_blinded == num_expected_to_blind,\
        "expected to blind {}, actually blinded {}".format(
            num_expected_to_blind, blind_result.num_successfully_blinded)

    if blind_result.num_successfully_blinded == 0:
        sys.stderr.write("\nNOTE: transaction is not blinded\n")
        assert unblinded_serialized == tx.serialize()
    else:
        sys.stderr.write("\nSuccessfully blinded {} outputs\n"
                         .format(blind_result.num_successfully_blinded))

    # Sign the only input of the transaction
    input_index = 0  # only one input in this tx - index 0
    sighash = SignatureHash(
        src_addr.to_scriptPubKey(), tx, input_index,
        SIGHASH_ALL, amount=amount_to_spend, sigversion=SIGVERSION_BASE)
    sig = key.sign(sighash) + bytes([SIGHASH_ALL])
    tx.vin[input_index].scriptSig = CScript([CScript(sig), CScript(key.pub)])
    VerifyScript(tx.vin[input_index].scriptSig, src_addr.to_scriptPubKey(),
                 tx, input_index, amount=amount_to_spend)

    sys.stderr.write("Successfully signed\n")

    # Print out blinded and signed transaction, hex-encoded.
    print(b2x(tx.serialize()))
