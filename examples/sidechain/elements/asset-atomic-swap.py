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

# This code spawns two processes, each process connects to its own
# Elements daemon, and issues its own asset(s).
# Then these two processes communicate with each other to prepare
# a transaction that atomically swaps their assets.
# Because the assets is within one blockchain network, the swap is executed
# by a cooperatively constructed and signed transaction that sends
# Bob's asset to Alice, and Alice's assets to Bob.
# For simplicity, Alice will pay the full fee for the transaction.

import os
import sys
import time
import signal
import traceback

from multiprocessing import Process, Pipe, Lock

from bitcointx import SelectParams
from bitcointx.rpc import RawProxy, JSONRPCError
from bitcointx.core import (
    COIN, Uint256, x, lx, b2x,
    CTransaction, CMutableTransaction, CTxIn, CTxOut, COutPoint,
    CMutableTxOut, CMutableTxIn, CMutableTxInWitness, CMutableTxOutWitness
)
from bitcointx.core.script import (
    CScript, SignatureHash,
    SIGHASH_ALL, SIGVERSION_BASE
)
from bitcointx.core.scripteval import VerifyScript
from bitcointx.core.key import CPubKey
from bitcointx.wallet import (
    CBitcoinAddress, CBitcoinSecret, P2PKHBitcoinAddress
)
from bitcointx.sidechain.elements import (
    CAsset, CConfidentialValue, CConfidentialAsset
)
from collections import namedtuple

# A simple offer struct
AtomicSwapOffer = namedtuple('AtomicSwapOffer', 'asset amount')

# A global lock variable to coordinate console output between
# child processes. We could pass the lock as arguments to the
# process functions, but it is simpler to make it global var
# and not clutter the participant process funcs with unneeded details
console_lock = None

# Participant functions need to know the asset that the fee is paid in.
# It will be specified on the command line when the example is run.
fee_asset = None

FIXED_FEE_SATOSHI = 10000  # For simplicity, we use fixed fee amount per tx

ansi_colors = {
    # Uncomment to have participant messages in different colors
    # 'alice': '\033[1;32m',  # green
    # 'bob': '\033[1;35m'  # purple
}
end_color = '\033[0m'


def main():
    """The main function prepares everyting for two participant processes
    to operate and communicate with each other, and starts them"""

    global console_lock
    global fee_asset

    if len(sys.argv) != 4:
        sys.stderr.write(
            "usage: {} <first-daemon-dir> <second-daemon-dir> fee_asset\n"
            .format(sys.argv[0]))
        sys.exit(-1)

    elements_config_path1 = os.path.join(sys.argv[1], 'elements.conf')
    if not os.path.isfile(elements_config_path1):
        sys.stderr.write(
            'config file {} not found or is not a regular file'
            .format(elements_config_path1))
        sys.exit(-1)

    elements_config_path2 = os.path.join(sys.argv[2], 'elements.conf')
    if not os.path.isfile(elements_config_path2):
        sys.stderr.write(
            'config file {} not found or is not a regular file'
            .format(elements_config_path2))
        sys.exit(-1)

    try:
        fee_asset = CAsset(lx(sys.argv[3]))
    except ValueError as e:
        sys.stderr.write('specified fee asset is not valid: {}'.format(e))
        sys.exit(-1)

    # Initialize console lock
    console_lock = Lock()

    # Switch the chain parameters to Elements sidechain.
    # The setting should remain in place for child processes.
    SelectParams('sidechain/elements')

    # Create a pipe for processes to communicate
    pipe1, pipe2 = Pipe(duplex=True)

    # Create process to run 'alice' participant function
    # and pass it one end of a pipe, and path to config file for node1
    p1 = Process(target=participant, name='alice',
                 args=(alice, 'Alice', pipe1, elements_config_path1))

    # Create process to run 'bob' participant function
    # and pass it one end of a pipe, and path to config file for node2
    p2 = Process(target=participant, name='bob',
                 args=(bob, '  Bob', pipe2, elements_config_path2))

    # Start both processes
    p1.start()
    p2.start()

    # The childs are on their own now. We just wait for them to finish.
    try:
        p1.join()
        p2.join()
    except KeyboardInterrupt:
        print()
        print("=============================================================")
        print("Interrupted from keyboard, terminating participant processes.")
        print("-------------------------------------------------------------")
        for p in (p1, p2):
            if p.is_alive():
                print('terminating', p.name)
                p.terminate()
            else:
                print(p.name, 'is not alive')
            p.join()
        print('Exiting.')
        print("=============================================================")


def participant(func, name, pipe, config_path):
    """Prepares environment for participants, run their functions,
    and handles the errors they did not bother to hanlde"""

    def say(msg): participant_says(name, msg)

    # Custom exception class to distinguish a case when
    # participant calss die() from other exceptions
    class ProtocolFailure(Exception):
        ...

    def die(msg): raise ProtocolFailure(msg)

    def recv(expected_type):
        timeout = 60
        if not pipe.poll(timeout):
            die('No messages received in {} seconds'.format(timeout))
        msg = pipe.recv()

        if msg[0] == 'bye!':
            say('Communication finished unexpectedly, exiting.')
            sys.exit(-1)

        if msg[0] != expected_type:
            die("unexpected message type '{}', expected '{}'"
                .format(msg[0], expected_type))

        return msg[1]

    def send(msg_type, data=None): pipe.send([msg_type, data])

    # Ignore keyboard interrupt, parent process handles it.
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    try:
        # Connect to Elements Core RPC with specified path
        rpc = connect_rpc(say, config_path)
        # Execute participant's function
        func(say, recv, send, die, rpc)
    except Exception as e:
        say('FAIL with {}: {}'.format(type(e).__name__, e))
        say("Traceback:")
        print("="*80)
        traceback.print_tb(sys.exc_info()[-1])
        print("="*80)
        send('bye!')
        sys.exit(-1)


def btc_to_satoshi(value):
    """Simple utility function to convert from BTC to satoshi"""
    return int(round(float(value) * COIN))


def participant_says(name, msg):
    """A helper function to coordinate
    console message output between processes"""

    color = ansi_colors.get(name.strip().lower(), '')
    console_lock.acquire()
    try:
        print("{}{}: {}{}".format(color, name, msg,
                                  end_color if color else ''))
    finally:
        console_lock.release()


def connect_rpc(say, config_path):
    """Connect to Elements daemon RPC and return RawProxy interface"""

    say('Connecting to Elements daemon RPC interface, using config in {}'
        .format(config_path))

    # At the time of writing, rpc.Proxy does not know about
    # Elements-specific options and fields.
    # We will use rpc.RawProxy and will do any conversions ourselves.
    return RawProxy(btc_conf_file=config_path)


def wait_confirm(say, txid, die, rpc):
    """Wait for particular transaction to be confirmed.
    generate test blocks if it is in mempool, but not confirmed.
    raise Exception if not confirmed in 60 seconds"""

    say('Waiting for txid {} to confim'.format(txid))
    for _ in range(60):
        try:
            confirms = rpc.getrawtransaction(txid, 1).get('confirmations', 0)
            if confirms > 0:
                return
            rpc.generate(1)
        except JSONRPCError as e:
            if e.error['code'] == -5:
                # Not yet in mempool, wait
                pass
        time.sleep(1)

    die('timed out waiting for confirmation')


def issue_asset(say, asset_amount, rpc):
    """Issue asset and return CAsset instance and utxo to spend"""

    say('Issuing my own new asset, amount: {}'.format(asset_amount))

    # No reissuance, so we specify tokenamount as 0
    issue = rpc.issueasset(asset_amount, 0)

    asset_str = issue['asset']
    say('The asset is {}'.format(asset_str))

    say('Getting unspent utxo for asset {}'.format(asset_str))
    # There should be only one utxo for newly-issued asset, we can use
    # destructuring assignment to get the first element of resulting list.
    # Utxo should be unconfirmed yet, so we specify 0 for minconf and maxconf.
    (asset_utxo, ) = rpc.listunspent(0, 0, [], False, asset_str)

    say('Unspent utxo for asset {} is {}:{}'
        .format(asset_str, asset_utxo['txid'], asset_utxo['vout']))

    say("Retrieving private key to spend UTXO (source address {})"
        .format(asset_utxo['address']))

    # Retrieve key to spend the UTXO and add it to asset_utxo dict
    asset_utxo['key'] = CBitcoinSecret(rpc.dumpprivkey(asset_utxo['address']))

    return asset_str, asset_utxo


def get_dst_addr(say, rpc):
    """Generate an address and retrieve blinding key for it"""

    # Note that we could generate our own keys, and make
    # addresses from them, and then derive the blinding keys,
    # but then we would have to decide how to store the keys
    # for the user to be able to do own exploration
    # after example finishes working. We choose the easiest path.
    #
    # Note that if we have master blinding key
    # (Elements will include master blinding key in wallet dump
    # in future versions), we could derive the blinding key
    # from the master key and the address, with this code:
    # addr.to_scriptPubKey().derive_blinding_key(blinding_derivation_key)
    # derive_blinding_key() follows the logic of blinding key
    # derivation in Elements Core source.

    say('Generating new address and retrieving blinding key for it')
    addr_str = rpc.getnewaddress()
    # Retrieve the blinding key
    blinding_key = CBitcoinSecret.from_secret_bytes(
        x(rpc.dumpblindingkey(addr_str)))

    return addr_str, blinding_key


def find_utxo_for_fee(say, die, rpc):
    """Find suitable utxo to pay the fee.
    Retrieve thekey to spend this utxo and add it to
    the returned dict."""

    # Find utxo to use for fee. In our simple example, only Alice pays the fee.
    # To be on a safe side, include only transactions
    # that are confirmed (1 as 'minconf' argument of listunspent)
    # and safe to spend (False as 'include_unsafe' # argument of listunspent)
    say('Searching for utxo for fee asset')
    utxo_list = rpc.listunspent(1, 9999999, [], False, fee_asset.to_hex())
    utxo_list.sort(key=lambda u: u['amount'])
    for utxo in utxo_list:
        # To not deal with possibility of dust outputs,
        # just require fee utxo to be big enough
        if btc_to_satoshi(utxo['amount']) >= FIXED_FEE_SATOSHI*2:
            utxo['key'] = CBitcoinSecret(rpc.dumpprivkey(utxo['address']))
            if 'assetcommitment' not in utxo:
                # If UTXO is not blinded, Elements daemon will not
                # give us assetcommitment, so we need to generate it ourselves.
                asset = CAsset(lx(utxo['asset']))
                utxo['assetcommitment'] = b2x(asset.to_commitment())
            return utxo
    else:
        die('Cannot find utxo for fee that is >= {} satoshi'
            .format(FIXED_FEE_SATOSHI*2))


def print_asset_balances(say, offers, rpc):
    say('Current asset balance:')
    for offer in offers:
        balance = rpc.getbalance("*", 1, False, offer.asset)
        say('{}: {}'.format(offer.asset, balance))


def sign_input(tx, input_index, amount, key):
    """Sign an input of transaction.
    Single-signature signing with SIGHASH_ALL"""
    src_addr = P2PKHBitcoinAddress.from_pubkey(key.pub)
    sighash = SignatureHash(
        src_addr.to_scriptPubKey(), tx, input_index,
        SIGHASH_ALL, amount=amount, sigversion=SIGVERSION_BASE)
    sig = key.sign(sighash) + bytes([SIGHASH_ALL])
    tx.vin[input_index].scriptSig = CScript([CScript(sig), CScript(key.pub)])
    VerifyScript(tx.vin[input_index].scriptSig, src_addr.to_scriptPubKey(),
                 tx, input_index, amount=amount)


def alice(say, recv, send, die, rpc):
    """A function that implements the logic
    of the first participant of an asset atomic swap"""

    # Issue two asset that we are going to swap to Bob's 1 asset
    asset1_str, asset1_utxo = issue_asset(say, 1.0, rpc)
    asset2_str, asset2_utxo = issue_asset(say, 1.0, rpc)

    # We will need to pay a fee in an asset suitable for this
    fee_utxo = find_utxo_for_fee(say, die, rpc)

    say('Getting change address for fee asset')
    # We don't care for blinding key of change - the node will
    # have it, anyway, and we don't need to unblind the change.
    fee_change_addr_str, _ = get_dst_addr(say, rpc)

    say('Will use utxo {}:{} (amount: {}) for fee, change will go to {}'
        .format(fee_utxo['txid'], fee_utxo['vout'], fee_utxo['amount'],
                fee_change_addr_str))

    say('Setting up communication with Bob')

    # Tell Bob that we are ready to communicate
    send('ready')

    # To avoid mempool synchronization problems,
    # in our example Alice is the one in charge of generating test blocks.
    # Bob gives alice txid of his transaction that he wants to be confirmed.
    bob_txid = recv('wait-txid-confirm')

    # Make sure asset issuance transactions are confirmed
    rpc.generate(1)
    wait_confirm(say, asset1_utxo['txid'], die, rpc)
    wait_confirm(say, asset2_utxo['txid'], die, rpc)
    wait_confirm(say, bob_txid, die, rpc)

    # Make sure Bob is alive and ready to communicate, and send
    # him an offer for two assets
    say('Sending offer to Bob')
    my_offers = [
        AtomicSwapOffer(asset=asset1_str,
                        amount=btc_to_satoshi(asset1_utxo['amount'])),
        AtomicSwapOffer(asset=asset2_str,
                        amount=btc_to_satoshi(asset2_utxo['amount']))
    ]
    send('offer', my_offers)

    bob_offer = recv('offer')

    print_asset_balances(say, my_offers + [bob_offer], rpc)

    say('Bob responded with his offer: {}'.format(bob_offer))

    # We unconditionally accept Bob's offer - his asset is
    # equally worthless as ours :-)

    # Generate an address for Bob to send his asset to.
    addr_str, blinding_key = get_dst_addr(say, rpc)

    say('Sending my address and assetcommitments for my UTXOs to Bob')
    # Send Bob our address, and the assetcommitments of our UTXOs
    # (but not any other information about our UTXO),
    # so he can construct and blind a partial transaction that
    # will spend his own UTXO, to send his asset to our address.
    assetcommitments = [asset1_utxo['assetcommitment'],
                        asset2_utxo['assetcommitment'],
                        fee_utxo['assetcommitment']]

    send('addr_and_assetcommitments', (addr_str, assetcommitments))

    partial_tx_bytes = recv('partial_blinded_tx')

    say('Got partial blinded tx of size {} bytes from Bob'
        .format(len(partial_tx_bytes)))

    partial_tx = CTransaction.deserialize(partial_tx_bytes)

    if len(partial_tx.vout) != 1:
        die('unexpected number of outputs in tx from Bob: expected 1, got {}'
            .format(len(partial_tx.vout)))

    ok, result = partial_tx.vout[0].unblind(
        blinding_key, partial_tx.wit.vtxoutwit[0].rangeproof)

    if not ok:
        die('cannot unblind output that should have been directed to us: {}'
            .format(result))

    if result.asset.to_hex() != bob_offer.asset:
        die("asset in partial transaction from Bob {} is not the same "
            "as asset in Bob's initial offer ({})"
            .format(result.asset.to_hex(), bob_offer.asset))

    if result.amount != bob_offer.amount:
        die("amount in partial transaction from Bob {} is not the same "
            "as amount in Bob's initial offer ({})"
            .format(result.amount, bob_offer.amount))

    say("Asset and amount in partial transaction matches Bob's offer")

    bob_addr_list, bob_assetcommitment = recv('addr_list_and_assetcommitment')

    if len(bob_addr_list) != len(my_offers):
        die('unexpected address list lenth from Bob. expected {}, got {}'
            .format(len(my_offers), len(bob_addr_list)))

    say("Bob's addresses to receive my assets: {}".format(bob_addr_list))

    # Convert Bob's addresses to address objects.
    # If Bob passes invalid address, we die with with exception.
    bob_addr_list = [CBitcoinAddress(a) for a in bob_addr_list]

    # Add our own inputs and outputs to Bob's partial tx

    # Create new mutable transaction from partial_tx
    tx = partial_tx.to_mutable()

    # We have assetcommitment for the first input,
    # other data is not needed for it.
    # initialize first elements of the arrays with empty/negative data.
    blinders = [Uint256()]
    assetblinders = [Uint256()]
    assets = [CAsset()]
    amounts = [-1]

    # First output is already blinded, fill the slot with empty data
    output_pubkeys = [CPubKey()]

    # But assetcommitments array should start with Bob's asset commitment
    assetcommitments = [x(bob_assetcommitment)]

    # We will add our inputs for asset1 and asset2, and also an input
    # that will be used to pay the fee.

    # Note that the order is important: Bob blinded his transaction
    # with assetcommitments in the order we send them to him,
    # and we should add our inputs in the same order.
    utxos_to_add = (asset1_utxo, asset2_utxo, fee_utxo)

    # Add inputs for asset1 and asset2 and fee_asset and prepare input data
    # for blinding
    for utxo in utxos_to_add:
        # When we create CMutableTransaction and pass CTxIn,
        # it will be converted to CMutableTxIn. But if we append
        # to tx.vin or tx.vout, we need to use mutable versions
        # of the txin/txout classes, or else blinding or signing
        # will fail with error, unable to modify the instances.
        # COutPoint is not modified, though, so we can leave it
        # immutable.
        tx.vin.append(
            CMutableTxIn(prevout=COutPoint(hash=lx(utxo['txid']),
                                           n=utxo['vout'])))
        blinders.append(Uint256(lx(utxo['blinder'])))
        assetblinders.append(Uint256(lx(utxo['assetblinder'])))
        assets.append(CAsset(lx(utxo['asset'])))
        amounts.append(btc_to_satoshi(utxo['amount']))
        # If we are supplying asset blinders and assetblinders for
        # particular input, assetcommitment data for that input do
        # not need to be correct. But if we are supplying assetcommitments
        # at all (auxiliary_generators argument to tx.blind()),
        # then all the elements of that array must have correct
        # type (bytes) and length (33). This is a requirement of the original
        # Elements Core API, and python-bitcointx requires this, too.
        assetcommitments.append(b'\x00'*33)

    # Add outputs to give Bob all our assets, and fill output pubkeys
    # for blinding the outputs to Bob's addresses
    for n, offer in enumerate(my_offers):
        tx.vout.append(
            CMutableTxOut(nValue=CConfidentialValue(offer.amount),
                          nAsset=CConfidentialAsset(CAsset(lx(offer.asset))),
                          scriptPubKey=bob_addr_list[n].to_scriptPubKey()))
        output_pubkeys.append(bob_addr_list[n].blinding_pubkey)

    # Add change output for fee asset
    fee_change_amount = btc_to_satoshi(fee_utxo['amount']) - FIXED_FEE_SATOSHI
    fee_change_addr = CBitcoinAddress(fee_change_addr_str)
    tx.vout.append(
        CMutableTxOut(nValue=CConfidentialValue(fee_change_amount),
                      nAsset=CConfidentialAsset(fee_asset),
                      scriptPubKey=fee_change_addr.to_scriptPubKey()))
    output_pubkeys.append(fee_change_addr.blinding_pubkey)

    # Add fee output.
    # Note that while we use CConfidentialAsset and CConfidentialValue
    # to specify value and asset, they are not in fact confidential here
    # - they are explicit, because we pass explicit values at creation.
    # You can check if they are explicit or confidential
    # with nValue.is_explicit(). If they are explicit, you can access
    # the unblinded values with nValue.to_amount() and nAsset.to_asset()
    tx.vout.append(CMutableTxOut(nValue=CConfidentialValue(FIXED_FEE_SATOSHI),
                                 nAsset=CConfidentialAsset(fee_asset)))
    # Add dummy pubkey for non-blinded fee output
    output_pubkeys.append(CPubKey())

    # Our transaction lacks txin witness instances for the added inputs,
    # and txout witness instances for added outputs.
    # Transaction serialization code will require in/out witness array length
    # to be equal to vin/vout array length.
    # Therefore we need to add dummy txin and txout witnesses for each
    # input and output that we added to transaction
    # we added one input and one output per asset, and an additional
    # input/change-output for fee asset.
    for _ in utxos_to_add:
        tx.wit.vtxinwit.append(CMutableTxInWitness())
        tx.wit.vtxoutwit.append(CMutableTxOutWitness())

    # And one extra dummy txout witness for fee output
    tx.wit.vtxoutwit.append(CMutableTxOutWitness())

    # And blind the combined transaction
    ok, blind_result = tx.blind(
        input_blinding_factors=blinders,
        input_asset_blinding_factors=assetblinders,
        input_assets=assets,
        input_amounts=amounts,
        output_pubkeys=output_pubkeys,
        auxiliary_generators=assetcommitments)

    # The blinding must succeed!
    if not ok:
        die('blind failed: {}'.format(blind_result))

    # And must blind exactly three outputs (two to Bob, one fee asset change)
    if blind_result.num_successfully_blinded != 3:
        die('blinded {} outputs, expected to be 3'
            .format(blind_result.num_successfully_blinded))

    say('Successfully blinded the combined transaction, will now sign')

    # Sign two new asset inputs, and fee asset input
    for n, utxo in enumerate(utxos_to_add):
        # We specify input_index as 1+n because we skip first (Bob's) input
        sign_input(tx, 1+n, btc_to_satoshi(utxo['amount']), utxo['key'])

    say('Signed my inputs, sending partially-signed transaction to Bob')

    send('partially_signed_tx', tx.serialize())

    # Get the swap transaction txid from Bob
    txid = recv('wait-txid-confirm')

    # Make sure it is confirmed
    rpc.generate(1)
    wait_confirm(say, txid, die, rpc)

    # Check that everything went smoothly
    balance = btc_to_satoshi(rpc.getbalance("*", 1, False, bob_offer.asset))
    if balance != bob_offer.amount:
        die('something went wrong, bob\'s asset balance after swap should be '
            '{} satoshi, but it is {} satoshi'
            .format(balance, bob_offer.amount))

    print_asset_balances(say, my_offers + [bob_offer], rpc)

    # Wait for alice to politely end the conversation
    send('thanks-goodbye')

    say('Asset atomic swap completed successfully')


def bob(say, recv, send, die, rpc):
    """A function that implements the logic
    of the second participant of an asset atomic swap"""

    # Issue an asset that we are going to swap
    asset_str, asset_utxo = issue_asset(say, 1.0, rpc)
    asset_amount_satoshi = btc_to_satoshi(asset_utxo['amount'])

    say('Setting up communication with Alice')

    # Wait for Alice to start communication
    recv('ready')
    # To avoid mempool synchronization problems in two-node regtest setup,
    # in our example Alice is the one in charge of generating test blocks.
    # Send txid of asset issuance to alice so she can ensure it is confirmed.
    send('wait-txid-confirm', asset_utxo['txid'])

    say('Waiting for Alice to send us an offer array')

    alice_offers = recv('offer')

    # We unconditionally accept Alice's offer - her assets are
    # equally worthless as our asset :-)

    say("Alice's offers are {}, sending my offer".format(alice_offers))

    my_offer = AtomicSwapOffer(amount=asset_amount_satoshi, asset=asset_str)

    send('offer', my_offer)

    say('Waiting for Alice\'s address and assetcommitments')

    alice_addr_str, alice_assetcommitments = recv('addr_and_assetcommitments')

    print_asset_balances(say, alice_offers + [my_offer], rpc)

    # Convert Alice's address to address object.
    # If Alice passes invalid address, we die with we die with exception.
    alice_addr = CBitcoinAddress(alice_addr_str)

    say('Alice\'s address: {}'.format(alice_addr))
    say('Alice\'s assetcommitments: {}'.format(alice_assetcommitments))

    # Create asset commitments array. First goes our own asset commitment,
    # because our UTXO will be first.
    assetcommitments = [x(asset_utxo['assetcommitment'])]
    for ac in alice_assetcommitments:
        # If Alice sends non-hex data, we will die while converting.
        assetcommitments.append(x(ac))

    # Let's create our part of the transaction. We need to create
    # mutable transaction, because blind() method only works for mutable.
    partial_tx = CMutableTransaction(
        vin=[CTxIn(prevout=COutPoint(hash=lx(asset_utxo['txid']),
                                     n=asset_utxo['vout']))],
        vout=[CTxOut(nValue=CConfidentialValue(asset_amount_satoshi),
                     nAsset=CConfidentialAsset(CAsset(lx(asset_str))),
                     scriptPubKey=alice_addr.to_scriptPubKey())])

    # Blind our part of transaction, specifying assetcommitments
    # (Incliding those received from Alice) as auxiliary_generators.

    # Note that we could get the blinding factors if we retrieve
    # the transaction that we spend from, deserialize it, and unblind
    # the output that we are going to spend.
    # We could do everything here (besides issuing the asset and sending
    # the transactions) without using Elements RPC, if we get our data
    # from files or database, etc. But to simplify our demonstration,
    # we will use the values we got from RPC.

    # See 'spend-to-confidential-address.py' example for the code
    # that does the unblinding itself, and uses the unblinded values
    # to create a spending transaction.

    ok, blind_result = partial_tx.blind(
        input_blinding_factors=[Uint256(lx(asset_utxo['blinder']))],
        input_asset_blinding_factors=[Uint256(lx(asset_utxo['assetblinder']))],
        input_assets=[CAsset(lx(asset_utxo['asset']))],
        input_amounts=[asset_amount_satoshi],
        output_pubkeys=[alice_addr.blinding_pubkey],
        auxiliary_generators=assetcommitments)

    # The blinding must succeed!
    if not ok:
        die('blind failed: {}'.format(blind_result))

    # And must blind exactly one output
    if blind_result.num_successfully_blinded != 1:
        die('blinded {} outputs, expected to be 1'
            .format(blind_result.num_successfully_blinded))

    say('Successfully blinded partial transaction, sending it to Alice')

    send('partial_blinded_tx', partial_tx.serialize())

    say("Generating addresses to receive Alice's assets")
    # Generate as many destination addresses as there are assets
    # in Alice's offer. Record blinding keys for the addresses.
    our_addrs = []
    blinding_keys = []
    for _ in alice_offers:
        addr_str, blinding_key = get_dst_addr(say, rpc)
        our_addrs.append(addr_str)
        blinding_keys.append(blinding_key)

    say("Sending my addresses and assetcommitment to Alice")
    send('addr_list_and_assetcommitment',
         (our_addrs, asset_utxo['assetcommitment']))

    semi_signed_tx_bytes = recv('partially_signed_tx')

    say('Got partially signed tx of size {} bytes from Alice'
        .format(len(semi_signed_tx_bytes)))

    semi_signed_tx = CTransaction.deserialize(semi_signed_tx_bytes)

    # Transaction should have 3 extra outputs - one output to Alice,
    # fee output, and fee asset change output
    if len(semi_signed_tx.vout) != len(alice_offers) + 3:
        die('unexpected number of outputs in tx from Alice: '
            'expected {}, got {}'.format(len(alice_offers)+3,
                                         len(semi_signed_tx.vout)))

    if not semi_signed_tx.vout[-1].is_fee():
        die('Last output in tx from Alice '
            'is expected to be fee output, but it is not')

    # Unblind outputs that should be directed to us and check
    # that they match the offer. We use n+1 as output index
    # because we skip our own output, which is at index 0.
    for n, offer in enumerate(alice_offers):
        ok, result = semi_signed_tx.vout[n+1].unblind(
            blinding_keys[n], semi_signed_tx.wit.vtxoutwit[n+1].rangeproof)

        if not ok:
            die('cannot unblind output {} that should have been '
                'directed to us: {}'.format(n+1, result))

        if result.asset.to_hex() != offer.asset:
            die("asset at position {} (vout {}) in partial transaction "
                "from Alice {} is not the same as asset in Alice's "
                "initial offer ({})"
                .format(n, n+1, result.asset.to_hex(), offer.asset))

        if result.amount != offer.amount:
            die("amount at position {} (vout {}) in partial transaction "
                "from Alice {} is not the same as amount in Alice's "
                "initial offer ({})"
                .format(n, n+1, result.amount, offer.amount))

    say("Assets and amounts in partially signed transaction "
        "match Alice's offer")

    # Signing will change the tx, so i
    tx = semi_signed_tx.to_mutable()

    # Our input is at index 0
    sign_input(tx, 0, btc_to_satoshi(asset_utxo['amount']), asset_utxo['key'])

    say('Signed the transaction from my side, sending')

    txid = rpc.sendrawtransaction(b2x(tx.serialize()))

    say('Sent with txid {}'.format(txid))

    # Ask alice to generate test block to confirm the swap transaction
    send('wait-txid-confirm', txid)

    # Wait for alice to politely end the conversation
    recv('thanks-goodbye')
    print_asset_balances(say, alice_offers + [my_offer], rpc)

    for i, offer in enumerate(alice_offers):
        balance = btc_to_satoshi(rpc.getbalance("*", 1, False, offer.asset))
        if balance != offer.amount:
            die('something went wrong, asset{} balance after swap should be '
                '{} satoshi, but it is {} satoshi'
                .format(i, balance, offer.amount))

    say('Asset atomic swap completed successfully')

if __name__ == '__main__':
    main()
