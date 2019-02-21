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
import signal
import traceback

from multiprocessing import Process, Pipe, Lock

from bitcointx import SelectParams
from bitcointx.rpc import RawProxy
from bitcointx.core import (
    COIN, Uint256, x, lx,
    CTransaction, CTxIn, CTxOut, COutPoint,
    CConfidentialValue, CConfidentialAsset
)
from bitcointx.wallet import CBitcoinAddress
from bitcointx.sidechain.elements import CAsset

# A global lock variable to coordinate console output between
# child processes. We could pass the lock as arguments to the
# process functions, but it is simpler to make it global var
# and not clutter the participant process funcs with unneeded details
console_lock = None

# Node functions need to know fee asset
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
            .format(elements_config_path1))
        sys.exit(-1)

    try:
        fee_asset = CAsset(lx(sys.argv[3]))
    except Exception as e:
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
    p1 = Process(target=run_child, name='alice',
                 args=(alice, 'Alice', pipe1, elements_config_path1))

    # Create process to run 'bob' participant function
    # and pass it one end of a pipe, and path to config file for node2
    p2 = Process(target=run_child, name='bob',
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


def run_child(func, name, pipe, config_path):
    """Prepares environment for participants, run their functions,
    and handles the errors they did not bother to hanlde"""

    def say(msg): participant_says(name, msg)

    def recv(expected_type):
        timeout = 60
        if not pipe.poll(timeout):
            raise Exception('No messages received in {} seconds'
                            .format(timeout))
        msg = pipe.recv()
        if msg[0] != expected_type:
            raise Exception("unexpected message type '{}', expected '{}'"
                            .format(msg[0], expected_type))

        return msg[1:]

    def send(*args): pipe.send(args)

    # Ignore keyboard interrupt, parent process handles it.
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    try:
        rpc = connect_rpc(say, config_path)
        func(say, recv, send, rpc)
    except Exception as e:
        say('FAIL with {}: {}'.format(type(e).__name__, e))
        say("Traceback:")
        print("="*80)
        traceback.print_tb(sys.exc_info()[-1])
        print("="*80)
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


def issue_asset(say, asset_amount, rpc):
    """Issue asset and return CAsset instance and utxo to spend"""

    say('Issuing my own new asset, amount: {}'.format(asset_amount))

    # No reissuance, so we specify tokenamount as 0
    issue = rpc.issueasset(asset_amount, 0)
    rpc.generate(1)

    asset_str = issue['asset']
    say('The asset is {}'.format(asset_str))

    say('Getting unspent utxo for asset {}'.format(asset_str))
    # There should be only one utxo for newly-issued asset, we can use
    # destructuring assignment to get the first element of resulting list
    (asset_utxo, ) = rpc.listunspent(1, 9999999, [], False, asset_str)

    say('Unspent utxo for asset {} is {}:{}'
        .format(asset_str, asset_utxo['txid'], asset_utxo['vout']))

    return asset_str, asset_utxo


def alice(say, recv, send, rpc):
    """A function that implements the logic
    of the first participant of an asset atomic swap"""

    # Find utxo to use for fee. In our simple example, only Alice pays the fee.
    # To be on a safe side, include only transactions
    # that are confirmed (1 as 'minconf' argument of listunspent)
    # and safe to spend (False as 'include_unsafe' # argument of listunspent)
    say('Getting list of unspent utxo for fee asset')
    utxo_list = rpc.listunspent(1, 9999999, [], False, fee_asset.to_hex())
    utxo_list.sort(key=lambda u: u['amount'])
    for utxo in utxo_list:
        if btc_to_satoshi(utxo['amount']) >= FIXED_FEE_SATOSHI:
            fee_utxo = utxo
            break
    else:
        raise Exception('Cannot find utxo for fee that is >= {} satoshi'
                        .format(FIXED_FEE_SATOSHI))

    say('Will use utxo {}:{} (amount: {}) for fee'
        .format(fee_utxo['txid'], fee_utxo['vout'], fee_utxo['amount']))

    # Issue two asset that we are going to swap to Bob's 1 asset
    asset1_str, asset1_utxo = issue_asset(say, 1.0, rpc)
    asset2_str, asset2_utxo = issue_asset(say, 1.0, rpc)

    # Make sure Bob is alive and ready to communicate
    say('Sending ping to Bob')
    send('ping')
    recv('pong')
    say('Bob responded !')

    say('Sending my address and assetcommitment for my UTXO to Bob')

    # Generate an address for Bob to send his asset to.
    # Note that we are using RawProxy for RPC, so we get address as string.
    addr_str = rpc.getnewaddress()

    # Send Bob our address, and the assetcommitments of our UTXOs
    # (but not any other UTXO info), so he can construct and blind
    # a partial transaction that will spend his own UTXO,
    # to send his asset to our address.
    send('addr_and_assetcommitments',
         addr_str, (asset1_utxo['assetcommitment'],
                    asset2_utxo['assetcommitment']))


def bob(say, recv, send, rpc):
    """A function that implements the logic
    of the second participant of an asset atomic swap"""

    # Issue an asset that we are going to swap
    asset_str, asset_utxo = issue_asset(say, 1.0, rpc)

    # Wait for Alice to start communication, and respond
    say('Waiting for Alice to send us ping')
    recv('ping')
    send('pong')
    say('Alice is ready to talk !')

    say('Waiting for Alice\'s address and assetcommitment')

    alice_addr_str, alice_assetcommitments = recv('addr_and_assetcommitments')

    # If Alice passes invalid address, we die with we die with exception.
    alice_addr = CBitcoinAddress(alice_addr_str)

    # Convert Alice's assetcommitments to hex (will also die on any errors)
    alice_assetcommitments = [x(ac) for ac in alice_assetcommitments]

    say('Alice\'s address: {}'.format(alice_addr))
    say('Alice\'s assetcommitments: {}'.format(alice_assetcommitments))

    # Let's create our part of the transaction
    tx = CTransaction(
        vin=[CTxIn(prevout=COutPoint(hash=lx(asset_utxo['txid']),
                                     n=asset_utxo['vout']))],
        vout=[CTxOut(nValue=CConfidentialValue(COIN),  # 1.0 of our asset
                     nAsset=CConfidentialAsset(x(asset_str)),
                     scriptPubKey=alice_addr.to_scriptPubKey())])

    # It is easier to construct immutable transaction, because
    tx = tx.to_mutable()  # We

    # Blind our part of transaction, specifying Alice's assetcommitments
    # as auxiliary_generators.

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

    blind_result = tx.blind(
        input_blinding_factors=[Uint256(lx(asset_utxo['blinder']))],
        input_asset_blinding_factors=Uint256(lx(asset_utxo['assetblinder'])),
        input_assets=[lx(asset_utxo['asset'])],
        input_amounts=[COIN],
        output_pubkeys=[alice_addr.blinding_pubkey],
        auxiliary_generators=alice_assetcommitments)


if __name__ == '__main__':
    main()
