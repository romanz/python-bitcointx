# Elements sidechain examples

This directory contains three example programs that demonstrate usage of python-bitcointx to work with Elements sidechain confidential transactions: building, serializing/deserializing, blinding and unblinding.

`unblind.py` takes hex-encoded transaction and blinding key, and successively tries to unblind the outputs of this transaction with the given blinding key.

`spend-to-confidential-address.py` takes hex-encoded transaction, spending key, unblinding key, and a destination address, and prints new hex-encoded transaction that spends the output of the input transaction that it can spend with the spending key. If this output is blinded, it then uses provided unblinding key to unblind the output. If the destination address provided is a confidential address, the code will blind the resulting transaction before signing it with spending key.

`asset-atomic-swap.py` works with two regtest Elements Core daemons, set up according to https://elementsproject.org/elements-code-tutorial/blockchain and uses their RPC API to issue assets and do other actions needed to demonstrate asset atomic swap. It features two participants: Alice and Bob, who issue new assets, and then atomically swap them by exchanging their swap offers, blinded (partial) transactions, and other data, building a final transaction out of the exchanged parts. The transaction is cooperatively signed by participants and then broadcasted within regtest network.

## Conventions

We assume you have python-bitcointx sources unpacked in your home directory, under $HOME/python-bitcointx.

`<cwd path>$` represends command prompt. Shell is assumed to be bash-compatible.

Make command is assumed to be GNU make.

Lines starting with `>` represent output from the commands.

# Setup

The command examples here assume the shell environment is set up as described in https://elementsproject.org/elements-code-tutorial/confidential-transactions and will use the shell aliases defined there.

Command examples also assume unix-like working environment.

To be able to work with confidential transaction beyond just serializing and deserializing them, the special experimental version of secp256k1 library, secp256k1-zkp is required. You can get it from https://github.com/ElementsProject/secp256k1-zkp. This experimental version of secp256k1 is currently not available as a ready-made package, so you will have to build the library yourself.

We assume you have secp256k1-zkp sources unpacked in your home directory, under $HOME/secp256k1-zkp path.

The examples were tested with secp256k1-zkp as of git commit `1bbad3a04be42edb1dda16c9eab24345b1f63c5d` with an additional patch applied that enables the programs that use secp256k1-zkp as a dynamic library (without the requirement to use C compiler) to get the size of a certain struct, that is required to perform blinding operations, at runtime. At the time of writing, the proposed patch to include the ability to get the size of this structure is not yet merged to secp256k1-zkp source. Because of this, to run the examples that do transaction blinding (`spend-to-confidential-address.py` and `asset-atomic-swap.py`) you will need to apply the patch to secp256k1-zkp before building it. The pull request at https://github.com/ElementsProject/secp256k1-zkp/pull/37 contains the information about the proposed patch, and the patch itself is included in the directory with the examples, the file name is `secp256k1-zkp-export-surjectionproof-size.diff`.

The examples will need to find python-bitcointx installed in `PYTHONPATH`. Follow your preferred method for python module installation.

One of the possible methods to install the module for current user (not system-wide):

    ~/$ cd python-bitcointx
    ~python-bitcoinx/$ pip3 install . --user

## Building secp256k1-zkp

Enter secp256k-zkp source directory

    ~/$ cd secp256k-zkp

Apply the patch patch mentioned above (in Setup section).

    ~/secp256k1-zkp$ patch -p1 <$HOME/python-bitcointx/examples/sidechain/elements/secp256k1-zkp-export-surjectionproof-size.diff 
    > patching file include/secp256k1_surjectionproof.h
    > patching file src/secp256k1.c

Run configuration script for the library, specifying the experimental modules that we need to work with confidential transactions

    ~/secp256k1-zkp$ ./configure --enable-experimental \
                                 --enable-module-generator \
                                 --enable-module-rangeproof \
                                 --enable-module-surjectionproof \
                                 --enable-module-ecdh \
                                 --enable-module-recovery

Build the library

    ~/secp256k1-zkp$ make

Back to our home directory

    ~/secp256k1-zkp$ cd
    ~/$

The actual dynamic library file will be called `libsecp256k1.so`, and may conflict with system-installed secp256k1 library. To avoid this, we will not install the library into the system. To work with our examples, it is enough to set `LD_LIBRARY_PATH` to the path where the linker can find this version of the library. We can do so with the command:

    ~/$ export LD_LIBRARY_PATH=$HOME/secp256k1-zkp/.libs/ 

Now, the programs that are executed in the current shell session will use our newly built secp256k1-zkp library.

# Unblinding example

To run `unblind.py` example, we need to prepare the data that it will be unblinding.
Assuming the Elements tutorial environment for standalone blockchain are in place,
we will get an address from node2, along with its blinding key, send some funds from node1
to this address, and will run `unblind.py` to unblind the output destined to the node2 address.

Get new address from node2

    ~/$ e2-cli getnewaddress
    > CTEomyVvMRYbSxCSvC63AJW2FWCgMPQuANwdFA11qWhW1aN8K4UHh8a1Z4MmzWwBRed381FrF6PyKfUT

Get the corresponding unconfidential address so we can check its presense in the output of getrawtransaction

    ~/$ e2-cli validateaddress CTEomyVvMRYbSxCSvC63AJW2FWCgMPQuANwdFA11qWhW1aN8K4UHh8a1Z4MmzWwBRed381FrF6PyKfUT | jq '.unconfidential'
    > "2dmGwHSBrDSpq14o6GFcn82Sshefk89tQz2"

Dump blinding key for the address into `blkey` file

    ~/$ e2-cli dumpblindingkey CTEomyVvMRYbSxCSvC63AJW2FWCgMPQuANwdFA11qWhW1aN8K4UHh8a1Z4MmzWwBRed381FrF6PyKfUT > blkey

Send the sum of `1.2345` of the default asset from node1 to the address we got from node2 (notice that we are using `e1-cli` here

    ~/$ e1-cli sendtoaddress CTEomyVvMRYbSxCSvC63AJW2FWCgMPQuANwdFA11qWhW1aN8K4UHh8a1Z4MmzWwBRed381FrF6PyKfUT 1.2345
    > 4ac7d627122544c20060cc69567f94b3d7410b5aa1c9501df689900df901c9be

Check that the output to the address is blinded. The address `2dmGwHSBrDSpq14o6GFcn82Sshefk89tQz2` is in vout at index 1 (indexes start from 0)

    ~/$ e1-cli getrawtransaction 4ac7d627122544c20060cc69567f94b3d7410b5aa1c9501df689900df901c9be 1| jq '.vout'

    > [
    >     {
    >         "value-minimum": 1e-08,
    >         "value-maximum": 1407374.88355328,
    >         "ct-exponent": 0,
    >         "ct-bits": 47,
    >         "amountcommitment": "08d283088cd2475eb3d9464499bebfd184de0f20af8a1967298e2c25ba09bc6554",
    >         "assetcommitment": "0b307e3badd1a84625d547ec6491a90b1bd540f11e634eebca259d743deb566e32",
    >         "n": 0,
    >         "scriptPubKey": {
    >             "asm": "OP_DUP OP_HASH160 dfc0d8fd2771d7995f5e6b45d9af58d407b1aed2 OP_EQUALVERIFY OP_CHECKSIG",
    >             "hex": "76a914dfc0d8fd2771d7995f5e6b45d9af58d407b1aed288ac",
    >             "reqSigs": 1,
    >             "type": "pubkeyhash",
    >             "addresses": [
    >                 "2dupr6aq8bukk78bYvU464utmGmB34rLCP8"
    >             ]
    >         }
    >     },
    >     {
    >         "value-minimum": 1e-08,
    >         "value-maximum": 42.94967296,
    >         "ct-exponent": 0,
    >         "ct-bits": 32,
    >         "amountcommitment": "08481b27c8a5de540653a7c0e837bdf9d895e86f0dfb80306301bcbb15769870e0",
    >         "assetcommitment": "0b7b146b207eedd05460ddde9d62580349cb0036668b8e785b6c16651b29c098b5",
    >         "n": 1,
    >         "scriptPubKey": {
    >             "asm": "OP_DUP OP_HASH160 81f6dc4b799e66824fce41c3401b61d1b3e37983 OP_EQUALVERIFY OP_CHECKSIG",
    >             "hex": "76a91481f6dc4b799e66824fce41c3401b61d1b3e3798388ac",
    >             "reqSigs": 1,
    >             "type": "pubkeyhash",
    >             "addresses": [
    >                 "2dmGwHSBrDSpq14o6GFcn82Sshefk89tQz2"
    >             ]
    >         }
    >     },
    >     {
    >         "value": 0.0003948,
    >         "asset": "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23",
    >         "n": 2,
    >         "scriptPubKey": {
    >             "asm": "",
    >             "hex": "",
    >             "type": "fee"
    >         }
    >     }
    > ]

Get the hex dump of the transaction into `rawtx` file

    ~/$ e1-cli getrawtransaction 4ac7d627122544c20060cc69567f94b3d7410b5aa1c9501df689900df901c9be > rawtx

Run `unblind.py` example, specifying the wile with raw hex dump of the transaction, and file witb blinding key.
Notice that the code successfully unblinded vout at index 1, and shows us correct address and amount.

    ~/$ python-bitcointx/examples/sidechain/elements/unblind.py rawtx blkey 

    > vout 0: cannot unblind
    >   destination address: 2dupr6aq8bukk78bYvU464utmGmB34rLCP8
    >   ct-exponent 0
    >   ct-bits 47
    >   value-minimum 1e-08
    >   value-maximum 1407374.88355328
    >
    > vout 1: unblinded
    >   destination address:
    >     confidential:	 CTEomyVvMRYbSxCSvC63AJW2FWCgMPQuANwdFA11qWhW1aN8K4UHh8a1Z4MmzWwBRed381FrF6PyKfUT
    >     unconfidential:	 2dmGwHSBrDSpq14o6GFcn82Sshefk89tQz2
    >   amount:		 1.2345
    >   blinding_factor:	 lx('af412ba6eecb0589b622ef4f3a8c4ca63fa2bb86a4610b826bc35f3144033d95')
    >   asset:		 CAsset('b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23')
    >   asset_blinding_factor: lx('02bab4ba91ba8e0a083c9e15beab22d71f841fdfcc6aabee210fb7efe2a654b2')
    >
    > vout 2: fee
    >   amount:		 0.0003948
    >   asset:		 CAsset('b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23')

# Spending to confidential address example

To run `spend-to-confidential-address.py` we will need the same environment as for the previous example, and we assume we have the same `rawtx` and `blkey` files that we generated in the previous example.

In addition to `rawtx` and `blkey` files we also need the key to spend the UTXO held at `2dmGwHSBrDSpq14o6GFcn82Sshefk89tQz2` address. We will dump it into `spendkey` file.

    ~/$ e2-cli dumpprivkey 2dmGwHSBrDSpq14o6GFcn82Sshefk89tQz2 > spendkey

We also need a destination address that our newly created transaction will send the funds to.

    ~/$ e1-cli getnewaddress
    > CTEoxxzhfXby3kwHbpwvBLWv8ZMoSyssp1msniDUAjayMHLHaJEyKNrm3GM5cCETnW8WMfaFvFypj6oh

Run `spend-to-confidential-address.py`, specifying the raw hex dump of tx from previous example, a key to spend the UTXO, the blinding key to unblind the UTXO, and the destination address. Hexadecimal representation of a resulting transaction is placed into `blinded_tx` file. Note that the amount in satoshi matches the amount we sent to 2dmGwHSBrDSpq14o6GFcn82Sshefk89tQz2 earlier.

    ~/$ python-bitcointx/examples/sidechain/elements/spend-to-confidential-address.py \
            rawtx spendkey blkey \
            CTEoxxzhfXby3kwHbpwvBLWv8ZMoSyssp1msniDUAjayMHLHaJEyKNrm3GM5cCETnW8WMfaFvFypj6oh \
            > blinded_tx

    > Searching for ouptut with address 2dmGwHSBrDSpq14o6GFcn82Sshefk89tQz2
    > Found at index 1
    > amount: 123450000
    > asset:  b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23
    >
    > Successfully blinded 1 outputs
    > Successfully signed

Let's check the current balance at node2, before we send our newly build transaction. As expected, the balance for newasset is 1.2345, that we sent in prevoius example

    ~/$ e2-cli getbalance
    > {
    >     "newasset": 1.23450000,
    >     "a6be6b365498cd451be75ba0f68c258ee01e08f3cb30d5f8469f6628db58dc61": 2.00000000
    > }

Let's send the transaction

    ~/$ e1-cli sendrawtransaction `cat blinded_tx`
    > 8d4ccfb1099d2e904f681bf9ff08806358684db1d9a23e3e3c2990013d3df810

And check that the balance has changed (we send the whole amount to the new address, which belongs to node1)

    ~/$ e2-cli getbalance
    > {
    >     "a6be6b365498cd451be75ba0f68c258ee01e08f3cb30d5f8469f6628db58dc61": 2.00000000
    > }

The balance at node1 will be changed only after we generate a block. Let's see the current balance:

    ~/$ e1-cli getbalance
    > {
    >     "newasset": 999998.76510520,
    >     "a6be6b365498cd451be75ba0f68c258ee01e08f3cb30d5f8469f6628db58dc61": 2.00000000
    > }

If we followed the instructions at https://elementsproject.org/elements-code-tutorial/blockchain, initial balance for newasset was 1000000. `1000000 - 999998.76510520 = 1.23489480`, a bit less than 1.2345, because the transaction fee was also paid from this sum.

Let's generate a new regtest block, so our new transaction will be confirmed

    ~/$ e1-cli generate 1
    > [
    >     "21cef0f53b10753a4f2a0078e3092907a5cb0c5a5550cee73563410c06259c39"
    > ]

And then check the balance at node1

    ~/$ e1-cli getbalance
    > {
    >     "newasset": 999999.99921040,
    >     "a6be6b365498cd451be75ba0f68c258ee01e08f3cb30d5f8469f6628db58dc61": 2.00000000
    > }

We can see that the balance is increased by `999999.99921040 - 999998.76510520 = 1.23410520`, this is less than 1.2345, because `spend-to-confidential-address.py` uses the same amount for fee that was used in source transaction. As we can see from the output of getrawtransaction above, the fee was 0.00039480, and  1.23410520 plus 0.00039480 is 1.2345.
    
# Asset atomic swap example

In contrast to cross-chain atomic swap which is performed by using [hash time locked contracts](https://en.bitcoin.it/wiki/Hash_Time_Locked_Contracts), the support for assets in Elements sidechain allows to perform atomic swaps just by cooperatively signing a transaction that have UTXOs holding different assets from different participants as inputs, and have an ouptuts that distribute the assets to participants according to their agreement. Because participants sign their inputs using `SIGHASH_ALL` type of transaction signature hash, for which all inputs and outputs of the transaction are commited to the signature hash, no participant can alter the transaction without invalidating signatures of the other participants as a result. The atomicity of the swap is in the fact that the assets will be transferred if and only if only when the cooperatively prepared and signed transaction is confirmed.

In the `asset-atomic-swap.py` example, two participants of an asset atomic swap are represented by two processes that communicate via `mulitprocessing.Pipe` mechanism provided by standard `multiprocessing` python module. Participant processes connect to Elements RPC API of Elements daemons that are started according to the procedure described at https://elementsproject.org/elements-code-tutorial/blockchain.

The environment is assumed to be the same as with the previous examples.

The example will need to know the asset that is used to pay the fee in our regtest network. If we look at getrawtransaction output in `unblind.py` example, we will see that the asset for fee is `b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23`.

To run an example, we will specify two directories of Elements daemons, that reside in our home directory, and the asset for fee. The output of the example will be descriptive enough to have an idea of what is happening. You can make the messages from participants to be in different colors by uncommenting the definitions for ANSI colors in the example source.

    ~/$ python-bitcointx/examples/sidechain/elements/asset-atomic-swap.py \
            ~/elementsdir1 ~/elementsdir2/ \
            b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23

    > Alice: Connecting to Elements daemon RPC interface, using config in /home/tmp/rgb/elementsdir1/elements.conf
    > Alice: Issuing my own new asset, amount: 1.0
    > Bob: Connecting to Elements daemon RPC interface, using config in /home/tmp/rgb/elementsdir2/elements.conf
    > Bob: Issuing my own new asset, amount: 1.0
    > Alice: The asset is 466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49
    > Alice: Getting unspent utxo for asset 466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49
    > Alice: Unspent utxo for asset 466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49 is d7c5334349c27df5a3afee3cabd20ff52f41ce86da0fe0a0f9fc2ddda6d124aa:0
    > Alice: Retrieving private key to spend UTXO (source address 2drAQaAFZyf7qduXECgk79JsKs97G8zTypT)
    > Alice: Issuing my own new asset, amount: 1.0
    > Bob: The asset is 4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62
    > Bob: Getting unspent utxo for asset 4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62
    > Bob: Unspent utxo for asset 4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62 is 84aa5da8c58b390836d776e8de5471c03bcdd64686a020feebf6f235841221da:1
    > Bob: Retrieving private key to spend UTXO (source address 2dm7PC3tWtDJ17GYi3dvSJWMnnYj58Yrqz4)
    > Bob: Setting up communication with Alice
    > Alice: The asset is f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55
    > Alice: Getting unspent utxo for asset f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55
    > Alice: Unspent utxo for asset f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55 is 3608a9d88f9638c594ce954df2310be1635aa026f99d35efcb40a5d1a2be5111:0
    > Alice: Retrieving private key to spend UTXO (source address 2dfdS4BBCvP62VKJ8N7Pbwt2JqHvZ6bYXxe)
    > Alice: Searching for utxo for fee asset
    > Alice: Getting change address for fee asset
    > Alice: Generating new address and retrieving blinding key for it
    > Alice: Will use utxo 8ccae4da74e3f571ae0c8125befff419bd29a624bd1958547e0e98250a6258b8:3 (amount: 0.00091280) for fee, change will go to CTEuajcMJYaYSmtsfpgp75p7K4EvajJKHtSnMXgcMTmkTvoXJtpsAS6SMWuJH5EExo4AQEmxMwYRz1Gy
    > Alice: Setting up communication with Bob
    > Bob: Waiting for Alice to send us an offer array
    > Alice: Waiting for txid d7c5334349c27df5a3afee3cabd20ff52f41ce86da0fe0a0f9fc2ddda6d124aa to confim
    > Alice: Waiting for txid 3608a9d88f9638c594ce954df2310be1635aa026f99d35efcb40a5d1a2be5111 to confim
    > Alice: Waiting for txid 84aa5da8c58b390836d776e8de5471c03bcdd64686a020feebf6f235841221da to confim
    > Alice: Sending offer to Bob
    > Bob: Alice's offers are [AtomicSwapOffer(asset='466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49', amount=100000000), AtomicSwapOffer(asset='f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55', amount=100000000)], sending my offer
    > Bob: Waiting for Alice's address and assetcommitments
    > Alice: Current asset balance:
    > Alice: 466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49: 1.00000000
    > Alice: f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55: 1.00000000
    > Alice: 4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62: 0E-8
    > Alice: Bob responded with his offer: AtomicSwapOffer(asset='4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62', amount=100000000)
    > Alice: Generating new address and retrieving blinding key for it
    > Alice: Sending my address and assetcommitments for my UTXOs to Bob
    > Bob: Current asset balance:
    > Bob: 466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49: 0E-8
    > Bob: f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55: 0E-8
    > Bob: 4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62: 1.00000000
    > Bob: Alice's address: CTEsSBZrt7NGu9goHtNxSH4vtQ1MnmkHcEtnBCeLLDsmmP53NT7Yg77SvYmjYnadcpJAAvYC8Ph1ukJd
    > Bob: Alice's assetcommitments: ['0bc6bceb4e1a35e0625a750b7ad1c44d3e19f0d2fae9017992dc8935ea39a24403', '0ae23d6b747636f029cb2dcd185d7fca1e6de1b98bb19084de3e7c87d3d909d9b6', '0b3c9380a617bbc2e8e0544417077f88ee2690b6a4e37cf904adb647dbad35de78']
    > Bob: Successfully blinded partial transaction, sending it to Alice
    > Bob: Generating addresses to receive Alice's assets
    > Bob: Generating new address and retrieving blinding key for it
    > Alice: Got partial blinded tx of size 2888 bytes from Bob
    > Bob: Generating new address and retrieving blinding key for it
    > Bob: Sending my addresses and assetcommitment to Alice
    > Alice: Asset and amount in partial transaction matches Bob's offer
    > Alice: Bob's addresses to receive my assets: ['CTEn4RBnfhCqCXo1mNJ3Kcbtq3oLRq2pkpwE5ap5Jz8uEbrcRGFm2Krsx34fZaaFncDLnCUu94JovY66', 'CTEmde7LxpFJwEw1815pxkho2YpMRT2DidRDuPnE92Huz6MCJLQMZNEZhA9CGWUu93dfCviSqaYBndXj']
    > Alice: Successfully blinded the combined transaction, will now sign
    > Alice: Signed my inputs, sending partially-signed transaction to Bob
    > Bob: Got partially signed tx of size 11885 bytes from Alice
    > Bob: Assets and amounts in partially signed transaction match Alice's offer
    > Bob: Signed the transaction from my side, sending
    > Bob: Sent with txid 2dec73424522e82e4e8200129821e523c35ceb20f84726574ce4103ba9a2e758
    > Alice: Waiting for txid 2dec73424522e82e4e8200129821e523c35ceb20f84726574ce4103ba9a2e758 to confim
    > Alice: Current asset balance:
    > Alice: 466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49: 0E-8
    > Alice: f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55: 0E-8
    > Alice: 4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62: 1.00000000
    > Alice: Asset atomic swap completed successfully
    > Bob: Current asset balance:
    > Bob: 466796178675b068c5be92f3f3d9464f8c0f6d295509611cc386cdb0f02afe49: 1.00000000
    > Bob: f3b0779c7312f0bccffd82e53ddf31aa3a24fefdd252ff8daffbbf4fc0b42a55: 1.00000000
    > Bob: 4a097e25030d764781b30c8176dda620694b8983fd2494abc57471a8c2d9cd62: 0E-8
    > Bob: Asset atomic swap completed successfully

That's all.

Please study the source of the examples and explore the state of the regtest network after they have ran.
