This directory contains two example programs that demonstrate usage of Elements sidechain confidential transaction blinding and unblinding functionality of python-bitcointx.

unblind.py takes hex-encoded transaction and blinding key, and successively tries to unblind the outputs of this transaction with the given blinding key.

spend-to-confidential-address.py takes hex-encoded transaction, spending key, unblinding key, and a destination address, and prints new hex-encoded transaction tha spends the output of the input transaction corresponding to the spending key. If this output is blinded, it then uses provided unblinding key to unblind this output. If the destination address provided is a confidential address, the code will blind the resulting transaction before signing it with spending key.


    secp256k1-zkp:

    $ ./configure --enable-experimental --enable-module-generator --enable-module-rangeproof --enable-module-surjectionproof --enable-module-ecdh --enable-module-recovery

    $ export LD_LIBRARY_PATH=$HOME/secp256k1-zkp/.libs/ 

    $ e2-cli getnewaddress
    CTEomyVvMRYbSxCSvC63AJW2FWCgMPQuANwdFA11qWhW1aN8K4UHh8a1Z4MmzWwBRed381FrF6PyKfUT

    $ e2-cli validateaddress CTEomyVvMRYbSxCSvC63AJW2FWCgMPQuANwdFA11qWhW1aN8K4UHh8a1Z4MmzWwBRed381FrF6PyKfUT
    {
        "isvalid": true,
        "address": "CTEomyVvMRYbSxCSvC63AJW2FWCgMPQuANwdFA11qWhW1aN8K4UHh8a1Z4MmzWwBRed381FrF6PyKfUT",
        "scriptPubKey": "76a91481f6dc4b799e66824fce41c3401b61d1b3e3798388ac",
        "confidential_key": "029715f0c93a987985b1ae0c199a38125a38e70b239723c283572cd78afb8d3487",
        "unconfidential": "2dmGwHSBrDSpq14o6GFcn82Sshefk89tQz2",
        "ismine": true,
        "iswatchonly": false,
        "isscript": false,
        "pubkey": "03935921547d02fad1a8a66e556604705c88816ec16db19ba3fe72cad8a5a2da4a",
        "iscompressed": true,
        "account": "",
        "timestamp": 1551698624,
        "hdkeypath": "m/0'/0'/1'",
        "hdmasterkeyid": "3ace4a933dc0bc70aecfe49ee6ae3fb766b9d188"
    }

    $ e2-cli dumpblindingkey CTEomyVvMRYbSxCSvC63AJW2FWCgMPQuANwdFA11qWhW1aN8K4UHh8a1Z4MmzWwBRed381FrF6PyKfUT > blkey

    $ e1-cli sendtoaddress CTEomyVvMRYbSxCSvC63AJW2FWCgMPQuANwdFA11qWhW1aN8K4UHh8a1Z4MmzWwBRed381FrF6PyKfUT 1.2345
    4ac7d627122544c20060cc69567f94b3d7410b5aa1c9501df689900df901c9be

    $ e1-cli getrawtransaction 4ac7d627122544c20060cc69567f94b3d7410b5aa1c9501df689900df901c9be 1| jq '.vout'

    [
        {
            "value-minimum": 1e-08,
            "value-maximum": 1407374.88355328,
            "ct-exponent": 0,
            "ct-bits": 47,
            "amountcommitment": "08d283088cd2475eb3d9464499bebfd184de0f20af8a1967298e2c25ba09bc6554",
            "assetcommitment": "0b307e3badd1a84625d547ec6491a90b1bd540f11e634eebca259d743deb566e32",
            "n": 0,
            "scriptPubKey": {
                "asm": "OP_DUP OP_HASH160 dfc0d8fd2771d7995f5e6b45d9af58d407b1aed2 OP_EQUALVERIFY OP_CHECKSIG",
                "hex": "76a914dfc0d8fd2771d7995f5e6b45d9af58d407b1aed288ac",
                "reqSigs": 1,
                "type": "pubkeyhash",
                "addresses": [
                    "2dupr6aq8bukk78bYvU464utmGmB34rLCP8"
                ]
            }
        },
        {
            "value-minimum": 1e-08,
            "value-maximum": 42.94967296,
            "ct-exponent": 0,
            "ct-bits": 32,
            "amountcommitment": "08481b27c8a5de540653a7c0e837bdf9d895e86f0dfb80306301bcbb15769870e0",
            "assetcommitment": "0b7b146b207eedd05460ddde9d62580349cb0036668b8e785b6c16651b29c098b5",
            "n": 1,
            "scriptPubKey": {
                "asm": "OP_DUP OP_HASH160 81f6dc4b799e66824fce41c3401b61d1b3e37983 OP_EQUALVERIFY OP_CHECKSIG",
                "hex": "76a91481f6dc4b799e66824fce41c3401b61d1b3e3798388ac",
                "reqSigs": 1,
                "type": "pubkeyhash",
                "addresses": [
                    "2dmGwHSBrDSpq14o6GFcn82Sshefk89tQz2"
                ]
            }
        },
        {
            "value": 0.0003948,
            "asset": "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23",
            "n": 2,
            "scriptPubKey": {
                "asm": "",
                "hex": "",
                "type": "fee"
            }
        }
    ]

    $ e1-cli getrawtransaction 4ac7d627122544c20060cc69567f94b3d7410b5aa1c9501df689900df901c9be > rawtx

    $ python3 python-bitcointx/examples/sidechain/elements/unblind.py rawtx blkey 

    vout 0: cannot unblind
      destination address: 2dupr6aq8bukk78bYvU464utmGmB34rLCP8
      ct-exponent 0
      ct-bits 47
      value-minimum 1e-08
      value-maximum 1407374.88355328

    vout 1: unblinded
      destination address:
        confidential:	 CTEomyVvMRYbSxCSvC63AJW2FWCgMPQuANwdFA11qWhW1aN8K4UHh8a1Z4MmzWwBRed381FrF6PyKfUT
        unconfidential:	 2dmGwHSBrDSpq14o6GFcn82Sshefk89tQz2
      amount:		 1.2345
      blinding_factor:	 lx('af412ba6eecb0589b622ef4f3a8c4ca63fa2bb86a4610b826bc35f3144033d95')
      asset:		 CAsset('b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23')
      asset_blinding_factor: lx('02bab4ba91ba8e0a083c9e15beab22d71f841fdfcc6aabee210fb7efe2a654b2')

    vout 2: fee
      amount:		 0.0003948
      asset:		 CAsset('b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23')

-----

    $ e2-cli dumpprivkey 2dmGwHSBrDSpq14o6GFcn82Sshefk89tQz2 > spendkey

    $ e1-cli getnewaddress
    CTEoxxzhfXby3kwHbpwvBLWv8ZMoSyssp1msniDUAjayMHLHaJEyKNrm3GM5cCETnW8WMfaFvFypj6oh

    $ python3 python-bitcointx/examples/sidechain/elements/spend-to-confidential-address.py rawtx spendkey blkey CTEoxxzhfXby3kwHbpwvBLWv8ZMoSyssp1msniDUAjayMHLHaJEyKNrm3GM5cCETnW8WMfaFvFypj6oh > blinded_tx

    Searching for ouptut with address 2dmGwHSBrDSpq14o6GFcn82Sshefk89tQz2
    Found at index 1
    amount: 123450000
    asset:  b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23

    Successfully blinded 1 outputs
    Successfully signed

    $ e2-cli getbalance
    {
        "newasset": 1.23450000,
        "a6be6b365498cd451be75ba0f68c258ee01e08f3cb30d5f8469f6628db58dc61": 2.00000000
    }

    $ e1-cli sendrawtransaction `cat blinded_tx`
    8d4ccfb1099d2e904f681bf9ff08806358684db1d9a23e3e3c2990013d3df810

    $ e2-cli getbalance
    {
        "a6be6b365498cd451be75ba0f68c258ee01e08f3cb30d5f8469f6628db58dc61": 2.00000000
    }

    $ e1-cli getbalance
    {
        "newasset": 999998.76510520,
        "a6be6b365498cd451be75ba0f68c258ee01e08f3cb30d5f8469f6628db58dc61": 2.00000000
    }

999998.76510520-1000000
-1.23489480

    $ e1-cli generate 1
    [
        "21cef0f53b10753a4f2a0078e3092907a5cb0c5a5550cee73563410c06259c39"
    ]
    $ e1-cli getbalance
    {
        "newasset": 999999.99921040,
        "a6be6b365498cd451be75ba0f68c258ee01e08f3cb30d5f8469f6628db58dc61": 2.00000000
    }

999999.99921040-1000000
scale=8
-.00078960/2
-.00039480
    
-----
