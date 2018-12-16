# python-bitcointx

This Python3 library provides an easy interface to the bitcoin transaction data
structures. This is based on https://github.com/petertodd/python-bitcoinlib,
but is focused only on providing the tools to build, manipulate and sign
bitcoin transactions, and related data structures.

## Notable differences from python-bitcoinlib:

* Network-related code that deals with network messages and blocks is removed.
* libsecp256k1 are used for signing and verifying.
  Signing by libsecp256k1 is deterministic, per RFC6979.
* Bech32-encoded address support
* HD keys support
* Confidential Addresses and Confidential Transaction support for Elements sidechain

## Requirements

- [libsecp256k1](https://github.com/bitcoin-core/secp256k1)
- [openssl](https://github.com/openssl/openssl) (optional, for historical signatures verification)

The RPC interface, `bitcointx.rpc`, is designed to work with Bitcoin Core v0.16.0.
Older versions may work but there do exist some incompatibilities.


## Structure

Everything consensus critical is found in the modules under bitcointx.core. This
rule is followed pretty strictly, for instance chain parameters are split into
consensus critical and non-consensus-critical.

    bitcointx.core            - Basic core definitions, datastructures, and
                                (context-independent) validation
    bitcointx.core.key        - ECC pubkeys
    bitcointx.core.script     - Scripts and opcodes
    bitcointx.core.scripteval - Script evaluation/verification
    bitcointx.core.serialize  - Serialization

Note that this code may not be fully consensus-compatible with current
bitcoin core codebase. Corner cases that is not relevant to creating valid bitcoin
transactions is unlikely to be considered. See also note on VerifyScript usage below.

Non-consensus critical modules include the following:

    bitcointx          - Chain selection
    bitcointx.base58   - Base58 encoding
    bitcointx.rpc      - Bitcoin Core RPC interface support
    bitcointx.wallet   - Wallet-related code, currently Bitcoin address and
                         private key support

Effort has been made to follow the Satoshi source relatively closely, for
instance Python code and classes that duplicate the functionality of
corresponding Satoshi C++ code uses the same naming conventions: CTransaction,
CPubKey, nValue etc. Otherwise Python naming conventions are followed.

## Mutable vs. Immutable objects

Like the Bitcoin Core codebase CTransaction is immutable and
CMutableTransaction is mutable; unlike the Bitcoin Core codebase this
distinction also applies to COutPoint, CTxIn, CTxOut.


## Endianness Gotchas

Rather confusingly Bitcoin Core shows transaction and block hashes as
little-endian hex rather than the big-endian the rest of the world uses for
SHA256. python-bitcointx provides the convenience functions x() and lx() in
bitcointx.core to convert from big-endian and little-endian hex to raw bytes to
accomodate this. In addition see b2x() and b2lx() for conversion from bytes to
big/little-endian hex.

## Note on VerifyScript() usage

It is good to use VerifyScript to pre-screen the transaction inputs that
you create, before passing the transaction to bitcoind, or for debugging purposes.

But! Bitcoin Core should _always_ remain the authoritative source on bitcoin
transaction inputs validity.

Script evaluation code of VerifyScript() is NOT in sync with Bitcoin Core code,
and lacks some features. While some effort was made to make it behave closer
to the code in Bitcoin Core, full compatibility is far away, and most likely
will not be ever achieved.

**WARNING**: DO NOT rely on VerifyScript() in deciding if certain signed
transaction input is valid.  In some corner cases (non-standard signature encoding,
unhandled script evaluation flags, etc) it may deem something invalid that bitcoind
would accept as valid.  More importanty, it could accept something as valid
that bitcoind would deem invalid.

## Module import style

While not always good style, it's often convenient for quick scripts if
`import *` can be used. To support that all the modules have `__all__` defined
appropriately.


# Example Code

See `examples/` directory. For instance this example creates a transaction
spending a pay-to-script-hash transaction output:

    $ PYTHONPATH=. examples/spend-pay-to-script-hash-txout.py
    <hex-encoded transaction>


## Selecting the chain to use

Do the following:

    import bitcointx
    bitcointx.SelectParams(NAME)

Where NAME is one of 'testnet', 'mainnet', or 'regtest'. The chain currently
selected is a global variable that changes behavior everywhere, just like in
the Satoshi codebase.

To use alternative chain parameters:

    import bitcointx
    bitcointx.SelectAlternativeParams(AltCoreParams, AltParams)`

See `examples/litecoin-alt-p2sh-prefix.py` for an example usage.

## Unit tests

Under bitcointx/tests using test data from Bitcoin Core. To run them:

    python -m unittest discover && python3 -m unittest discover

Alternately, if Tox (see https://tox.readthedocs.org/) is available on your
system, you can run unit tests for multiple Python versions:

    ./runtests.sh

Currently, the following implementations are tried (any not installed are
skipped):

    * CPython 3.4
    * CPython 3.5
    * PyPy
    * PyPy3

HTML coverage reports can then be found in the htmlcov/ subdirectory.

## Documentation

Sphinx documentation is in the "doc" subdirectory. Run "make help" from there
to see how to build. You will need the Python "sphinx" package installed.

Currently this is just API documentation generated from the code and
docstrings. Higher level written docs would be useful, perhaps starting with
much of this README. Pages are written in reStructuredText and linked from
index.rst.
