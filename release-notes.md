# python-bitcointx release notes

## v0.10.4.dev0

* Elements sidechain support:

    Confidential addresses
    Confidential transactions:
        serialization/deserialization
        blinding/unblinding

    Note that at the time of writing this, the functionality
    required to blind and unblind transactions are only present
    in experimental version of secp256k1-zkp library, that also
    requires a patch to be interoperable with python-bitcointx.
    The procedure to build this library and patch it is described
    in the README file of Elements sidechain examplees.

    Serialization and deserialization for Elements sidechain
    transactions does not depend on secp256k1-zkp.

    See examples in examples/sidechain/elements/

* Core transaction class and accompanying transaction component classes
  are now only a front-ends to implementation-specific classes.
  When you create CTransaction, for example, you will get an instance
  of CBitcoinTransaction if default chain parameters are in effect,
  or CElementsSidechainTransaction, if you have choosen Elements
  sidechain parameters. Same with CTxIn, CTxWitness, and other
  transaction component classes, and also CScript. This allows to support
  different (Bitcoin-based) transaction formats and various
  blockchain-specific functionality while the basic code that is not
  affected by the differences between specifications still can work
  unmodified. If you need to check for transaction component class types
  with isinstance, you can use CTransactionBase, CTxInBase, etc.

* CTxWitness now is immutable, CMutableTxWitness is added.

* More consistent mutable/immutable transaction component class handling.
  Creating CMutableTransaction and specifying CTxIn for inputs will result
  in CMutableTransaction instance that have CMutableTxIn in their inputs
  (Actually, CBitcoinMutableTxIn or CElementsSidechainMutableTxIn)

* Default transaction nVersion is now 2 (the same as in current Bitcoin Core)

* CPubKey() can be instantiated without parameters (will return invalid pubkey instance)

* CBlock, CBlockHeader and all related code is removed

* repr() and str() can return different representations for CTransaction contents.
  For example, CConfidentialAsset of Elements sidechain will render as
  CConfidentialAsset(CONFIDENTIAL) when rendered with str,
  but will show the bytes of the commitment when rendered with repr

* Refactoring and cleanup

## v0.10.3.post0

* Fix import issue with SelectParams()

## v0.10.3

**Breaking Changes**

* HD Key API changed, now it is more convenient.
  CBitcoinExtKey now is a subclass of CExtKeyMixin
  CBitcoinExtPubKey now is a subclass of CExtPubKeyMixin
  all classes for keys are instances of bytes
  see `examples/derive-hd-key.py` and b`itcointx/tests/test_hd_keys.py`

  Note that CBitcoinSecret instance is 33 bytes long if compressed,
  and 32 if not. CKey instance is always 32 bytes long.
  key.secret\_bytes is 32 bytes long in both cases.

* CBase58Data removed, replaced with CBase58PrefixedData, CBase58RawData
  CBase58PrefixedData is more generic, it works with arbitrary
  prefixes instead of 1-byte nVersion. used both for addresses and keys.

* Alternative base58 prefixes are now specified in MainParams
  via BASE58\_PREFIX\_ALIAS. see `examples/litecoin-alt-p2sh-prefix.py`.

**Other changes**

* libsecp256k1 may be built without pubkey recovery functions.
  in this case, CKey.sign\_compact() and CKey.recover\_compact()
  will not work, but it will not affect other functions.

* fix for bug when P2PKHBitcoinAddress.from\_scripPubKey is called
  for bare checksig with uncompressed pubkey - wrong address were generated.
  Relevant only for historical addresses.

* Other small fixes

## v0.10.2

* Support for bech32-encoded segwit addresses

* Support for HD keys. Modelled after Bitcoin Core classes: CExtKey, CExtPubKey,
  CBitcoinExtKey, CBitcoinExtPubKey. for usage examples,
  see examples/derive-hd-key.py and bitcointx/tests/test\_hd\_keys.py

* openssl dependency is optional, used only for verification of historical
  non-strict-DER-encoded signatures - CPubKey.verify\_nonstrict(). If not
  available, and verify\_nonstrict() is called, a RuntimeError will be raised.

* VerifyScript(): more `SCRIPT_VERIFY_*` flags are handled.
  VerifyScriptError is raised if unhandled flag is explicitly given. 
  Warning about VerifyScript not being consensus-compatible added to README.

* Make specifying alternative chain params easier with SelectAlternativeParams()
  (see examples/litecoin-alt-p2sh-prefix.py)

* CKey class has been moved from bitcointx.wallet to bitcointx.core.key
  - this is more logical and matches Bitcoin Core layout

* CECKey class was removed - it was a wrapper around OpenSSL's EC\_KEY,
  and is not needed anymore.

---

python-bitcointx is based on python-bitcoinlib

as of commit 05cbb3c9560b36cfe71bac06085a231a6244e13a 2018-04-26 06:46:09

therefore we include the 

# python-bitcoinlib release notes

## v0.10.1

Identical in every way to v0.10.0, but re-uploaded under a new version to fix a
PyPi issue.


## v0.10.0

Minor breaking change: RPC port for regtest updated to the new v0.16.0 default.

Other changes:

* Now looks for `.cookie` files in the datadir, if specified.
* Authentication in a RPC `service_url` is now parsed.
* Implemented bip-0037 version message.
* `contrib/verify-commits/` removed for now due to breakage.


## v0.9.0

Now supports segwit, which breaks the API in minor ways from v0.8.0. This
version introduces lots of new API functionality related to this, such as the
new `CScriptWitness`, `CTxInWitness`, `CTxWitness`, new segwit-specific logic
in `SignatureHash()` etc.


## v0.8.0

Major breaking API change!

While this interim release doesn't by itself include segwit support, it does
change the name of the `CTransaction/CMutableTransaction` method `GetHash()` to
`GetTxid()` to prepare for a future segwit-enabled release.  Incorrect calls to
`GetHash()` will now raise a `AttributeError` exception with an explanation.

Since this release doesn't yet include segwit support, you will need to set the
Bitcoin Core `-rpcserialversion=0` option, either as a command line argument,
or in your `bitcoin.conf` file. Otherwise the RPC interface will return
segwit-serialized transactions that this release's RPC support doesn't
understand.

Other changes:

* Cookie file RPC authentication is now supported.
* `msg_header` now correctly uses `CBlockHeader` rather than `CBlock`.
* RPC `getbalance` now supports `include_watchonly`
* RPC `unlockwallet` is now supported


## v0.7.0

Breaking API changes:

* The 'cooked' CScript iterator now returns `OP_0` for the empty binary string
  rather than `b''`

* The alias `JSONRPCException = JSONRPCError` has been removed. This alias was
  added for compatibility with v0.4.0 of python-bitcoinlib.

* Where appropriate, `RPC_INVALID_ADDRESS_OR_KEY` errors are now caught
  properly, which means that rather than raising `IndexError`, RPC commands
  such as `getblock` may raise `JSONRPCError` instead. For instance during
  initial startup previously python-bitcoinlib would incorrectly raise
  `IndexError` rather than letting the callee know that RPC was unusable. Along
  those lines, `JSONRPCError` subclasses have been added for some (but not
  all!) of the types of RPC errors Bitcoin Core returns.

Bugfixes:

* Fixed a spurious `AttributeError` when `bitcoin.rpc.Proxy()` fails.


## v0.6.1

New features:

* getblockheader RPC call now supports the verbose option; there's no other way
  to get the block height, among other things, from the RPC interface.
* subtoaddress and sendmany RPC calls now support comment and
  subtractfeefromamount arguments.


## v0.6.0

Breaking API changes:

* RPC over SSL support removed to match Bitcoin Core's removal of RPC SSL
  support in v0.12.0 If you need this, use an alternative such as a stunnel or
  a SSH tunnel.

* Removed SCRIPT_VERIFY constants ``bitcoin.core.script``, leaving just the
  constants in ``bitcoin.core.scripteval``; being singletons the redundant
  constants were broken anyway.

* SCRIPT_VERIFY_EVEN_S renamed to SCRIPT_VERIFY_LOW_S to match Bitcoin Core's naming

* SCRIPT_VERIFY_NOCACHE removed as Bitcoin Core no longer has it (and we never
  did anything with it anyway)


## v0.5.1

Various small bugfixes; see git history.

New features:

* New RPC calls: fundrawtransaction, generate, getblockheader
* OP_CHECKLOCKTIMEVERIFY opcode constant


## v0.5.0

Major fix: Fixed OpenSSL related crashes on OSX and Arch Linux. Big thanks to
everyone who helped fix this!

Breaking API changes:

* Proxy no longer has ``__getattr__`` to support arbitrary methods. Use
  RawProxy or Proxy.call instead. This allows new wrappers to be added safely.
  See docstrings for details.

New features:

* New RPC calls: getbestblockhash, getblockcount, getmininginfo
* Signing and verification of Bitcoin Core compatible messages. (w/ pubkey recovery)
* Tox tests
* Sphinx docs

Notable bugfixes:

* getinfo() now works where disablewallet=1


## v0.4.0

Major fix: OpenSSL 1.0.1k rejects non-canonical DER signatures, which Bitcoin
Core does not, so we now canonicalize signatures prior to passing them to
OpenSSL. Secondly we now only generate low-S DER signatures as per BIP62.

API changes that might break compatibility with existing code:

* MAX_MONEY is now a core chain parameter
* MainParams now inherits from CoreMainParams rather than CoreChainParams
* str(<COutPoint>) now returns hash:n format; previously was same as repr()
* RawProxy() no longer has _connection parameter

Notable bugfixes:

* MsgSerializable.to_bytes() no longer clobbers testnet params
* HTTPS RPC connections now use port 443 as default
* No longer assumes bitcoin.conf specifes rpcuser

New features:

* New RPC calls: dumpprivkey, importaddress
* Added P2P support for msg_notfound and msg_reject
* Added support for IPv6 addr messages


## v0.3.0

Major change: cleaned up what symbols are exported by modules. \_\_all\_\_ is now
used extensively, which may break some applications that were not importing the
right modules. Along those lines some implementation details like the ssl
attribute of the bitcoin.core.key module, and the entire bitcoin.core.bignum
module, are no longer part of the public API. This should not affect too many
users, but it will break some code.

Other notable changes:

* New getreceivedbyaddress RPC call.
* Fixed getbalance RPC call when wallet is configured off.
* Various code cleanups and minor bug fixes.


## v0.2.1

* Improve bitcoin address handling. P2SH and P2PKH addresses now get their own
  classes - P2SHBitcoinAddress and P2PKHBitcoinAddress respectively - and P2PKH
  can now convert scriptPubKeys containing non-canonical pushes as well as bare
  checksig to addresses.
* .deserialize() methods now fail if there is extra data left over.
* Various other small bugfixes.
* License is now LGPL v3 or later.


## v0.2.0

Major change: CTransaction, CBlock, etc. now come in immutable (default) and
mutable forms. In most cases mutable and immutable can be used interchangeably;
when that is not possible methods are provided to create new (im)mutable
objects from (im)mutable ones efficiently.

Other changes:

* New BIP70 payment protocol example. (Derren Desouza)
* Rework of message serialization. Note that this may not represent the final
  form of P2P support, which is still in flux. (Florian Schmaus)
* Various bugfixes

Finally starting this release, git tags will be of the form
'python-bitcoinlib-(version)', replacing the less specific '(version)' form
previously used.

