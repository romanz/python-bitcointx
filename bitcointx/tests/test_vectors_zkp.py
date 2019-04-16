import ctypes

from bitcointx.core.secp256k1 import (
    secp256k1, secp256k1_has_zkp,
    secp256k1_blind_context,
    SECP256K1_GENERATOR_SIZE, SECP256K1_PEDERSEN_COMMITMENT_SIZE,
    build_aligned_data_array
)

from bitcointx.sidechain import elements

genH = bytes(bytearray([
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e, 0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
    0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68, 0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04
]))

def test_blinding():
    commit = ctypes.create_string_buffer(SECP256K1_PEDERSEN_COMMITMENT_SIZE)
    blind = b'\xAA' * 32
    amount = ctypes.c_uint64(123)
    ret = secp256k1.secp256k1_pedersen_commit(
        secp256k1_blind_context, commit, blind, amount, genH)
    assert ret == 1
    assert commit.value.hex() == '08230230edf4cce9fbf49bd5cc49ea776d2233b836bed210110c67c631908815c3'

    confValue, commitment = elements.create_value_commitment(blind=blind, gen=genH, amount=amount)
    assert confValue.commitment.hex() == '08230230edf4cce9fbf49bd5cc49ea776d2233b836bed210110c67c631908815c3'
    assert commitment.startswith(confValue.commitment)

    proof_len = ctypes.c_size_t(5134)
    proof = ctypes.create_string_buffer(proof_len.value)
    nonce = commitment[:32]  # TODO: fix

    message = b"My tears are like the quiet drift / Of petals from some magic rose;"
    extra_commit = b"And all my grief flows from the rift / Of unremembered skies and snows."

    ret = secp256k1.secp256k1_rangeproof_sign(
        secp256k1_blind_context,    # const secp256k1_context* ctx
        proof,                      # unsigned char *proof
        ctypes.byref(proof_len),    # size_t *plen
        1,                  # uint64_t min_value,
        commitment,                 # const secp256k1_pedersen_commitment *commit,
        blind,                      # const unsigned char *blind,
        nonce,                      # const unsigned char *nonce,
        0,                          # int exp,
        32,                         # int min_bits,
        amount,                     # uint64_t value,
        message,                    # const unsigned char *message,
        len(message),               # size_t msg_len,
        extra_commit,               # const unsigned char *extra_commit,
        len(extra_commit),          # size_t extra_commit_len,
        genH                        # const secp256k1_generator* gen
    )
    assert ret == 1
    proof = proof[:proof_len.value]
    assert proof.hex() == '601f00000000000000013941cec6c55b6ceee2df6f2e249cab46d1c3bb9eb5c5d205831d28da9a113e4b9c5e2aa24a9679088c43e648dea6afe35c5ba77450da89aea65786aeaa3c92aaff5aff37d17c8c92227a4fb16aaf6c7b0c16375f5686934b724c765c1f079c91c861fba0a579ca191dcb57f63be7b690568b84d3c21b95a7e97f2b9b904628b1bbb76dc23e7e0c9eca87ec88f428e623b3699fc38aebd1d72c774c2a38c50d7cd51b92d8c36d02f94373387f9c40ec3a14309cf32cd883236b698ceed64dc7353d55acfd2041ee7b1e3888f805fa93947dcea6923dbf0ee5fc2a66133d3b48b8e9095238ba3b4df87aa1b27161f1d5ab00de2c6f9e8b10d30d422583346265e7a810e2d78c19c35d497df11d985ad3128ee4c73f05a403d290fbc5c5cd5e8a4351fa5a830c6ad7ec6dd792e25b46deaa801f7f408ac4adffc87aeb8dbcc4627834fb0603887c8396aaa60a670f5439c6dfd42a3fa87af20f3b21ead87ac9381a842a5811c84a111b971f8527d500412f430e1d57cfe4ed36c400209fdec7b6b1b21548d7774bbeaf544ee9cb30b82e47980229ad56946a71524be3d96c470c7b2779ed0fbc40d1329e27ba9bc11690bb7288feeadab99379634f873f3a45a20396a491829b86ced6e0d5bd47141dd87b2864a3306024f6d90f4157e80775abb89355443a93fe5ac8f3a9c96cecf45551d9656e6908ac2ae7501e00162779982c2bd3f577feada30641e5b0ecb7e61e8c04a70d1535b6d4c6fa7a778c6ecf8ec2f69f6dff0f74c47031f6de991b0fb0aef26dde0c67432cab3a19f363a96a346123acbbb2e2169c2ec982c1f2301b0c4ed552d87e95b79f514c3ec6eb204621621d01d5d4303ca114583e6251e88e4faa6df429060f657fe8944994de24520a81f32d826f0f0352724012241b565b93eeeab56e820b319283a2bd884182a4fed81540aa24127d09e580740b44bb22f55b3d536a0fac19bc7a32100c9285e6d4963295a387205602b4b246cbea575b6e1666735480f21dfa534fd00b018d0c45cba486b527c7c34f5f1974103f75b123c4718373ca7d38f245dec05889d3030346ca971f35ab8776b7cbba38fd21eeb6f7255a63bb2c18e8a0f065a85087d4cb75272f3a2b1fa56a927ec98020c1a117f29ad868330ab4c964f3756b5b9e92961df87372fa92b4ccf97d08476d633620e892b01d2db4abac494fdde30fde367f10b88a1deee05a5476a7498c1af412dbb9bf00cdd8a91ebfd490287623b4ed0524df79d039c2685319fa8b45b4afc1bbe72bc0448ae88851a0546d6f1621be86b76e9ed3597151fcdc30872400374706fadc903b61ba83168542baab24b42b01fe72829dca96c4ee1fc37bd7c065bc159c2374a3d492048b50858d8b21e3503c37b287853837f30123dcc61770e1e30a2e68f940beb7e5b31747695965244fc7fffa1b218f541e1db62a68994d860ce2cc6e4d61cb4495df2ad04b9c322115b4e40b2219bffd1784371b97f1885abd0534440368541177d268242a0ade90497e4e5a2bef53d93ce1243cb3ca9757d479e89e5a031577caa92c870128e9f0bd566a70a9abcabec1777e8fd137208fc88f38f7c1f33c14d9c70404b7c455a7b1c6a5bdf5c22d1962bec59f09959faecb8f30b6e972c7e256169be0af2c529d974334bf396377ceae644542ed50d9aabbe26df3bd2d8241d8ab7f9a3c9b30cb11fff630c048683d7dbc8f12ba7a21f7e92c075567e1a69b139f897a39dfcd53cddf5c83835af380367b5c1f2be6cad7b1a84ba48ddd2c61ebf3d4f8761d8428f827e4c477170b4848cf4eccca145bfc9820dd978852fc69fa5a122e583a4665f330f97a82b22f861f95a2409bc96eff9a8fe541ee2cf1438353aba1388a609110a461eb1ff984dfb4ce7933f4951311d3e2ea34a1944839ed5d29189dc06d753bc3cb4aa20ed65dc55f93a1b1b55f8f022e2a875daef5b4f9f9be57830b862fa5b2e3e7d6e77d047a60ea3b55ff5d37291f5a21e407d064673e6e08d2f60b09df944f44798fe4afe92c6ebbd43573fe29161bb21f87a629dbbda3a98a11223500673bb4da8cd8dc4f1516a0946790d1cbeae1adc30d68c744fbeb2bad0842ec5f176d43e8cdae12dce068560d73e141591bd9cab42dbfa0f753ea965141796b038b38000bcd2f29533b18c9af4daad2bc7b99ba36b9b503ce039a797d70110316e809ec44765ac3ac792e0a49a16001f623c2f6d9e0a55d44cee189eeb3891231fac048387a773455e751e4771477af4a2fc0fd47995b0b95fe584a161041f2c6093e369d9c22325a1bd55a8fac32e2f14c7304d320a427ee13de0c0088a8457b57c652a02aee1a696f8b41188254f8e1764baebeb17c383cacbabe2b1ca070e3c904d34492e8612ac55d5d1fcb6c90d8f91ed7a6db77fb77b7787410aaa2a76aa2904f9c160a2db409763ec41a945ebe9f9cd76d8deb539840f952ae16e3caee44b4af704bd26531a88812925a9015d7897b531d6f96180d021dccc68a15f7024754edfe1efe1b0da2ee757480c7622a340f403d316fb64c9c019ac0dd4ecf4dd5e9ac0ae39e9795f1ed2da88bb69ff78066cee3c0d0fa1c336bd4c831eb71906f77698e2f84fc6bd68e860b812296ab312d6f189842bf780943de3271522dd1639d24d14d630cd3e49b41a6a6c6d31ae9aa607ee0f6daa60b9ab88ed2fc3e5918fbacb986f2c49e6b92fbc6f382ed4e46f603238eb1080c579627efa9e8e8af75b4855d7100afbe8994ea7cbe11d87eef3d0a9d9f3930d76f8bf37062c999ef7cbd22db5b5b43b864b1c3c5b616d8865dfdef447e4c41ad03b9226b328aebf6bd3ef300f094079cd6792cc423d2588a446da424ee22e05b0e6b5cbeda8a40983c551e037adb4e1615ad1f998056797409eb44dc3fad1f3609218626d87cd3252783aa9b8ed1ed7519f9363ee6fc9ca7bd63d1984f3c599c18df1d92356898147d81ff1fd911dc80b8f1dab4ca5f90e168eed559d78999c993d19a4451775dac6384fde3645166880fb5a9d84f71512cc7611877e48cd388a0c354a4f39a26054c32f3216a4bf0a5af2380561839f96a5f1f5a8c643f0790c09963bc15843faf15756aa023cec7f494f6566f1e04e55afb4c01dc188c627c04b39f27e21bf39cb208b2ecba763aed0cc60ed28e6baf8ebc12a7738dcd627f8ec11db946b574ae2626a91f8feb10021c994b574f213315b500a0eea2af58911796be5bf07610a7fd4ec1f8b75137e02bac17db014b6d5d4c46f918c3aa732b34378fc988219653c01819e491c552ecc132628d8cadf3bf68f6fc929ec6679b37cb77379804e7e523e61f6cff9566c8420c27fb18bf514baa97948153750db3f05456adedf90cfc3ab2abaa31afc750f8eca149eaa95b73acd6f5e2029163a74a5d0747dfec6548a64410d2590ada6c695f7c4a2e1aafff35d75dc6bf4a059f2af8e051446934b59a6e5a67b5890bacaba3b3796c1a5028401f304577deef1350bc6053478be1a50ee8e62502869ab8959ebf2c3a113248b0b1e9fbfb3ec65ff82bc6ac0051815ecb6fcd6d9bded870fe5d533c60914d8140a96c604f299a5fec41312feb6378af9d195602'

    # nonce = commitment[:32] # TODO: derive via ECDH with BIP-32 derived private key
    # message = b"My tears are like the quiet drift / Of petals from some magic rose;"
    # extra_commit = b"And all my grief flows from the rift / Of unremembered skies and snows."
    # ret = secp256k1_zkp.rangeproof_sign(value, commitment, blinding_factor, nonce, message, extra_commit)
    # assert ret == 1
