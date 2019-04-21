import ctypes
import hashlib

from bitcointx.core.secp256k1 import (
    secp256k1, secp256k1_has_zkp,
    secp256k1_blind_context,
    SECP256K1_GENERATOR_SIZE, SECP256K1_PEDERSEN_COMMITMENT_SIZE,
    build_aligned_data_array
)

from bitcointx.sidechain import elements
from bitcointx.core.key import CKey, CPubKey

genH = bytes(bytearray([
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e, 0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
    0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68, 0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04
]))

def test_blinding():
    pubkey = bytes.fromhex('03bbe24b33e3caae9d11eb5df19c4038e5edc350fbfdbb449a6094407a668f833d')
    ephemeral_privkey = b'\xEE'*32
    ephemeral_key = CKey.from_secret_bytes(ephemeral_privkey)
    ecdh_pubkey = ephemeral_key.ECDH(CPubKey(pubkey))
    nonce = hashlib.sha256(ecdh_pubkey).digest()
    assert nonce.hex() == 'bfe3c8bff01d1a8a49a267ea5daed5a32a7ba79754413e60538c526c4b91292e'

    commit = ctypes.create_string_buffer(SECP256K1_PEDERSEN_COMMITMENT_SIZE)
    amount_blind = b'\xAA' * 32
    amount = ctypes.c_uint64(123)
    ret = secp256k1.secp256k1_pedersen_commit(
        secp256k1_blind_context, commit, amount_blind, amount, genH)
    assert ret == 1
    assert commit.value.hex() == '08230230edf4cce9fbf49bd5cc49ea776d2233b836bed210110c67c631908815c3'

    confValue, commitment = elements.create_value_commitment(blind=amount_blind, gen=genH, amount=amount)
    assert confValue.commitment.hex() == '08230230edf4cce9fbf49bd5cc49ea776d2233b836bed210110c67c631908815c3'
    assert commitment.startswith(confValue.commitment)

    proof_len = ctypes.c_size_t(5134)
    proof = ctypes.create_string_buffer(proof_len.value)

    message = b"My tears are like the quiet drift / Of petals from some magic rose;"
    extra_commit = b"And all my grief flows from the rift / Of unremembered skies and snows."

    ret = secp256k1.secp256k1_rangeproof_sign(
        secp256k1_blind_context,    # const secp256k1_context* ctx
        proof,                      # unsigned char *proof
        ctypes.byref(proof_len),    # size_t *plen
        1,                  # uint64_t min_value,
        commitment,                 # const secp256k1_pedersen_commitment *commit,
        amount_blind,               # const unsigned char *blind,
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
    assert proof.hex() == '601f0000000000000001eb5c441b89c41178f2503729f54eda0fd8e4945ce103945c3267596ccc86ba546e5c847ff65a8c016b8420cfcfc63148e8b1c8990007dfd25ad84ee84d5336a6b1b5c5d37a3a6034d1817dd09bf2ebbd8a4be071502998a317ce44497bb35839a64b74de283956f46285af88c908fde1ded8e5130f661beb15e6b113f6b97d3fcd93e111638b66d995c562a39b75a2c327e5fee6c538b04cc509ea0352931dc9d67e454892b29895af93ef188d00362960a66eb38dd8b03c57b328656a5013fad6644c61785649af8991dccee4b4fb9f3f4d3704bd3f213bb880fa63c3fe82e0b4c7ebc00682732fac779b911874bd1358cdfff24024cf5351f5ca7902ff252fda02ed0f0d29ff7b34e8165ba6f0d0583e6d1a25b58dd1a8e7468c47452d94238cf3c4fc26d74a29a930c0caafbf5b5f4f0527cb7d0f062182c64dd04b29547e24bd615387486a0355a3211c7264bf474c9e3bc1c84f2207092aed038ee8a8a5d9ee1049bdd1c1f2b6ab1b01f780b5af72725a4240e689378903e4b13b1840d2c7f794776acaa965bbc5c9bd8f67c96728522e7e328399d4d8eb6ecf3a4872f4d17217e93ee3c772c2c8f523f9591c17a5c11b8db448df16c37cdc8861759b56597b7418e3d2391f1a1fe574bb27e20ddd7359854ad4a559a2466998a0f624d052488b4b494136f33524d0037f35b942689b3248d69c5f6374584ecb41a3feee35de162febd7f9d2f4884677b7885aeb043e1dc4196082b9f23ea2b6f66636865c43ec5b66f89e3f308ff353b4f93970a9ca454b3d7e9febcd33cbaf77c42bdce3c21023e349450e3fa4cac5671888a5dfadf84188847da498c54544bfab6fc9ab35b94558cccf3756904081c6cab542fa07ef72669b4c5e4b9af9c928314d51d86ccb4429f5a0bbe5e3384d0268a5ef1eede9bf9959a9226b3970b70a774d1425d0170273f35c4c8df3650a5d239acbf173431dbd32e57d109317330b774b2b021563940422ded74848bb4bc9a0fd1e002eafc8100400d03f8a53eede7a17d5c8820498dc6a8c7bbd9a98e71e0f3be1a9ef9714f89735510d1bba66acd53a0211276407a6118abae200d447ca2addb16dca0b559927319d9c6c6bb5fd3862cc0148c4dedbdcc40a9415ba1ab666b4def3c0f07713f575a2e57492d8df81f06dbec3c236151c854b9fdb9abce8271ecd7fbd39775fdda5264f52ea809470da7d09a920b7f7270f916b9f379c1f6bb91d049921533b4daa19827ede999fe506b40014c7d0649279b17c9d5e84de15b184ebbf1a857e27b8e74845fe629157a6f0e630f2da3d96b534038fa6ed477d6fff14f7a6d0992eeb6a03c7c78ff5700a2239a4389100d84f59ac7d81f50a1b81d0fff03b89a3cd914f5bedda5d1f818cb37c5a803e8866e631141d1ed2cf4baa4d5f5cb1c46a1a11ac8233424588391db94fe9aa6f254f1ac43e28078fbe9054e41f3bea308bcf5af933b05ad0c07e94fc150db523d0daf1fc6563333ebadaa67d5284ab5d1066bcabf4bcadd795ad1feebf70fb442dd105fdd10c7df3ae511078d836dd1307858be36d26659a899ee5f8e45b6a9788dc240f388601b3c8dc8b8a5cc17fe5eb5259077ff3cec3d660eb4bf4393390c69a40e41568019328d583ace5e4ed90c374cbd8e09511e2d826a78531bc7e44820cfb4c1885736697fe75a2a10045a74bd07feaa8e734c29deaac24600d57f246ace6340459629de9173665f2b3defee94645c8c5c572abffd10baf80476cef7ad91e2c16453c1973f470531fa7ef149daaa0d4e4d5434237ede76a07554fae1111cfb7817b1e07d4050e3ca450b1ccfe03548b1f2ee68ceb1d75f2b7c068269bccd163b77f496f319d1d5b3c9de36e9f1d67fcf1118244f8f2aaa72efafeab07d3c271c384f327c56fcef8e287a9bcd946fa7c0b46cd8f114963c5b56da117e152b6b6df4ebb46664c19de296595b9415eea7061679b896ae8a3910b3962d066b7f10b0480fbe2dfb49025c08f6114aaa141c5bfe0cbf250b9ccc2db35524eda23a7e4abf8cf56572554c715e261a23d97fcebfd73289c706162a667caed17fe50eea57e0ebbe137ad3fee4ea85debd00291163179c68b0e26de6807e048ed416662adcb4ece303f543ebd63ca9f31808eddd27fa72259fcc6fdf96d85c2ab10a74b30dde80e9e888cab00811ad0ba4dc3a2f5dcf604bdc1c4474738baf9fc9374e2ea933301273b159a8efcffd6f409451b00a715d831b7d1a8d5c517701121238c4c7b01e3a06fba1466ca368fbb24a7368525faaa20a741399e6e5bd1217541e5d768d8e77de9bd87f7b312632913ebf16e02af3e7596b96634d8c6c65bd5180d6f63700df8aacf06654317bf130c9638d833fa43c24fdecbc9ced2278d627af9edb73de936298eddbe2ed2a2ba6ebe40e7ea7d25a0e6d10b42f88a28a1a072d7c87564f5fe5066a2c75d827be6cb0eb41676cc0c6102343d94ac1ea36d8a36fc9027f5ae37400f10a2fe7d80596e93ae036b6d1b80ba81548308eb8a8fa23e624025a341ad38bdc605104b50809fd72b3d5060ed8f8a77ea2ee610389259a6b88e4c187f987f22f95cd1548608430ff54322cb47dd4cbf6ca38822164a97bee7b4a5d5a482249696bac92f27ee48ccd039a388a8c071c574246205d73725e88943e7a4f85d1ff5b031ef1e1d338f53b7b6d30cec11274e64dafd202ed2b20d754aa07e422062f2a6e27b83198fac0a066bd7762a30bbea6a69521d944f48b8a9c98be301eca036eca03e96e878d2b5d22fa1f937cb7ebceefcfdcb6575dfb610a0c2b9cb33190d900f3045ce6f6a925665f82a677c790f20b9ed71ce62af298380c107b8dd8d2fddca7c3afdaf0eae97b21ddc4b581e6aed21ad6310894aa7ef3a29ac5084234a4f2cbd8e75f1758ecacceff413fb75a61e367229ee51062bab8ff51d13bcc3603680a39a265b710e551c958692635f14b454b07b20a72416b19aa2273b272dba79536488db32ae0b9321fc16770aa3f1f49f4a254d7bcc932aaa2271c44e0ce31a9b3bd01fddaa0b3d7c228e26295c4409bf17c6162d7a0f8b768155a1d8514ccb4b2ad46725fc08897ea26a046bff8509e227eae0f9107cb67ea2e4ed4c096c96f550770327c81ffce767f552a039433b72b7a6adde468469a50523c3ebe7edd01d75383e4c77f2d571b43a6c048de7bb565f2b6b6db4cbc897e9e5198b31c824f2261bd387fdd3ecef8f0be47b08d0405fd24a13afab6f2a59bdd24a2026b8aba18242f51e7c8942b472ad486cdb5802c3439fe18d9c92711f990629441f914b96fe637d4c172c550502247111f3a6bccbebfe12fd649aef357271cfd72f470c126646bf6ec43ebea8aac2ed9c01b96999d90ec8b9e3482ddc00031710339b9d80356eebe0cfd350e42501f6e6abbcf2b1309ce897ae3e606c657d4f661fed9c8da5d668fddcdc045024e791c844854b1039d1fe893de409ec4805ad1cb37b446c6ab003c850716349fc230518777a0b4f0f4831bd60458474a19e4891f6411c963b502e30bc96483e4f853d0d360b644946f6445934aabfc6068f12c3a900113b345a41f644dfa9a5a8c9e0edb084e464e409'

    # nonce = commitment[:32] # TODO: derive via ECDH with BIP-32 derived private key
    # message = b"My tears are like the quiet drift / Of petals from some magic rose;"
    # extra_commit = b"And all my grief flows from the rift / Of unremembered skies and snows."
    # ret = secp256k1_zkp.rangeproof_sign(value, commitment, blinding_factor, nonce, message, extra_commit)
    # assert ret == 1
