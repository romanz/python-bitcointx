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
from bitcointx.core import Uint256, lx

def test_blinding():
    asset = elements.CAsset(bytes.fromhex('230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2'))
    asset_blind = Uint256(bytes.fromhex('b07670eb940bd5335f973daad8619b91ffc911f57cced458bbbf2ce03753c9bd'))
    (confAsset, genBytes) = elements.blind_asset(asset, asset_blind)
    assert confAsset.commitment == bytes.fromhex('0a706c19c4b7698acfb620a8966d5c256b938c100f8e885e57e21e8c3761916853')
    assert genBytes == bytes.fromhex('706c19c4b7698acfb620a8966d5c256b938c100f8e885e57e21e8c37619168534f5f7de67db93506e5f424dfb23c22abb211d3a3934598d1bc62a7ace9c44513')

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
        secp256k1_blind_context, commit, amount_blind, amount, genBytes)
    assert ret == 1
    assert commit.value.hex() == '098f337a18e9afa90267b2f34e9861ad3988dac8b38abbb2ae821832d13fd33128'

    confValue, commitment = elements.create_value_commitment(blind=amount_blind, gen=genBytes, amount=amount)
    assert confValue.commitment.hex() == '098f337a18e9afa90267b2f34e9861ad3988dac8b38abbb2ae821832d13fd33128'
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
        genBytes                    # const secp256k1_generator* gen
    )
    assert ret == 1
    proof = proof[:proof_len.value]
    assert proof.hex() == '601f0000000000000001df67497312feb26a000e56e4a1b72583623c2217b2d6514fdbc037150362625f5c18c94e94451d69985e7b0c92caaced5d3425a061d549b4a616bb13dd4d667a8550a51859b95c7af715914e70669e9fc4e157a19da5bf19793a1d24f83c1d6ff8414e01c8b2d09b23ea1cf5842b042d4c059f180cfc2f07b5539a431c72d89003a76462355b3c6342699e905df74193a87bf7d912dd48b44252209f27f39ed0cd7e96e17237d990ae48e832ce4b88b09de1688cb793bbfb0bd9b2aff70633316157ce462fa1f2b81555458dbad26fcd84835d4fedb3daca212aca0918dad51be4527edfc48fea00913db852373adeef740a7f20e963c541bd8ccf77399d945c787af2dfe43ab262a4aed806839440afef91e47045a84ce7d6437d9c8ffd9ca14c78c1c7e6f8e3a8a580bc18bf3c8611b6a98e2ffe3ef797b0158d9d04c7b2f533ccdfe6a17f0d9ec1dfdf449bb0d8acabd83c94d8c56b1705598c9a8de22c24a5db96cac771d3f3c7f68c5439886ae7de209e67047e45ed85975d4c25e62440400e7c1c5bd05711b315a22f8e65f628f1f823cbe4f03e68cee054044da5a9131274511def173e9648b9b92f1743af39f0e982cdf1c6ad7cd50ec7986fd385dd2f47db20fac5871f07dabfe4b49a22bd4a95021726edd73f1cf2af24b9a656be094db1e48237d049195333890bc27c8474aa4fe847397f03f1e5eca27984dd5870cec48df803f86bf5d0aa2363b6fd3e3089f18aa1d5006243f42d7048cac8c47ddc1137420bd91c14e5859bc83a205c7f2b0b7a4725747f4e9c0dd4d389512ae83f024412f4a9cae547d4e59c359ecaf4f32ba825c7e6da466467c74e15d8107add9ce57e39f56bf8d4e2102598f0425e441792d2334df430d4075818b80e97a7e342fa008a1119af579cb2aabb15e29ba4ef91ec6c35b6696fbe7304ce8ebaba2d8148e0d109e09e419f9532f2bcdd0e3f9a073c6f43b2c7d3884cd0045c0b541bc7f437f7a834afbfa4e18a1230e51ff84186440fd2d91feb023eb021fd6bfe4711ffe11a7d51153fe0592b94e8cb3abf512260319e05a3fb31a799dc668905f8fe7416801a70f1637a99be269c4e6e1b3316fb82c8dc53d3e56f027a645549b085b0fa5367f4d4c0eecf3bf975acad92b1a128bec1886c3199be2e70bf75fbd37e247966e8383d3c756d986ff9f95839404fc0c33a6c9dc915f75209542adf6ff0141aa401da606010bb84c551e067a41427e86f9ff1ac2764c18aa7f2ce2e1cfb26de8b6d96a1d5b5985e2c67bb2042c8136d1b286620f1ad9fcc71389fdd26533ad3767d7f77b4f357f065de92704461df349d2cc78714b44496a1192fa1e3989393efe12438506954695e1b7e43b28ec95c66b3335cb0e8f6e8421785a1dbf4e0982b32efa31f181e9e39c2c90cd9c17cfc23e9c0de14d93614200bed66e79b8570c18a31cac84c0ebdfb4ab35b3e76af952bce31ed074203129c9fec6c3c60a7635bc7d8d4d25f93d4b6c53ab0ae8950362c75334443d8b4ed784b545bad39994343b50a9ca6b70be86898af4f2599dad4bc20f4d315c348681e062dcff934b3156f99e5a305113cc5683ba3270a10a12f0d41833790d645cbc527938d4ee388a9e1f9df3867f787e99ddc5092a82f5627bfb6fe72e18024902b98cfe9fc7e763d11b1c46e1507a17f9e71937c92d4f2ddecbcad0847c1e16fc297b461e93d8331754ea155a5fc90c280b44c8f4628d8c083303dfa67f57d82e7d8f4b6d35b91a4dc9b47ca6d027fe50ed38092eb9a9555c22a3dc4880ea997f0ad688503d87aa7a844782483dbabde687f0351740ab0f0753be09a1b18f8f864d85a9d7305f60f814ed7ec468cf06734fadf8b34edb4d81813b2cb9a2475ba93c19a76c803cca8e275227c1f5d39917111a88b2d477e166b6d22ef8b3d32c47adb22750e12606a1170a3f320fa23d256f48229ef173bf22c8799863130b12eb4416b299e42dfd8bc79b3cc938cc0a8360a63149085c063c30bf66d233030429f9a675f048ae1f231e90a616916f3e31241bffe43feb98209d536881c3c532328fe35568ee33c13fa2a56b5d0b5306ac7b3c6ecfddb7017e0c2557f56d1ccbac2226bd84472845887e4c15f091b47b5d5acd8d4cf35ddd0b36f913492ccfac589a1d71c4c866b839d1e500b41970aaacaffc3792a5f7b7bd6cf4150e18234ffaf3531480183e2c35eda32e106a2bfdd35106d2cd8a236639363cdc3454f32149128475caf45562128d95d2d618fa5618cf0afccb6ea82932fb1c965a39c1d7f73f18dbdd944da19b9952ad7dc0081353fe806dab6e2af7674121cea718f31e2600407337641e160d8984989a203410b7c32c995e0c0deab6962e0e9ff22a5b323921d3c95d2b2a78ea3cc4cbdbfb874f45b7494569d8df7a248fd28619ed9d7e0e9e332fd1a628f647af91be7b2d9464464ce0e4b99357f8bf8994582ea6149b61273ea0eb773eb58c5c8b519d5ec9e038106683deb086810b2beb41edee1615258b2447eb0cc7532878bb72d5d63650238712d06fcbb3e520a85e128b07e69b3484b5a6a556e13757bddaec6cc96dc0866d1b003800d1a11f3e357d9bb8eb9908daf314b93434870e0b233cc41686f1084427282b828345ff7f4b6d7edbf8c698c8518efb4f71ac590aacdf918fa130ddaa60b591ad4a83d29248c059837c1d96bfd2a27e6b39a3e0841e8dfd2656720ca3e65c91c0f59ac40cc23cc201bde236a5ccedf4f8e1967f2f3b90c8b3cd3a95c2012bddf9e0063648105b76224fbffacf782e47821266c26d3cb66d1f452c069dd95eca61beb815cc1cd08f8f185762bd0cf2758277a3e10dff41c89453fddf2c9233542dc05088c04be0356661b857b43789d7f90d15a38cd56a0be1573daff90625c382344436544191827c35a0fd653dcad5cc2f9d615b10c42816ccd2708e5c23797052f5724b98ae2516bfaaa193e3314d5a48cd31516fcc7a1abf0d015a9030733514b37612d2e73d0cb5528a53a8eeae27320deabb35799fb84be33213a2640d5ca49b86a0415e9c355412a43d8bf1de31abfcdd1a4df986a43ce385fe6a354e9be037847852481f45e6122dd16db5213deadb23029b6b0e750014c8ed127fec7ea3154e06ea41007a9528f25f7a766dcdb1169387874d71af784e90c7536da743a5b441ccdd76b129ce9ff979ad4465ac1a9287728d65eef1f9dcd6aea89f4c3370576c3260f33ed0451823b4cdfc0e84d971bf317382185585f39fea0418ac77aa22f4eee55573c58b70da0d64ebd63f51997deae9e7a476499c878686b059eed7851b1f0f60a7125fb1e44a5a35a2620afb3e5f2a7d5c2e99d6464de9d60ad0047ea683992c20082f6eeeb12e95eb18f2f28e2a6aaf8cd7db425e6c634e3b1b81fdc5371f782a29d3975be43e2bd73bbd740240b35fa60240db2d0c9719a5dccbea63c3d2408ab50c80903fe3c0a974022657f1f4f5eaf73c73f51e4651974e241039457f6b609d7cc7ad959ef1b009285d65d544bff7889d75421ad9102c4c8302578cd38d946cd468f6eea55e2cc6f27ad438129c8f7a6feb60d2af4ba74aededc6c36d18d3308701c1abcb984'

    # nonce = commitment[:32] # TODO: derive via ECDH with BIP-32 derived private key
    # message = b"My tears are like the quiet drift / Of petals from some magic rose;"
    # extra_commit = b"And all my grief flows from the rift / Of unremembered skies and snows."
    # ret = secp256k1_zkp.rangeproof_sign(value, commitment, blinding_factor, nonce, message, extra_commit)
    # assert ret == 1

def test_balance_blinds():
    amounts_to_blind = [2099999199946660, 2099997399936660, 1100000000]
    blinds = [
        lx('06d23112c6ae181b46780b243d856ed3291b00601e19e52890b90dcdce20a95f'),
        lx('77fde0710ed86ec3040d0b0fa2347588e401ddc70ef9306bc2f1e6fd3c822044'),
        lx('6c40981edaa4ca0f72e670dae452124acb09730add6b81378460d7afc59f0c3a')
    ]
    assetblinds = [
        lx('0129eb8e1126935f1c0632aaff45537a830c4f3d5fcb0820f50ef70b9fb7eae3'),
        lx('bdc95337e02cbfbb58d4ce7cf511c9ff919b61d8aa3d975f33d50b94eb7076b0'),
        lx('90cda608ff97c735fc63dd6932b166c11357eb6f13044281d551989e27249c18')
    ]

    amounts_to_blind = (ctypes.c_uint64 * len(amounts_to_blind))(*amounts_to_blind)
    assetblinds_ptrs = (ctypes.c_char_p*len(assetblinds))()
    for i, ab in enumerate(assetblinds):
        assetblinds_ptrs[i] = ab

    blinds_ptrs = (ctypes.c_char_p*len(blinds))()
    for i, blind in enumerate(blinds):
        b = ctypes.create_string_buffer(blind, 32)
        blinds_ptrs[i] = ctypes.cast(b, ctypes.c_char_p)

    ret = secp256k1.secp256k1_pedersen_blind_generator_blind_sum(
        secp256k1_blind_context,
        amounts_to_blind, assetblinds_ptrs, blinds_ptrs,
        3, 1)
    assert ret
    assert blinds_ptrs[-1][:32].hex() == '08f06eb7ebc9808370ad143542f0db3cfe27a8373efcb463f096f71c71a9c04b'
