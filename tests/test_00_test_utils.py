from oic.utils.keyio import build_keyjar, KeyJar

from fedoidc.test_utils import make_jwks_bundle, make_fs_jwks_bundle

TEST_ISS = "https://test.example.com"
KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

SIGN_KEYJAR = build_keyjar(KEYDEFS)[1]


def test_make_jwks_bundle():
    """
    testing in-memory JWKS bundle
    """
    liss = ['https://foo.example.com', 'https://bar.example.com']
    jb = make_jwks_bundle(TEST_ISS, liss, SIGN_KEYJAR, KEYDEFS)
    assert set(jb.keys()) == set(liss)
    for iss in liss:
        _kj = jb[iss]
        assert isinstance(_kj, KeyJar)
        assert len(_kj.keys()) == 1  # Issuers
        assert list(_kj.keys())[0] == iss
        _keys = _kj.get_issuer_keys(iss)
        assert len(_keys) == 2
        assert _kj.keys_by_alg_and_usage(iss, 'RS256', 'sig')
        assert _kj.keys_by_alg_and_usage(iss, 'ES256', 'sig')


def test_make_fs_jwks_bundle():
    """
    testing on disc JWKS bundle
    """
    liss = ['https://foo.example.com', 'https://bar.example.com']
    jb = make_fs_jwks_bundle(TEST_ISS, liss, SIGN_KEYJAR, KEYDEFS)
    assert set(jb.keys()) == set(liss)
    for iss in liss:
        _kj = jb[iss]
        assert isinstance(_kj, KeyJar)
        assert len(_kj.keys()) == 1  # Issuers
        assert list(_kj.keys())[0] == iss
        _keys = _kj.get_issuer_keys(iss)
        assert len(_keys) == 2
        assert _kj.keys_by_alg_and_usage(iss, 'RS256', 'sig')
        assert _kj.keys_by_alg_and_usage(iss, 'ES256', 'sig')
