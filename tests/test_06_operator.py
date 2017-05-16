import os

import time
from oic.utils.keyio import build_keyjar

from fedoidc.operator import FederationOperator

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]


def test_key_rotation():
    _keyjar = build_keyjar(KEYDEFS)[1]
    fo = FederationOperator(iss='https://example.com/op', keyjar=_keyjar,
                            keyconf=KEYDEFS, remove_after=1)
    fo.rotate_keys()
    assert len(fo.keyjar.get_issuer_keys('')) == 4
    time.sleep(1)
    fo.rotate_keys()
    assert len(fo.keyjar.get_issuer_keys('')) == 4
