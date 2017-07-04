from oic.oauth2 import Message

from fedoidc import MetadataStatement

from fedoidc.operator import Operator
from oic.utils.keyio import build_keyjar

from fedoidc.bundle import JWKSBundle

from fedoidc.entity import FederationEntity

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]


def test_get_metadata_statement():
    jb = JWKSBundle('')
    for iss in ['https://example.org', 'https://example.com']:
        jb[iss] = build_keyjar(KEYDEFS)[1]

    op = Operator(keyjar=jb['https://example.com'], iss='https://example.com/')
    req = MetadataStatement(foo='bar')
    sms = op.pack_metadata_statement(req, alg='RS256')
    sms_dir = {'https://example.com': sms}
    req['metadata_statements'] = Message(**sms_dir)
    ent = FederationEntity(None, fo_bundle=jb)
    loe = ent.get_metadata_statement(req)
    assert loe