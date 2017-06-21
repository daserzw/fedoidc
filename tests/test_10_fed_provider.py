import json
import os
import shutil
from time import time

import pytest

from fedoidc import test_utils
from fedoidc.file_system import FileSystem

from fedoidc.entity import FederationEntity
from fedoidc.provider import Provider
from jwkest import jws, as_unicode

from oic import rndstr
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import AuthzHandling
from oic.utils.keyio import build_keyjar
from oic.utils.sdb import SessionDB

# Create JWKS bundle
from oic.utils.userinfo import UserInfo

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

TOOL_ISS = 'https://localhost'

FO = {'swamid': 'https://swamid.sunet.se', 'feide': 'https://www.feide.no'}

OA = {'sunet': 'https://sunet.se'}

IA = {}

SMS_DEF = {
    OA['sunet']: {
        "discovery": {
            FO['swamid']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'discovery'},
                 'signer': FO['swamid'], 'uri': False},
            ]
        },
        "registration": {
            FO['swamid']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'registration'},
                 'signer': FO['swamid'], 'uri': False},
            ]
        },
    }
}

MS_DIR = 'ms_dir_10'
fs = FileSystem(MS_DIR)
fs.reset()

if os.path.isdir('mds'):
    shutil.rmtree('mds')

liss = list(FO.values())
liss.extend(list(OA.values()))

signer, keybundle = test_utils.setup(
    KEYDEFS, TOOL_ISS, liss, ms_path=MS_DIR, csms_def=SMS_DEF,
    mds_dir='mds', base_url='https://localhost')


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        if cookie == "FAIL":
            return None, 0
        else:
            return {"uid": self.user}, time()


AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add("UNDEFINED", DummyAuthn(None, "username"))

# dealing with authorization
AUTHZ = AuthzHandling()
SYMKEY = rndstr(16)  # symmetric key used to encrypt cookie info

USERDB = {
    "user": {
        "name": "Hans Granberg",
        "nickname": "Hasse",
        "email": "hans@example.org",
        "verified": False,
        "sub": "user"
    },
    "username": {
        "name": "Linda Lindgren",
        "nickname": "Linda",
        "email": "linda@example.com",
        "verified": True,
        "sub": "username"
    }
}

USERINFO = UserInfo(USERDB)


class TestProvider(object):
    @pytest.fixture(autouse=True)
    def create_provider(self):
        sunet_op = 'https://www.sunet.se/op'

        _kj = build_keyjar(KEYDEFS)[1]
        fed_ent = FederationEntity(None, keyjar=_kj, iss=sunet_op,
                                   signer=signer[OA['sunet']])

        self.op = Provider(sunet_op, SessionDB(sunet_op), {},
                           AUTHN_BROKER, USERINFO,
                           AUTHZ, client_authn=verify_client, symkey=SYMKEY,
                           federation_entity=fed_ent)
        self.op.baseurl = self.op.name

    def test_create_metadata_statement_request(self):
        _fe = self.op.federation_entity
        statement = self.op.create_providerinfo()
        req = _fe.create_metadata_statement_request(statement)
        assert 'signing_keys' in req

    def test_use_signing_service(self):
        _fe = self.op.federation_entity
        statement = self.op.create_providerinfo()
        req = _fe.create_metadata_statement_request(statement)

        sjwt = _fe.signer.create_signed_metadata_statement(
            req, 'discovery', fos=_fe.signer.metadata_statements.keys())

        assert sjwt

        # should be a signed JWT

        _js = jws.factory(sjwt)
        assert _js
        assert _js.jwt.headers['alg'] == 'RS256'
        _req = json.loads(as_unicode(_js.jwt.part[1]))
        assert _req['iss'] == OA['sunet']

    def test_create_fed_provider_info(self):
        fedpi = self.op.create_fed_providerinfo()

        assert 'signing_keys' not in fedpi

        assert len(fedpi['metadata_statements']) == 1
        _js = jws.factory(fedpi['metadata_statements'][FO['swamid']])
        assert _js
        assert _js.jwt.headers['alg'] == 'RS256'
        _body = json.loads(as_unicode(_js.jwt.part[1]))
        assert _body['iss'] == self.op.federation_entity.signer.signing_service.iss
