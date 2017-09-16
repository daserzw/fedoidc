import json
import os
import shutil
from time import time

import pytest
from fedoidc import ClientMetadataStatement
from fedoidc import test_utils
from fedoidc.entity import FederationEntity
from fedoidc.file_system import FileSystem
from fedoidc.operator import Operator
from fedoidc.provider import Provider
from jwkest import as_unicode
from jwkest import jws

from oic import rndstr
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import AuthzHandling
from oic.utils.http_util import Created
from oic.utils.http_util import Response
from oic.utils.keyio import build_keyjar
from oic.utils.sdb import SessionDB
from oic.utils.sdb import create_session_db
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
        "response": {
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

# Clear out old stuff
for d in ['mds', 'ms_dir', 'ms_path']:
    if os.path.isdir(d):
        shutil.rmtree(d)

MS_DIR = 'ms_dir'

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
                                   signer=signer[OA['sunet']],
                                   fo_bundle=keybundle)

        _sdb = create_session_db(sunet_op, 'hemlighet', 'ordet', {})
        self.op = Provider(sunet_op, _sdb, {},
                           AUTHN_BROKER, USERINFO,
                           AUTHZ, client_authn=verify_client, symkey=SYMKEY,
                           federation_entity=fed_ent)
        self.op.baseurl = self.op.name
        self.op.signer = signer[OA['sunet']]

    def test_create_metadata_statement_request(self):
        _fe = self.op.federation_entity
        statement = self.op.create_providerinfo()
        req = _fe.add_signing_keys(statement)
        assert 'signing_keys' in req

    def test_use_signing_service(self):
        _fe = self.op.federation_entity
        statement = self.op.create_providerinfo()
        req = _fe.add_signing_keys(statement)

        sjwt = _fe.signer.create_signed_metadata_statement(
            req, 'discovery', fos=_fe.signer.metadata_statements.keys(),
            single=True)

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

    def test_provider_endpoint(self):
        pi_resp = self.op.providerinfo_endpoint()

        assert isinstance(pi_resp, Response)
        assert pi_resp.status == "200 OK"
        _info = json.loads(pi_resp.message)
        assert list(_info['metadata_statements'].keys()) == [FO['swamid']]
        _js = jws.factory(_info['metadata_statements'][FO['swamid']])
        assert _js
        assert _js.jwt.headers['alg'] == 'RS256'
        _body = json.loads(as_unicode(_js.jwt.part[1]))
        assert _body['iss'] == self.op.federation_entity.signer.signing_service.iss

    def test_registration_endpoint_no_fed(self):
        request = {'redirect_uris': ['https://example.com/rp']}
        resp = self.op.registration_endpoint(request)
        assert isinstance(resp, Created)
        assert resp.status == "201 Created"
        clresp = json.loads(resp.message)
        assert 'metadata_statements' not in clresp

    def test_registration_endpoint_fed(self):
        request = ClientMetadataStatement(
            redirect_uris= ['https://example.com/rp'])
        rp = Operator(keyjar=keybundle[FO['swamid']], iss=FO['swamid'])
        sms = rp.pack_metadata_statement(request, alg='RS256')
        request = rp.extend_with_ms(request, {FO['swamid']: sms})

        resp = self.op.registration_endpoint(request.to_dict())
        assert isinstance(resp, Created)
        assert resp.status == "201 Created"

        clresp = json.loads(resp.message)
        assert list(clresp['metadata_statements'].keys()) == [FO['swamid']]
