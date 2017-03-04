from oic.utils.http_util import Created

from fedoidc.bundle import JWKSBundle

from fedoidc.client import Client

from fedoidc.entity import FederationEntity
from fedoidc.provider import Provider
from fedoidc import test_utils, ProviderConfigurationResponse, MetadataStatement

from oic import rndstr
from oic.utils.keyio import build_keyjar

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

SYMKEY = rndstr(16)

TOOL_ISS = 'https://localhost'

FO = {'swamid': 'https://swamid.sunet.se', 'feide': 'https://www.feide.no'}

OA = {'sunet': 'https://sunet.se', 'uninett': 'https://uninett.no'}

IA = {}

EO = {'sunet.op': 'https://sunet.se/op',
      'foodle.rp': 'https://foodle.uninett.no'}

BASE = {'sunet.op': EO['sunet.op']}

SMS_DEF = {
    'sunet': {
        FO['swamid']: [
            {'request': {}, 'requester': OA['sunet'],
             'signer_add': {}, 'signer': FO['swamid']},
        ],
        FO['feide']: [
            {'request': {}, 'requester': OA['sunet'],
             'signer_add': {}, 'signer': FO['feide']},
        ],
    },
    'uninett': {
        FO['feide']: [
            {'request': {}, 'requester': OA['uninett'],
             'signer_add': {}, 'signer': FO['feide']},
        ]
    }
}
liss = list(FO.values())
liss.extend(list(OA.values()))
liss.extend(list(EO.values()))

signer, keybundle = test_utils.setup(KEYDEFS, TOOL_ISS, liss, SMS_DEF, OA,
                                     'ms_dir')

fo_keybundle = JWKSBundle('https://example.com')
for iss in FO.values():
    fo_keybundle[iss] = keybundle[iss]


def test_parse_pi():
    sunet_op = 'https://www.sunet.se/op'

    _kj = build_keyjar(KEYDEFS)[1]
    op_fed_ent = FederationEntity(None, keyjar=_kj, iss=sunet_op,
                                  signer=signer['https://sunet.se'],
                                  fo_bundle=fo_keybundle)

    op = Provider(sunet_op, None, {},
                  None, {}, None, client_authn=None, symkey=SYMKEY,
                  federation_entity=op_fed_ent)
    op.baseurl = op.name

    uninett_op = 'https://foodle.uninett.no'

    _kj = build_keyjar(KEYDEFS)[1]
    rp_fed_ent = FederationEntity(None, keyjar=_kj, iss=uninett_op,
                                  signer=signer['https://uninett.no'],
                                  fo_bundle=fo_keybundle)

    rp = Client(federation_entity=rp_fed_ent, fo_priority=list(FO.values()))

    pi = op.create_fed_providerinfo()

    assert pi

    rp.parse_federation_provider_info(pi)

    assert len(rp.provider_federations) == 2
    assert set(rp.provider_federations.keys()) == {'https://swamid.sunet.se',
                                                   'https://www.feide.no'}

    req = rp.federated_client_registration_request(
        redirect_uris='https://foodle.uninett.no/authz',
        claims=['openid', 'email', 'phone']
    )

    assert req

    resp = op.registration_endpoint(req.to_dict())

    assert isinstance(resp, Created)
