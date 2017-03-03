from fedoidc.entity import FederationEntity
from fedoidc.provider import Provider
from fedoidc.test_utils import setup

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
    'sunet':{
        'sunet.swamid': [
            {'request': {}, 'requester': OA['sunet'],
             'signer_add': {}, 'signer': FO['swamid']},
        ],
        'sunet.feide': [
            {'request': {}, 'requester': OA['sunet'],
             'signer_add': {}, 'signer': FO['feide']},
        ],
    },
    'uninett':{
        'uninett.feide': [
            {'request': {}, 'requester': OA['uninett'],
             'signer_add': {}, 'signer': FO['feide']},
        ]
    }
}
liss = list(FO.values())
liss.extend(list(OA.values()))
liss.extend(list(EO.values()))

signer, keybundle = setup(KEYDEFS, TOOL_ISS, liss, SMS_DEF, OA, 'ms_dir')


def test_parse_pi():
    sunet_op = 'https://www.sunet.se/op'

    _kj = build_keyjar(KEYDEFS)[1]
    fed_ent = FederationEntity(None, keyjar=_kj, iss=sunet_op,
                               signer={'uninett': signer['uninett']})

    op = Provider(sunet_op, None, {},
                  None, {}, None, client_authn=None, symkey=SYMKEY,
                  federation_entity=fed_ent)
    op.baseurl = op.name
