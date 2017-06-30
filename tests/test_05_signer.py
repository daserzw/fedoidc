import os
import shutil

from fedoidc import MetadataStatement
from fedoidc import test_utils

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

# Clear out old stuff
for d in ['mds', 'ms_dir', 'ms_path']:
    if os.path.isdir(d):
        shutil.rmtree(d)

liss = list(FO.values())
liss.extend(list(OA.values()))

signer, keybundle = test_utils.setup(
    KEYDEFS, TOOL_ISS, liss, ms_path='ms_dir_10', csms_def=SMS_DEF,
    mds_dir='mds_10', base_url='https://localhost')


def test_signer():
    items = signer[OA['sunet']].items()
    assert set(list(items.keys())) == {'discovery', 'registration'}
    assert set(list(items['discovery'])) == {FO['swamid']}


def test_create_sms():
    s = signer[OA['sunet']]
    req = MetadataStatement(issuer='https://example.org/op')
    r = s.create_signed_metadata_statement(req, 'discovery')
    assert r
