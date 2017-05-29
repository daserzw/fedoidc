import os
import shutil

from fedoidc import test_utils, MetadataStatement
from fedoidc.file_system import FileSystem

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
                 'signer': FO['swamid']},
            ]
        },
        "registration": {
            FO['swamid']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'registration'},
                 'signer': FO['swamid']},
            ]
        },
    }
}

SMSU_DEF = {
    OA['sunet']: {
        "discovery": {
            FO['feide']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'discovery'},
                 'signer': FO['feide']},
            ]
        },
        "registration": {
            FO['feide']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'registration'},
                 'signer': FO['feide']},
            ]
        },
    }
}

fs = FileSystem('ms_dir')
fs.reset()

liss = list(FO.values())
liss.extend(list(OA.values()))

signer, keybundle = test_utils.setup(
    KEYDEFS, TOOL_ISS, liss, csms_def=SMS_DEF, ms_path='ms_dir',
    csmsu_def=SMSU_DEF, mds_dir='mds', base_url='https://localhost')


def test_signer():
    items = signer[OA['sunet']].items()
    assert set(list(items.keys())) == {'discovery', 'registration'}
    assert set(list(items['discovery'])) == {FO['feide'], FO['swamid']}


def test_create_sms():
    s = signer[OA['sunet']]
    req = MetadataStatement(issuer='https://example.org/op')
    r = s.create_signed_metadata_statement(req, 'discovery')
    assert r
