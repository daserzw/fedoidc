#!/usr/bin/env python3
import json
import os
import shutil
from urllib.parse import quote_plus

from fedoidc import test_utils

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

TOOL_ISS = 'https://localhost'

FO = {'swamid': 'https://swamid.sunet.se'}

OA = {'sunet': 'https://sunet.se'}

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
        "response": {
            FO['swamid']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'response'},
                 'signer': FO['swamid'], 'uri': False},
            ]
        },
    }
}

# Clear out old stuff
for d in ['mds', 'ms']:
    if os.path.isdir(d):
        shutil.rmtree(d)

liss = list(FO.values())
liss.extend(list(OA.values()))

signers, keybundle = test_utils.setup(
    KEYDEFS, TOOL_ISS, liss, ms_path='ms', csms_def=SMS_DEF,
    mds_dir='mds', base_url='https://localhost')

exp = 'jwks_bundle'
if not os.path.isdir(exp):
    os.mkdir(exp)
os.chdir(exp)
for iss, kj in keybundle.items():
    fn = quote_plus(iss)
    fp = open(fn, 'w')
    fp.write(json.dumps(kj.export_jwks(issuer=iss)))
    fp.close()
os.chdir('..')