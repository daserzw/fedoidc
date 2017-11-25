#!/usr/bin/env python3
import json
import os
import shutil
from urllib.parse import quote_plus

from fedoidc import test_utils

import fo_conf

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

TOOL_ISS = 'https://localhost'

# Clear out old stuff
for d in ['mds', 'ms']:
    if os.path.isdir(d):
        shutil.rmtree(d)

liss = list(fo_conf.FO.values())
liss.extend(list(fo_conf.OA.values()))

signers, keybundle = test_utils.setup(
    KEYDEFS, TOOL_ISS, liss, ms_path=fo_conf.MS_PATH, csms_def=fo_conf.SMS_DEF,
    mds_dir=fo_conf.MDS_DIR, base_url=fo_conf.BASE_URL)

exp = 'jwks_bundle'
if not os.path.isdir(exp):
    os.mkdir(exp)
os.chdir(exp)
for iss, kj in keybundle.items():
    fn = quote_plus(iss)
    fp = open(fn, 'w')
    fp.write(json.dumps(kj.export_jwks(issuer=iss)))
    fp.close()
os.rmdir('fo_jwks')
os.chdir('..')