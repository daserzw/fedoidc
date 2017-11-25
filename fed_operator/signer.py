#!/usr/bin/env python3
from urllib.parse import quote_plus

import argparse
import json

from fedoidc import MetadataStatement
from fedoidc.signing_service import InternalSigningService
from fedoidc.signing_service import Signer

from oic.utils.keyio import build_keyjar

KEYDEFS= [{"type": "RSA", "key": "keys/{}.key", "use": ["sig"]}]

parser = argparse.ArgumentParser()
parser.add_argument('-i', dest='iss')
parser.add_argument('-m', dest='ms_dir', default='ms')
parser.add_argument(dest="statement")
args = parser.parse_args()

_keydefs = []
for spec in KEYDEFS:
    spec['key'] = spec['key'].format(quote_plus(args.iss))
    _keydefs.append(spec)

sig_keys = build_keyjar(KEYDEFS)[1]
signing_service = InternalSigningService(iss=args.iss, signing_keys=sig_keys)
signer = Signer(signing_service, args.ms_dir)

_args = json.loads(open(args.statement,'r').read())
_mds = MetadataStatement(**_args)

_mds.verify()

print(signer.create_signed_metadata_statement(_mds, single=True))
