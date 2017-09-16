#!/usr/bin/env python3
import argparse
import json
import os

from urllib.parse import quote_plus

from fedoidc import MetadataStatement
from fedoidc.signing_service import InternalSigningService
from fedoidc.signing_service import Signer
from oic.utils.keyio import KeyJar

parser = argparse.ArgumentParser()
parser.add_argument('-i', dest='issuer', help="issuer id of the OP")
parser.add_argument('-c', dest='context', help="OIDC operation")
parser.add_argument('-t', dest='target')
parser.add_argument(dest="filename")
args = parser.parse_args()

oa = args.issuer
qpoa = quote_plus(oa)

_kj = KeyJar()
_jwks = json.loads(open(os.path.join('fo_jwks',qpoa)).read())
_kj.import_jwks(_jwks, oa)
sign_serv = InternalSigningService(iss=oa, signing_keys=_kj)
signer = Signer(sign_serv, ms_dir=os.path.join('ms', qpoa))

_req = open(args.filename, 'r').read()
_msg = MetadataStatement()
_msg.from_json(_req)
_res = signer.create_signed_metadata_statement(_msg, context=args.context)

for iss, sms in _res.items():
    _qp = quote_plus(iss)
    _dn = os.path.join(args.target, qpoa, args.context)
    if not os.path.isdir(_dn):
        os.makedirs(_dn)
    _fn = os.path.join(_dn, _qp)
    _fp = open(_fn, 'w')
    _fp.write(sms)
    _fp.close()