#!/usr/bin/env python3
import argparse
import json

from fedoidc import read_jwks_file
from fedoidc.bundle import JWKSBundle
from fedoidc.operator import Operator


parser = argparse.ArgumentParser()
parser.add_argument('-j', dest='jwks',
                    help="A JWKS file that contains the federation operators public keys")
parser.add_argument('-r', dest='req_jws', help="The message as a JWS")
parser.add_argument('-R', dest='req_json', help="The message as a JSON doc")
parser.add_argument('-f', dest='fo', help='The identifier of the Federation')
parser.add_argument('-l', dest='flatten', action='store_true',
                    help="Flatten the compounded metadata statement")
args = parser.parse_args()

kj = read_jwks_file(args.jwks)

_bundle = JWKSBundle('')
_bundle[args.fo] = kj

op = Operator(jwks_bundle=_bundle)

if args.req_jws:
    _fo, _req = open(args.req).read().rsplit(':', 1)
    _bundle[_fo] = kj

    res = op.unpack_metadata_statement(jwt_ms=_req.strip())
elif args.req_json:
    _req = json.loads(open(args.req_json).read())
    res = op.unpack_metadata_statement(json_ms=_req)
else:
    raise Exception('Need one of -r or -R')

print(res.result)

loe = op.evaluate_metadata_statement(res.result)

if loe and loe[0].le:
    print(loe[0].le)
else:
    print('No trusted claims')