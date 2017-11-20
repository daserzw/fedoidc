#!/usr/bin/env python3
import argparse
import json

from fedoidc import MetadataStatement, read_jwks_file
from fedoidc.operator import Operator


parser = argparse.ArgumentParser()
parser.add_argument('-j', dest='jwks')
parser.add_argument('-i', dest='iss')
parser.add_argument('-r', dest='req')
parser.add_argument('-l', dest='lifetime', default=86400, type=int)
parser.add_argument('-f', dest='fo')
args = parser.parse_args()

kj = read_jwks_file(args.jwks)
op = Operator(keyjar=kj, iss=args.iss, lifetime=args.lifetime)

_req = json.loads(open(args.req).read())
req = MetadataStatement(**_req)
if args.fo:
    print('{}:{}'.format(args.fo, op.pack_metadata_statement(req)))
else:
    print('{}:{}'.format(args.iss, op.pack_metadata_statement(req)))