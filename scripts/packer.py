import argparse
import json

from fedoidc import MetadataStatement, read_jwks_file
from fedoidc.operator import Operator


parser = argparse.ArgumentParser()
parser.add_argument('-j', dest='jwks')
parser.add_argument('-i', dest='iss')
parser.add_argument('-r', dest='req')
args = parser.parse_args()

kj = read_jwks_file(args.jwks)
op = Operator(keyjar=kj, iss=args.iss)

_req = json.loads(open(args.req).read())
req = MetadataStatement(**_req)
print(op.pack_metadata_statement(req))
