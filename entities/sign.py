import argparse
import json
import os

from oic.utils.keyio import KeyJar

from fedoidc import MetadataStatement
from fedoidc.signing_service import InternalSigningService

parser = argparse.ArgumentParser()
parser.add_argument('-r', dest='request')
parser.add_argument('-a', dest='alg', default='RS256')
parser.add_argument(dest="nickname")
args = parser.parse_args()

if not os.path.isdir(args.nickname):
    print('No such entity')
    exit(-1)

kj = KeyJar()
iss = open(os.path.join(args.nickname, 'iss')).read()
jwks = open(os.path.join(args.nickname, 'jwks')).read()
kj.import_jwks(jwks=json.loads(jwks), issuer=iss)

sigserv = InternalSigningService(iss=iss, signing_keys=kj, alg=args.alg)

msg = MetadataStatement()
msg.from_json(open(args.request).read())

print(sigserv(msg))
