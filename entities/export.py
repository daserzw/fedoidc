import argparse
import json
import os
from urllib.parse import quote_plus

from oic.utils.keyio import KeyJar

parser = argparse.ArgumentParser()
parser.add_argument(dest="nickname")
args = parser.parse_args()

if not os.path.isdir(args.nickname):
    print('No such entity')
    exit(-1)

kj = KeyJar()
iss = open(os.path.join(args.nickname, 'iss')).read()
imp_jwks = open(os.path.join(args.nickname, 'jwks')).read()
kj.import_jwks(jwks=json.loads(imp_jwks), issuer=iss)

exp_jwks = kj.export_jwks(issuer=iss)
fname = quote_plus(iss)

fp = open(fname, 'w')
fp.write(json.dumps(exp_jwks))
fp.close()
