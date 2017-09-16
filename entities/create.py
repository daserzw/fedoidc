#!/usr/bin/env python3
import argparse
import json
import os

from oic.utils.keyio import build_keyjar

parser = argparse.ArgumentParser()
parser.add_argument('-i', dest='iss')
parser.add_argument('-k', dest='keytype', default='RSA')
parser.add_argument(dest="nickname")
args = parser.parse_args()

if not os.path.isdir(args.nickname):
    os.makedirs(args.nickname)

keyspec = [{"type": args.keytype, 'name': '', "use": ["sig"]}]

kj = build_keyjar(keyspec)[1]

jwks = kj.export_jwks(private=True)
fp = open(os.path.join(args.nickname, 'jwks'), 'w')
fp.write(json.dumps(jwks))
fp.close()

if not args.iss:
    print('No Issuer ID given')
else:
    fp = open(os.path.join(args.nickname, 'iss'), 'w')
    fp.write(args.iss)
    fp.close()
