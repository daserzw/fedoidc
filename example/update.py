from urllib.parse import quote_plus, unquote_plus

from fedoidc.bundle import FSJWKSBundle
from fedoidc.operator import Operator
from fedoidc.test_utils import setup_ms

import fo_conf

jb = FSJWKSBundle('', fdir='fo_jwks',
                  key_conv={'to': quote_plus, 'from': unquote_plus})

operator = {}

for entity, _keyjar in jb.items():
    operator[entity] = Operator(iss=entity, keyjar=_keyjar)


signers = setup_ms(fo_conf.SMS_DEF, fo_conf.MS_PATH, fo_conf.MDS_DIR,
                   fo_conf.BASE_URL, operator)