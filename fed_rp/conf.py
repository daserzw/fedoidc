__author__ = 'roland'

BASEURL = "https://localhost"

# If BASE is https these has to be specified
SERVER_KEY = 'certs/key.pem'
SERVER_CERT = 'certs/cert.pem'
CA_BUNDLE = None

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "scope": ["openid", "email", "phone", "profile"],
    "response_type": ["code"],
    # "user_info": {
    #     "name": None,
    #     "email": None,
    #     "nickname": None
    # },
    # "request_method": "param"
}

SIG_DEF_KEYS = [{"type": "RSA", "key": "keys/rp_key.pem", "use": ["sig"]}]
MS_DIR = '../fed_conf/ms_dir'
JWKS_DIR = '../fed_conf/fo_jwks'

# KEYDEFS= [{"type": "RSA", "key": "keys/sig_key.pem", "use": ["sig"]}]
