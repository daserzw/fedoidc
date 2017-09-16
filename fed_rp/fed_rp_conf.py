__author__ = 'roland'

BASEURL = "https://localhost"

# If BASE is https these has to be specified
SERVER_KEY = 'certs/key.pem'
SERVER_CERT = 'certs/cert.pem'
CA_BUNDLE = None

CONSUMER_CONFIG = {
    #"authz_page": "/authz",
    "scope": ["openid", "email", "phone", "profile"],
    "response_type": ["code"],
}

SIG_DEF_KEYS = [{"type": "RSA", "key": "keys/rp_key.pem", "use": ["sig"]}]
MS_DIR = '../ms'
JWKS_DIR = 'jwks_dir'
FO_JWKS = '../fo_jwks'

# Priority order between the federations.
# MUST contain all the federations this OP belongs to.
PRIORITY = ['https://swamid.sunet.se']

# Superior
SUPERIOR = 'https://sunet.se'
