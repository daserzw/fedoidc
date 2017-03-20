# -*- coding: utf-8 -*-

keys = [
    {"type": "RSA", "key": "keys/enc_key.pem", "use": ["enc"]},
    {"type": "RSA", "key": "keys/sig_key.pem", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]}
]

ISSUER='https://localhost'
SERVICE_URL = "{issuer}/verify"

#Only Username and password.
AUTHENTICATION = {
    "UserPassword": {"ACR": "PASSWORD", "WEIGHT": 1, "URL": SERVICE_URL,
                     "END_POINTS": ["verify"]}
}

PASSWD = {
    "diana": "krall",
    "babs": "howes",
    "upper": "crust"
}

JWKS_FILE_NAME = "static/jwks.json"
JWKS_DIR = 'jwks'
SIG_KEYS_DEFS = [{"type": "RSA", "key": "keys/fed_sig.pem", "use": ["sig"]}]
SIGNER_ID = 'https://example.com'
MS_DIR = 'ms_dir'
FO_PRIORITY = []

MAKO_ROOT = '.'

COOKIENAME = 'pyoic'
COOKIETTL = 4 * 60  # 4 hours
SYM_KEY = "SoLittleTime,Got"

SERVER_CERT = "certs/cert.pem"
SERVER_KEY = "certs/key.pem"
#CA_BUNDLE="certs/chain.pem"
CA_BUNDLE = None

# =======  SIMPLE DATABASE ==============

USERINFO = "SIMPLE"

USERDB = {
    "diana": {
        "sub": "dikr0001",
        "name": "Diana Krall",
        "given_name": "Diana",
        "family_name": "Krall",
        "nickname": "Dina",
        "email": "diana@example.org",
        "email_verified": False,
        "phone_number": "+46 90 7865000",
        "address": {
            "street_address": "Umeå Universitet",
            "locality": "Umeå",
            "postal_code": "SE-90187",
            "country": "Sweden"
        },
    },
    "babs": {
        "sub": "babs0001",
        "name": "Barbara J Jensen",
        "given_name": "Barbara",
        "family_name": "Jensen",
        "nickname": "babs",
        "email": "babs@example.com",
        "email_verified": True,
        "address": {
            "street_address": "100 Universal City Plaza",
            "locality": "Hollywood",
            "region": "CA",
            "postal_code": "91608",
            "country": "USA",
        },
    },
    "upper": {
        "sub": "uppe0001",
        "name": "Upper Crust",
        "given_name": "Upper",
        "family_name": "Crust",
        "email": "uc@example.com",
        "email_verified": True,
    }
}

