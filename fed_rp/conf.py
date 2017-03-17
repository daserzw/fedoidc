__author__ = 'roland'

BASEURL = "https://localhost"

# If BASE is https these has to be specified
SERVER_KEY = 'certs/key.pem'
SERVER_CERT = 'certs/cert.pem'
CA_BUNDLE = None

# information used when registering the client
ME = {
    "application_type": "web",
    "application_name": "idpproxy",
    "contacts": ["ops@example.com"],
}

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "flow_type": "code",
    "scope": ["openid", "profile", "email", "address", "phone"],
    "response_type": "code",
}

KEYDEFS= [{"type": "RSA", "key": "keys/sig_key.pem", "use": ["sig"]}]
MS_DIR = './ms_dir'
