__author__ = 'roland'

SIGNER_ID = "https://localhost"

# If BASE is https these has to be specified
SERVER_KEY = 'certs/key.pem'
SERVER_CERT = 'certs/cert.pem'
CA_BUNDLE = None

KEYDEFS= [{"type": "RSA", "key": "keys/{}.key", "use": ["sig"]}]

MS_DIR = './ms_dir'
