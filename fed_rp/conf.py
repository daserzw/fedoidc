__author__ = 'roland'

PORT = 8666
BASE = "https://localhost:" + str(PORT) + "/"

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
