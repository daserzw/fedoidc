FO = {'swamid': 'https://swamid.sunet.se'}

OA = {'sunet': 'https://sunet.se'}

SMS_DEF = {
    OA['sunet']: {
        "discovery": {
            FO['swamid']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'discovery'},
                 'signer': FO['swamid'], 'uri': False},
            ]
        },
        "registration": {
            FO['swamid']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'registration'},
                 'signer': FO['swamid'], 'uri': False},
            ]
        },
        "response": {
            FO['swamid']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'response'},
                 'signer': FO['swamid'], 'uri': False},
            ]
        }
    }
}

MS_PATH = 'ms'
MDS_DIR = 'mds'
BASE_URL = 'https://localhost'
