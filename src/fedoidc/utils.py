import json

from jwkest import as_unicode
from oic.oic import JasonWebToken
from oic.utils.jwt import JWT

from fedoidc import MetadataStatement
from fedoidc.bundle import jwks_to_keyjar
from jwkest.jws import JWS, factory


def self_sign_jwks(keyjar, iss, kid='', lifetime=3600):
    """
    Create a signed JWT containing a JWKS. The JWT is signed by one of the
    keys in the JWKS.

    :param keyjar: A KeyJar instance with at least one private signing key
    :param iss: issuer of the JWT, should be the owner of the keys
    :param kid: A key ID if a special key should be used otherwise one
        is picked at random.
    :param lifetime: The lifetime of the signed JWT
    :return: A signed JWT
    """

    # _json = json.dumps(jwks)
    _jwt = JWT(keyjar, iss=iss, lifetime=lifetime)

    jwks = keyjar.export_jwks(issuer=iss)

    return _jwt.pack(owner=iss, jwks=jwks, kid=kid)


def verify_self_signed_jwks(sjwt):
    """
    Verify the signature of a signed JWT containing a JWKS.
    The JWT is signed by one of the keys in the JWKS. 
    In the JWT the JWKS is stored using this format ::
    
        'jwks': {
            'keys': [ ]
        }

    :param sjwt: Signed Jason Web Token
    :return: Dictionary containing 'jwks' (the JWKS) and 'iss' (the issuer of 
        the JWT)
    """

    _jws = factory(sjwt)
    _json = _jws.jwt.part[1]
    _body = json.loads(as_unicode(_json))
    iss = _body['iss']
    _jwks = _body['jwks']

    _kj = jwks_to_keyjar(_jwks, iss)

    try:
        _kid = _jws.jwt.headers['kid']
    except KeyError:
        _keys = _kj.get_signing_key(owner=iss)
    else:
        _keys = _kj.get_signing_key(owner=iss, kid=_kid)

    _ver = _jws.verify_compact(sjwt, _keys)
    return {'jwks': _ver['jwks'], 'iss': iss}


def request_signed_by_signing_keys(keyjar, msreq, iss, lifetime, kid=''):
    """
    A metadata statement signing request with 'signing_keys' signed by one
    of the keys in 'signing_keys'.

    :param keyjar: A KeyJar instance with the private signing key
    :param msreq: Metadata statement signing request. A MetadataStatement 
    instance.
    :param iss: Issuer of the signing request also the owner of the signing 
    keys.
    :return: Signed JWT where the body is the metadata statement
    """

    try:
        jwks_to_keyjar(msreq['signing_keys'], iss)
    except KeyError:
        jwks = keyjar.export_jwks(issuer=iss)
        msreq['signing_keys'] = jwks

    _jwt = JWT(keyjar, iss=iss, lifetime=lifetime)

    return _jwt.pack(owner=iss, kid=kid, **msreq.to_dict())


def verify_request_signed_by_signing_keys(smsreq):
    """
    Verify that a JWT is signed with a key that is inside the JWT.
    
    :param smsreq: Signed Metadata Statement signing request
    :return: Dictionary containing 'ms' (the signed request) and 'iss' (the
        issuer of the JWT).
    """

    _jws = factory(smsreq)
    _json = _jws.jwt.part[1]
    _body = json.loads(as_unicode(_json))
    iss = _body['iss']
    _jwks = _body['signing_keys']

    _kj = jwks_to_keyjar(_jwks, iss)

    try:
        _kid = _jws.jwt.headers['kid']
    except KeyError:
        _keys = _kj.get_signing_key(owner=iss)
    else:
        _keys = _kj.get_signing_key(owner=iss, kid=_kid)

    _ver = _jws.verify_compact(smsreq, _keys)
    # remove the JWT specific claims
    for k in JasonWebToken.c_param.keys():
        try:
            del _ver[k]
        except KeyError:
            pass
    try:
        del _ver['kid']
    except KeyError:
        pass

    return {'ms': MetadataStatement(**_ver), 'iss': iss}
