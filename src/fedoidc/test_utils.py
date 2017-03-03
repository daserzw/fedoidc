import copy
import os

from urllib.parse import quote_plus
from urllib.parse import unquote_plus

from fedoidc import MetadataStatement
from fedoidc.bundle import FSJWKSBundle, JWKSBundle
from fedoidc.bundle import keyjar_to_jwks_private
from fedoidc.operator import Operator

from oic.utils.keyio import build_keyjar


def make_fs_jwks_bundle(iss, fo_liss, sign_keyjar, keydefs, base_path=''):
    """
    Given a list of Federation identifiers creates a FSJWKBundle containing all
    the signing keys.

    :param iss: The issuer ID of the entity owning the JWKSBundle
    :param fo_liss: List with federation identifiers as keys
    :param sign_keyjar: Keys that the JWKSBundel owner can use to sign
        an export version of the JWKS bundle.
    :param keydefs: What type of keys that should be created for each
        federation. The same for all of them.
    :param base_path: Where the pem versions of the keys are stored as files
    :return: A FSJWKSBundle instance.
    """
    jb = FSJWKSBundle(iss, sign_keyjar, 'fo_jwks',
                      key_conv={'to': quote_plus, 'from': unquote_plus})

    # Need to save the private parts on disc
    jb.bundle.value_conv['to'] = keyjar_to_jwks_private

    for entity in fo_liss:
        _name = entity.replace('/', '_')
        try:
            _ = jb[entity]
        except KeyError:
            fname = os.path.join(base_path, 'keys', "{}.key".format(_name))
            _keydef = copy.deepcopy(keydefs)
            _keydef[0]['key'] = fname

            _jwks, _keyjar, _kidd = build_keyjar(_keydef)
            jb[entity] = _keyjar

    return jb


def make_jwks_bundle(iss, fo_liss, sign_keyjar, keydefs, base_path=''):
    """
    Given a list of Federation identifiers creates a FSJWKBundle containing all
    the signing keys and a dictionary with Operator instances representing all
    the FOs.

    :param iss: The issuer ID of the entity owning the JWKSBundle
    :param fo_liss: List of federation identifiers
    :param sign_keyjar: Keys that the JWKSBundel owner can use to sign
        an export version of the JWKS bundle.
    :param keydefs: What type of keys that should be created for each
        federation. The same for all of them.
    :return: A tuple with a JWKSBundle instance and an operator dictionary.
    """
    jb = JWKSBundle(iss, sign_keyjar)

    for entity in fo_liss:
        _keydef = copy.deepcopy(keydefs)
        _jwks, _keyjar, _kidd = build_keyjar(_keydef)
        jb[entity] = _keyjar

    return jb


def make_ms(desc, ms, root, leaf, operator):
    """
    Construct a signed metadata statement

    :param desc: A description of who wants who to signed what.
        represented as a dictionary containing: 'request', 'requester',
        'signer' and 'signer_add'.
    :param ms: Metadata statements to be added
    :param root: if this is the metadata statement signed by a FO
    :param leaf: if the requester is the entity operator/agent
    :param operator: A dictionary containing Operator instance as values.
    :return: A tuple with the signed metadata statement and the FO ID.
        The FO ID is '' if this is not the root MS.
    """
    req = MetadataStatement(**desc['request'])
    _requester = operator[desc['requester']]
    req['signing_keys'] = _requester.signing_keys_as_jwks()
    if ms:
        if isinstance(ms, list):
            req['metadata_statements'] = ms[:]
        else:
            req['metadata_statements'] = [ms[:]]
    req.update(desc['signer_add'])

    if leaf:
        jwt_args = {'aud': [_requester.iss]}
    else:
        jwt_args = {}

    _signer = operator[desc['signer']]
    ms = _signer.pack_metadata_statement(req, jwt_args=jwt_args)
    if root is True:
        _fo = _signer.iss
    else:
        _fo = ''

    return ms, _fo


def make_signed_metadata_statements(smsdef, operator):
    """
    Create a compounded metadata statement.

    :param smsdef: A list of descriptions of how to sign metadata statements
    :param operator: A dictionary with operator ID as keys and Operator
        instances as values
    :return: A compounded metadata statement
    """
    res = []

    for ms_chain in smsdef:
        _ms = []
        depth = len(ms_chain)
        i = 1
        _fo = []
        _root_fo = []
        root = True
        leaf = False
        for desc in ms_chain:
            if i == depth:
                leaf = True
            if isinstance(desc, dict):
                _ms, _fo = make_ms(desc, _ms, root, leaf, operator)
            else:
                _mss = []
                _fos = []
                for d in desc:
                    _m, _f = make_ms(d, _ms, root, leaf, operator)
                    _mss.append(_m)
                    if _f:
                        _fos.append(_f)
                _ms = _mss
                if _fos:
                    _fo = _fos
            if root:
                _root_fo = _fo
            root = False
            i += 1

        res.append({'fo':_root_fo, 'ms':_ms})
    return res
