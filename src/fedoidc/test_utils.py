import copy
import hashlib
import os

from urllib.parse import quote_plus
from urllib.parse import unquote_plus

from jwkest import as_bytes

from fedoidc.entity import FederationEntity

from fedoidc import MetadataStatement
from fedoidc.bundle import FSJWKSBundle, JWKSBundle
from fedoidc.bundle import keyjar_to_jwks_private
from fedoidc.file_system import FileSystem
from fedoidc.operator import Operator
from fedoidc.signing_service import Signer
from fedoidc.signing_service import InternalSigningService

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
    the signing keys.

    :param iss: The issuer ID of the entity owning the JWKSBundle
    :param fo_liss: List of federation identifiers
    :param sign_keyjar: Keys that the JWKSBundel owner can use to sign
        an export version of the JWKS bundle.
    :param keydefs: What type of keys that should be created for each
        federation. The same for all of them.
    :return: A JWKSBundle instance.
    """
    jb = JWKSBundle(iss, sign_keyjar)

    for entity in fo_liss:
        _keydef = copy.deepcopy(keydefs)
        _jwks, _keyjar, _kidd = build_keyjar(_keydef)
        jb[entity] = _keyjar

    return jb


def make_ms(desc, leaf, operator, ms=None, ms_uris=None):
    """
    Construct a signed metadata statement

    :param desc: A description of who wants who to signed what.
        represented as a dictionary containing: 'request', 'requester',
        'signer' and 'signer_add'.
    :param leaf: if the requester is the entity operator/agent
    :param operator: A dictionary containing Operator instance as values.
    :param ms: Metadata statements to be added, dict. The values are
        signed MetadataStatements.
    :param ms_uris: Metadata Statement URIs to be added. 
        Note that ms and ms_uris can not be present at the same time.
        It can be one of them or none.
    :return: A dictionary with the FO ID as key and the signed metadata 
        statement as value.
    """
    req = MetadataStatement(**desc['request'])
    _requester = operator[desc['requester']]
    req['signing_keys'] = _requester.signing_keys_as_jwks()

    _signer = operator[desc['signer']]

    if ms:
        req['metadata_statements'] = list(ms.values())
        if len(ms):
            _fo = list(ms.keys())[0]
        else:
            _fo = ''
    elif ms_uris:
        req['metadata_statement_uris'] = dict(ms_uris.items())
        if len(ms_uris):
            _fo = list(ms_uris.keys())[0]
        else:
            _fo = ''
    else:
        _fo = _signer.iss

    req.update(desc['signer_add'])

    if leaf:
        jwt_args = {'aud': [_requester.iss]}
    else:
        jwt_args = {}

    ms = _signer.pack_metadata_statement(req, jwt_args=jwt_args)

    return {_fo: ms}


def make_signed_metadata_statement(ms_chain, operator):
    """
    Based on a set of metadata statement descriptions build a compounded
    metadata statement. This is not using metadata_statement_uris.
    
    :param ms_chain: 
    :param operator: 
    :return: 
    """
    _ms = None
    depth = len(ms_chain)
    i = 1
    leaf = False
    for desc in ms_chain:
        if i == depth:
            leaf = True
        if isinstance(desc, dict):
            _ms = make_ms(desc, leaf, operator, _ms)
        else:
            _ms = {}
            for d in desc:
                _m = make_ms(d, leaf, operator, _ms)
                _ms.update(_m)
        i += 1

    return _ms


def make_signed_metadata_statement_uri(ms_chain, operator, mds=None,
                                       base_uri=''):
    """
    Based on a set of metadata statement descriptions build a compounded
    metadata statement. This is using metadata_statement_uris.

    :param ms_chain: 
    :param operator: 
    :param mds:
    :param base_uri;
    :return: 
    """
    _ms = {}
    depth = len(ms_chain)
    i = 1
    leaf = False
    for desc in ms_chain:
        if i == depth:
            leaf = True
        if isinstance(desc, dict):
            _x = make_ms(desc, leaf, operator, ms_uris=_ms)
            _ms = {}
            for k,v in _x.items():
                _ms[k] = '{}/{}'.format(base_uri, mds.add(v))
        else:
            _ms = {}
            for d in desc:
                _x = make_ms(d, leaf, operator, ms_uris=_ms)
                _m = {}
                for k, v in _x.items():
                    _m[k] = '{}/{}'.format(base_uri, mds.add(v))
                _ms.update(_m)
        i += 1

    return _ms


def make_signed_metadata_statements(smsdef, operator, mds_dir='', base_uri=''):
    """
    Create a compounded metadata statement.

    :param smsdef: A list of descriptions of how to sign metadata statements
    :param operator: A dictionary with operator ID as keys and Operator
        instances as values
    :param mds_dir:
    :param base_uri:
    :return: A compounded metadata statement
    """
    res = []

    if mds_dir:
        mds = MetaDataStore(mds_dir)
        for ms_chain in smsdef:
            res.append(make_signed_metadata_statement_uri(ms_chain, operator,
                                                          mds, base_uri))
    else:
        for ms_chain in smsdef:
            res.append(make_signed_metadata_statement(ms_chain, operator))

    return res


def setup(keydefs, tool_iss, liss, csms_def, oa, ms_path):
    """

    :param keydefs: Definition of which signing keys to create/load
    :param tool_iss: An identifier for the JWKSBundle instance
    :param liss: List of federation entity IDs
    :param csms_def: Definition of which signed metadata statements to build
    :param oa: Dictionary with Organization agents
    :param ms_path: Where to store the signed metadata statements
    :return: A tuple of (Signer dictionary and FSJWKSBundle instance)
    """
    sig_keys = build_keyjar(keydefs)[1]
    key_bundle = make_fs_jwks_bundle(tool_iss, liss, sig_keys, keydefs, './')

    sig_keys = build_keyjar(keydefs)[1]
    jb = FSJWKSBundle(tool_iss, sig_keys, 'fo_jwks',
                      key_conv={'to': quote_plus, 'from': unquote_plus})

    # Need to save the private parts
    jb.bundle.value_conv['to'] = keyjar_to_jwks_private
    jb.bundle.sync()

    operator = {}

    for entity, _keyjar in key_bundle.items():
        operator[entity] = Operator(iss=entity, keyjar=_keyjar)

    signers = {}
    for iss, sms_def in csms_def.items():
        ms_dir = os.path.join(ms_path, quote_plus(iss))
        for context, spec in sms_def.items():
            _dir = os.path.join(ms_dir, context)
            metadata_statements = FileSystem(
                _dir, key_conv={'to': quote_plus, 'from': unquote_plus})
            for fo, _desc in spec.items():
                res = make_signed_metadata_statement(_desc, operator)
                metadata_statements[fo] = res[fo]
        signers[iss] = Signer(
            InternalSigningService(iss, operator[iss].keyjar), ms_dir)

    return signers, key_bundle


def create_federation_entity(iss, conf, fos, sup, entity=''):
    _keybundle = FSJWKSBundle('', fdir=conf.JWKS_DIR,
                              key_conv={'to': quote_plus, 'from': unquote_plus})

    # Organisation information
    _kj = _keybundle[sup]
    fname = os.path.join(conf.MS_DIR, quote_plus(sup))
    signer = Signer(InternalSigningService(sup, _kj), fname)

    # And then the FOs
    jb = JWKSBundle('')
    for fo in fos:
        jb[fo] = _keybundle[fo]

    # The OPs own signing keys
    _keys = build_keyjar(conf.SIG_DEF_KEYS)[1]
    return FederationEntity(entity, iss=iss, keyjar=_keys, signer=signer,
                            fo_bundle=jb)


class MetaDataStore(FileSystem):
    @staticmethod
    def hash(value):
        _hash = hashlib.sha256()
        _hash.update(as_bytes(value))
        return _hash.hexdigest()

    def add(self, value):
        _key = self.hash(value)
        self[_key] = value
        return _key
