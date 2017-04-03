import copy
import json
import logging

from jwkest import BadSignature
from jwkest.jws import JWSException
import time

from fedoidc import ClientMetadataStatement
from fedoidc import DoNotCompare
from fedoidc import IgnoreKeys
from fedoidc import is_lesser
from fedoidc import unfurl

from oic.oauth2.message import MissingSigningKey

from oic.utils.keyio import build_keyjar
from oic.utils.jwt import JWT

__author__ = 'roland'

logger = logging.getLogger(__name__)


class ParseInfo(object):
    def __init__(self):
        self.input = None
        self.parsed_statement = []
        self.error = {}
        self.result = None
        self.branch = {}


class LessOrEqual(object):
    def __init__(self, iss='', sup=None):
        if sup:
            self.iss = sup.iss
        else:
            self.iss = iss
        self.sup = sup
        self.err = {}
        self.le = {}

    def __setitem__(self, key, value):
        self.le[key] = value

    def keys(self):
        return self.le.keys()

    def items(self):
        return self.le.items()

    def __getitem__(self, item):
        return self.le[item]

    def __contains__(self, item):
        return item in self.le

    def sup_items(self):
        if self.sup:
            return self.sup.le.items()
        else:
            return {}

    def eval(self, orig):
        _le = {}
        _err = []
        for k, v in self.sup_items():
            if k in DoNotCompare:
                continue
            if k in orig:
                if is_lesser(orig[k], v):
                    _le[k] = v
                else:
                    _err.append((k, orig[k], v))
            else:
                _le[k] = v

        for k, v in orig.items():
            if k in DoNotCompare:
                continue
            if k not in _le:
                _le[k] = v

        self.le = _le
        self.err = _err

    def protected_claims(self):
        if self.sup:
            return self.sup.le

    def unprotected_claims(self):
        if self.sup:
            res = {}
            for k,v in self.le.items():
                if k not in self.sup.le:
                    res[k] = v
            return res
        else:
            return self.le


def le_dict(les):
    return dict([(l.iss, l) for l in les])


class Operator(object):
    def __init__(self, keyjar=None, jwks_bundle=None, httpcli=None, iss=None):
        """

        :param keyjar: Contains the operators signing keys
        :param jwks_bundle: Contains the federation operators signing keys
            for all the federations this instance wants to talk to
        :param httpcli: A http client to use when information has to be
            fetched from somewhere else
        :param iss: Issuer ID
        """
        self.keyjar = keyjar
        self.jwks_bundle = jwks_bundle
        self.httpcli = httpcli
        self.iss = iss
        self.failed = {}

    def signing_keys_as_jwks(self):
        _l = [x.serialize() for x in self.keyjar.get_signing_key()]
        if not _l:
            _l = [x.serialize() for x in
                  self.keyjar.get_signing_key(owner=self.iss)]
        return {'keys': _l}

    def _ums(self, pr, meta_s, keyjar):
        try:
            _pi = self.unpack_metadata_statement(
                jwt_ms=meta_s, keyjar=keyjar)
        except (JWSException, BadSignature,
                MissingSigningKey) as err:
            logger.error('Encountered: {}'.format(err))
            pr.error[meta_s] = err
        else:
            pr.branch[meta_s] = _pi
            pr.parsed_statement.append(_pi.result)
        return pr

    def _unpack(self, json_ms, keyjar, cls, jwt_ms=None):
        _pr = ParseInfo()
        _pr.input = json_ms
        if 'metadata_statements' in json_ms:
            for meta_s in json_ms['metadata_statements']:
                _pr = self._ums(_pr, meta_s, keyjar)

            for _ms in _pr.parsed_statement:
                if _ms:  # can be None
                    try:
                        keyjar.import_jwks(_ms['signing_keys'], '')
                    except KeyError:
                        pass

        if 'metadata_statement_uris' in json_ms:
            if self.httpcli:
                for iss, url in json_ms['metadata_statement_uris'].items():
                    if iss not in keyjar:  # FO I don't know about
                        continue
                    else:
                        _jwt = self.httpcli.http_request(url)
                        _pr = self._ums(_pr, _jwt, keyjar)

                for _ms in _pr.parsed_statement:
                    if _ms:  # can be None
                        keyjar.import_jwks(_ms['signing_keys'], '')

        if jwt_ms:
            try:
                _pr.result = cls().from_jwt(jwt_ms, keyjar=keyjar)
            except MissingSigningKey as err:
                logger.error('Encountered: {}'.format(err))
                _pr.error[jwt_ms] = err
        else:
            _pr.result = json_ms

        if _pr.parsed_statement:
            _pr.result['metadata_statements'] = [
                x.to_json() for x in _pr.parsed_statement if x]
        return _pr

    def unpack_metadata_statement(self, json_ms=None, jwt_ms='', keyjar=None,
                                  cls=ClientMetadataStatement):
        """

        :param json_ms: Metadata statement as a JSON document
        :param jwt_ms: Metadata statement as JWT
        :param keyjar: Keys that should be used to verify the signature of the
            document
        :param cls: What type (Class) of metadata statement this is
        :return: ParseInfo instance
        """

        if not keyjar:
            keyjar = self.jwks_bundle.as_keyjar()

        if jwt_ms:
            try:
                json_ms = unfurl(jwt_ms)
            except JWSException:
                raise

        if json_ms:
            return self._unpack(json_ms, keyjar, cls, jwt_ms)
        else:
            raise AttributeError('Need one of json_ms or jwt_ms')

    def pack_metadata_statement(self, metadata, keyjar=None, iss=None, alg='',
                                jwt_args=None, **kwargs):
        """

        :param metadata: Original metadata statement as a MetadataStatement
            instance
        :param keyjar: KeyJar in which the necessary keys should reside
        :param iss: Issuer ID
        :param alg: Which signing algorithm to use
        :param jwt_args: Additional JWT attribute values
        :param kwargs: Additional metadata statement attribute values
        :return: A JWT
        """
        if iss is None:
            iss = self.iss
        if keyjar is None:
            keyjar = self.keyjar

        # Own copy
        _metadata = copy.deepcopy(metadata)
        _metadata.update(kwargs)
        _jwt = JWT(keyjar, iss=iss, msgtype=_metadata.__class__)
        if alg:
            _jwt.sign_alg = alg

        if iss in keyjar.keys():
            owner = iss
        else:
            owner = ''

        if jwt_args:
            return _jwt.pack(cls_instance=_metadata, owner=owner, **jwt_args)
        else:
            return _jwt.pack(cls_instance=_metadata, owner=owner)

    def evaluate_metadata_statement(self, metadata):
        """
        Computes the resulting metadata statement from a compounded metadata
        statement.
        If something goes wrong during the evaluation an exception is raised

        :param metadata: The compounded metadata statement
        :return: A Flatten instance
        """

        # start from the innermost metadata statement and work outwards

        res = dict([(k, v) for k, v in metadata.items() if k not in IgnoreKeys])

        if 'metadata_statements' in metadata:
            les = []
            for ms in metadata['metadata_statements']:
                for _le in self.evaluate_metadata_statement(json.loads(ms)):
                    le = LessOrEqual(sup=_le)
                    le.eval(res)
                    les.append(le)
            return les
        else:  # this is the innermost
            le = LessOrEqual(iss=metadata['iss'])
            le.eval(res)
            return [le]

    def correct_usage(self, metadata, federation_usage):
        """
        Remove MS paths that are marked to be used for another usage

        :param metadata:
        :param federation_usage:
        :return:
        """

        if 'metadata_statements' in metadata:
            _msl = []
            for ms in metadata['metadata_statements']:
                if self.correct_usage(json.loads(ms),
                                      federation_usage=federation_usage):
                    _msl.append(ms)
            if _msl:
                metadata['metadata_statements'] = _msl
                return metadata
            else:
                return None
        else:  # this is the innermost
            try:
                assert federation_usage == metadata['federation_usage']
            except KeyError:
                pass
            except AssertionError:
                return None
            return metadata


class FederationOperator(Operator):
    def __init__(self, keyjar=None, jwks_bundle=None, httpcli=None,
                 iss=None, keyconf=None, bundle_sign_alg='RS256'):

        Operator.__init__(self, keyjar=keyjar, jwks_bundle=jwks_bundle,
                          httpcli=httpcli, iss=iss)

        self.keyconf = keyconf
        self.jb = jwks_bundle
        self.bundle_sign_alg = bundle_sign_alg

    def public_keys(self):
        return self.keyjar.export_jwks()

    def rotate_keys(self, keyconf=None):
        _old = [k.kid for k in self.keyjar.get_issuers_keys('') if k.kid]

        if keyconf:
            self.keyjar = build_keyjar(keyconf, keyjar=self.keyjar)[1]
        else:
            self.keyjar = build_keyjar(self.keyconf, keyjar=self.keyjar)[1]

        for k in self.keyjar.get_issuers_keys(''):
            if k.kid in _old:
                if not k.inactive_since:
                    k.inactive_since = time.time()

    def export_jwks(self):
        return self.keyjar.export_jwks()

    def add_to_bundle(self, fo, jwks):
        self.jb[fo] = jwks

    def remove_from_bundle(self, fo):
        del self.jb[fo]

    def export_bundle(self):
        return self.jb.create_signed_bundle(sign_alg=self.bundle_sign_alg)
