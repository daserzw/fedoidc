import copy
from urllib.parse import quote_plus
from urllib.parse import unquote_plus

import requests

from fedoidc.file_system import FileSystem
from oic.utils.jwt import JWT


class ServiceError(Exception):
    pass


class SigningService(object):
    def __init__(self, add_ons=None, alg='RS256'):
        self.add_ons = add_ons or {}
        self.alg = alg

    def __call__(self, req, **kwargs):
        raise NotImplemented()


class InternalSigningService(SigningService):
    def __init__(self, iss, signing_keys, add_ons=None, alg='RS256'):
        SigningService.__init__(self, add_ons=add_ons, alg=alg)
        self.signing_keys = signing_keys
        self.iss = iss

    def __call__(self, req, **kwargs):
        """

        :param req: Original metadata statement as a MetadataStatement
        instance
        :param keyjar: KeyJar in which the necessary keys should reside
        :param iss: Issuer ID
        :param alg: Which signing algorithm to use
        :param kwargs: Additional metadata statement attribute values
        :return: A JWT
        """
        iss = self.iss
        keyjar = self.signing_keys

        # Own copy
        _metadata = copy.deepcopy(req)
        _metadata.update(self.add_ons)
        _jwt = JWT(keyjar, iss=iss, msgtype=_metadata.__class__)
        _jwt.sign_alg = self.alg

        if iss in keyjar.issuer_keys:
            owner = iss
        else:
            owner = ''

        if kwargs:
            return _jwt.pack(cls_instance=_metadata, owner=owner, **kwargs)
        else:
            return _jwt.pack(cls_instance=_metadata, owner=owner)


class WebSigningService(SigningService):
    def __init__(self, url, add_ons=None, alg='RS256'):
        SigningService.__init__(self, add_ons=add_ons, alg=alg)
        self.url = url

    def __call__(self, req, **kwargs):
        r = requests.post(self.url, json=req)
        if 200 <= r.status_code < 300:
            return r.text
        else:
            raise ServiceError("{}: {}".format(r.status_code, r.text))


class Signer(object):
    def __init__(self, signing_service, ms_dir):
        self.metadata_statements = {}

        for key, _dir in ms_dir.items():
            self.metadata_statements[key] = FileSystem(
                _dir, key_conv={'to': quote_plus, 'from': unquote_plus})

        self.signing_service = signing_service

    def create_signed_metadata_statement(self, req, context, fos=None):
        """

        :param req: The metadata statement to be signed
        :param fos: Signed metadata statements from these Federation Operators
            should be added.
        :param context: The context in which this Signed metadata
            statement should be used
        :return: signed Metadata Statement
        """

        if fos is None:
            fos = list(self.metadata_statements[context].keys())

        _msl = []
        for f in fos:
            try:
                _msl.append(self.metadata_statements[context][f])
            except KeyError:
                pass

        if fos and not _msl:
            raise KeyError('No metadata statements matched')

        if _msl:
            req['metadata_statements'] = _msl

        return self.signing_service(req)

