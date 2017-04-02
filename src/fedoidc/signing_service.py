import copy
import os
from urllib.parse import quote_plus
from urllib.parse import unquote_plus

import logging
import requests

from fedoidc.file_system import FileSystem
from oic.utils.jwt import JWT

logger = logging.getLogger(__name__)


class ServiceError(Exception):
    pass


class SigningService(object):
    def __init__(self, add_ons=None, alg='RS256'):
        self.add_ons = add_ons or {}
        self.alg = alg

    def __call__(self, req, **kwargs):
        raise NotImplemented()


class InternalSigningService(SigningService):
    def __init__(self, iss, signing_keys, add_ons=None, alg='RS256',
                 lifetime=3600):
        SigningService.__init__(self, add_ons=add_ons, alg=alg)
        self.signing_keys = signing_keys
        self.iss = iss
        self.lifetime = lifetime

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
        _jwt = JWT(keyjar, iss=iss, msgtype=_metadata.__class__,
                   lifetime=self.lifetime)
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
    def __init__(self, signing_service, ms_dir=None, def_context=''):
        self.metadata_statements = {}

        if isinstance(ms_dir, dict):
            for key, _dir in ms_dir.items():
                self.metadata_statements[key] = FileSystem(
                    _dir, key_conv={'to': quote_plus, 'from': unquote_plus})
        elif ms_dir:
            for item in os.listdir(ms_dir):
                _dir = os.path.join(ms_dir, item)
                if os.path.isdir(_dir):
                    self.metadata_statements[item] = FileSystem(
                        _dir, key_conv={'to': quote_plus, 'from': unquote_plus})
        else:
            self.metadata_statements = {'register': {}, 'discovery': {},
                                        'response': {}}

        self.signing_service = signing_service
        self.def_context = def_context

    def metadata_statement_fos(self, context=''):
        if not context:
            context = self.def_context

        try:
            return list(self.metadata_statements[context].keys())
        except KeyError:
            return 0

    def create_signed_metadata_statement(self, req, context='', fos=None):
        """

        :param req: The metadata statement to be signed
        :param fos: Signed metadata statements from these Federation Operators
            should be added.
        :param context: The context in which this Signed metadata
            statement should be used
        :return: signed Metadata Statement
        """

        if not context:
            context = self.def_context

        if self.metadata_statements:
            try:
                cms = self.metadata_statements[context]
            except KeyError:
                logger.error(
                    'No metadata statements for this context: {}'.format(
                        context))
                raise
            else:
                if fos is None:
                    fos = list(cms.keys())

                _msl = []
                for f in fos:
                    try:
                        _msl.append(cms[f])
                    except KeyError:
                        pass

                if fos and not _msl:
                    raise KeyError('No metadata statements matched')

                if _msl:
                    req['metadata_statements'] = _msl

        return self.signing_service(req)
