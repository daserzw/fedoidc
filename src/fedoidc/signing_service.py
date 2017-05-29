import copy
import os
from urllib.parse import quote_plus
from urllib.parse import unquote_plus

import logging
import requests
from oic.oauth2 import Message

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

    def name(self):
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

    def name(self):
        return self.iss


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

    def name(self):
        return self.url


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

    def items(self):
        res = {}
        for key, fs in self.metadata_statements.items():
            res[key] = list(fs.keys())
        return res

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
        :param context: The context in which this Signed metadata
            statement should be used
        :param fos: Signed metadata statements from these Federation Operators
            should be added.
        :return: Dictionary with signed Metadata Statements as values
        """

        if not context:
            context = self.def_context

        _sms = {}
        if self.metadata_statements:
            try:
                cms = self.metadata_statements[context]
            except KeyError:
                try:
                    logger.error(
                        'Signer: {}, items: {}'.format(self.signing_service.iss,
                                                       self.items()))
                except AttributeError:
                    pass
                logger.error(
                    'No metadata statements for this context: {}'.format(
                        context))
                raise
            else:
                if fos is None:
                    fos = list(cms.keys())

                for f in fos:
                    try:
                        val = cms[f]
                    except KeyError:
                        continue

                    if val.startswith('http'):
                        req['metadata_statement_uris'] = {f: val}
                        _sms[f] = self.signing_service(req)
                        del req['metadata_statement_uris']
                    else:
                        req['metadata_statements'] = {f: val}
                        _sms[f] = self.signing_service(req)
                        del req['metadata_statements']

                if fos and not _sms:
                    raise KeyError('No metadata statements matched')

        return _sms
