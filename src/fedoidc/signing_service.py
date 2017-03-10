import copy
from urllib.parse import quote_plus
from urllib.parse import unquote_plus

from fedoidc.file_system import FileSystem
from oic.utils.jwt import JWT


class SigningService(object):
    def __init__(self, iss, signing_keys, add_ons=None, alg='RS256'):
        self.iss = iss
        self.signing_keys = signing_keys
        self.add_ons = add_ons or {}
        self.alg = alg

    def __call__(self, req, **kwargs):
        """

        :param metas: Original metadata statement as a MetadataStatement
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


class Signer(object):
    def __init__(self, signing_service, ms_dir):
        self.metadata_statements = FileSystem(
            ms_dir, key_conv={'to': quote_plus, 'from': unquote_plus})
        self.signing_service = signing_service

    def create_signed_metadata_statement(self, req, fos=None):
        if fos is None:
            fos = list(self.metadata_statements.keys())

        _msl = []
        for f in fos:
            try:
                _msl.append(self.metadata_statements[f])
            except KeyError:
                pass

        if not _msl:
            raise KeyError('No metadata statements matched')

        req['metadata_statements'] = _msl
        return self.signing_service(req)

