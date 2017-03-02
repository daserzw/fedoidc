import copy

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

        if kwargs:
            return _jwt.pack(cls_instance=_metadata, **kwargs)
        else:
            return _jwt.pack(cls_instance=_metadata)


