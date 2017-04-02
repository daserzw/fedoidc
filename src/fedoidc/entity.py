import json
import logging
import re

from fedoidc import MetadataStatement
from oic.utils.keyio import KeyJar
from fedoidc.operator import Operator

__author__ = 'roland'

logger = logging.getLogger(__name__)


def read_jwks_file(self, jwks_file):
    _jwks = open(jwks_file, 'r').read()
    _kj = KeyJar()
    _kj.import_jwks(json.loads(_jwks), '')
    return _kj


class FederationEntity(Operator):
    def __init__(self, srv, iss='', keyjar=None, signer=None, fo_bundle=None):
        """

        :param srv: A Client or Provider instance
        :param iss: A identifier assigned to this entity by the operator
        :param keyjar: Key this entity can use to sign things
        :param signer: A signer to use for signing documents
            (client registration requests/provide info response) this
            entity produces.
        :param fo_bundle: A bundle of keys that can be used to verify
            the root signature of a compounded metadata statement.
        """

        Operator.__init__(self, iss=iss, keyjar=keyjar, httpcli=srv,
                          jwks_bundle=fo_bundle)

        # Who can sign request from this entity
        self.signer = signer

    @staticmethod
    def pick_by_priority(req, priority=None):
        if not priority:
            _key = list(req.keys())[0]  # Just return any
            return _key, req[_key]

        for iss in priority:
            try:
                return iss, req[iss]
            except KeyError:
                pass
        return '', None

    def pick_signed_metadata_statements_regex(self, pattern, context):
        """
        Pick signed metadata statements based on ISS pattern matching
        :param pattern: A regular expression to match the iss against
        :return: list of tuples (FO ID, signed metadata statement)
        """
        comp_pat = re.compile(pattern)
        sms = self.signer.metadata_statements[context]
        res = []
        for iss, vals in sms.items():
            if comp_pat.search(iss):
                res.extend((iss, vals))
        return res

    def pick_signed_metadata_statements(self, fo, context):
        """
        Pick signed metadata statements based on ISS pattern matching
        :param fo: Federation operators ID
        :return: list of tuples (FO ID, signed metadata statement)
        """
        sms = self.signer.metadata_statements[context]
        res = []
        for iss, vals in sms.items():
            if iss == fo:
                res.extend((iss, vals))
        return res

    def get_metadata_statement(self, json_ms, cls=MetadataStatement,
                               context=''):
        """
        Unpack and evaluate a compound metadata statement

        :param json_ms: The metadata statement as a JSON document
        :param cls: The class the response should be typed into
        :param context: In which context the metadata statement should be used.
        :return: A dictionary with metadata statements per FO
        """
        _pi = self.unpack_metadata_statement(json_ms=json_ms, cls=cls)
        if not _pi.result:
            return {}

        if context:
            _cms = self.correct_usage(_pi.result, context)
        else:
            _cms = _pi.result

        if _cms:
            ms_per_fo = self.evaluate_metadata_statement(_cms)
            return ms_per_fo
        else:
            return {}

    def create_metadata_statement_request(self, statement):
        """
        Create a request to be signed by higher ups.

        :return: A JSON document
        """
        statement['signing_keys'] = self.signing_keys_as_jwks()
        return statement
