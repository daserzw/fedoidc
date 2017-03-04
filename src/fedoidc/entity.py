import json
import logging
import re

from fedoidc import MetadataStatement
from oic.utils.keyio import KeyJar
from fedoidc.operator import Operator

__author__ = 'roland'

logger = logging.getLogger(__name__)


class FederationEntity(Operator):
    def __init__(self, srv, iss='', keyjar=None,
                 signer=None, fo_bundle=None):
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

    def read_jwks_file(self, jwks_file):
        _jwks = open(jwks_file, 'r').read()
        _kj = KeyJar()
        _kj.import_jwks(json.loads(_jwks), '')
        return _kj

    def pick_by_priority(self, req, priority=None):
        if not priority:
            _key = list(req.keys())[0]  # Just return any
            return _key, req[_key]

        for iss in priority:
            try:
                return iss, req[iss]
            except KeyError:
                pass
        return '', None

    def pick_signed_metadata_statements_regex(self, pattern):
        """
        Pick signed metadata statements based on ISS pattern matching
        :param pattern: A regular expression to match the iss against
        :return: list of tuples (FO ID, signed metadata statement)
        """
        comp_pat = re.compile(pattern)
        sms = self.signer.signed_metadata_statements
        res = []
        for iss, vals in sms.items():
            if comp_pat.search(iss):
                res.extend((iss, vals))
        return res

    def pick_signed_metadata_statements(self, fo):
        """
        Pick signed metadata statements based on ISS pattern matching
        :param fo: Federation operators ID
        :return: list of tuples (FO ID, signed metadata statement)
        """
        sms = self.signer.signed_metadata_statements
        res = []
        for iss, vals in sms.items():
            if iss == fo:
                res.extend((iss, vals))
        return res

    def get_metadata_statement(self, json_ms, cls=MetadataStatement):
        """
        Unpack and evaluate a compound metadata statement
        :param json_ms: The metadata statement as a JSON document
        :return: A dictionary with metadata statements per FO
        """
        _cms = self.unpack_metadata_statement(json_ms=json_ms, cls=cls)
        ms_per_fo = self.evaluate_metadata_statement(_cms)

        return ms_per_fo

    def create_metadata_statement_request(self, statement, fos):
        """
        Create a request to be signed by higher ups.

        :param fos: List of Federations that we like to work within.
        :return: A JSON document
        """
        statement['signing_keys'] = self.signing_keys_as_jwks()
        _ms = []
        for fo in fos:
            try:
                _ms.append(
                    self.signer.metadata_statements[fo])
            except KeyError:
                pass
        if _ms:
            statement['metadata_statements'] = _ms

        return statement
