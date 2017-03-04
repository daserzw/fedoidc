import logging

from fedoidc import ClientMetadataStatement
from oic.oauth2 import error
from oic.oic import provider
from oic.oic.message import DiscoveryRequest
from oic.oic.message import DiscoveryResponse
from oic.oic.message import OpenIDSchema
from oic.oic.message import RegistrationRequest
from oic.oic.provider import SWD_ISSUER
from oic.utils.http_util import Created, BadRequest
from oic.utils.http_util import Response
from oic.utils.sanitize import sanitize

logger = logging.getLogger(__name__)


class Provider(provider.Provider):
    def __init__(self, name, sdb, cdb, authn_broker, userinfo, authz,
                 client_authn, symkey, urlmap=None, ca_certs="", keyjar=None,
                 hostname="", template_lookup=None, template=None,
                 verify_ssl=True, capabilities=None, schema=OpenIDSchema,
                 jwks_uri='', jwks_name='', baseurl=None, client_cert=None,
                 federation_entity=None, fo_priority=None):
        provider.Provider.__init__(
            self, name, sdb, cdb, authn_broker, userinfo, authz,
            client_authn, symkey, urlmap=urlmap, ca_certs=ca_certs,
            keyjar=keyjar, hostname=hostname, template_lookup=template_lookup,
            template=template, verify_ssl=verify_ssl, capabilities=capabilities,
            schema=schema, jwks_uri=jwks_uri, jwks_name=jwks_name,
            baseurl=baseurl, client_cert=client_cert)

        self.federation_entity = federation_entity
        self.fo_priority = fo_priority

    def create_signed_metadata_statement(self, fos=None, setup=None):
        """

        :param signer:
        :param fos:
        :param setup:
        :return:
        """
        pcr = self.create_providerinfo(setup=setup)

        if fos is None:
            fos = list(self.federation_entity.signer.metadata_statements.keys())

        _req = self.federation_entity.create_metadata_statement_request(pcr,
                                                                        fos)

        return self.federation_entity.signer.signing_service(_req)

    def create_fed_providerinfo(self, fos=None, setup=None):
        """

        :param fos:
        :param setup:
        :return:
        """

        _ms = self.create_signed_metadata_statement(fos, setup)

        pcr = self.create_providerinfo(setup=setup)
        pcr['metadata_statements'] = [_ms]

        return pcr

    def discovery_endpoint(self, request, handle=None, **kwargs):
        if isinstance(request, dict):
            request = DiscoveryRequest(**request)
        else:
            request = DiscoveryRequest().deserialize(request, "urlencoded")

        try:
            assert request["service"] == SWD_ISSUER
        except AssertionError:
            return BadRequest("Unsupported service")

        _response = DiscoveryResponse(locations=[self.baseurl])
        if self.federation_entity.signed_metadata_statements:
            _response.update(
                {'metadata_statements':
                     self.federation_entity.signed_metadata_statements
                         .values()})

        headers = [("Cache-Control", "no-store")]

        return Response(_response.to_json(), content="application/json",
                        headers=headers)

    def registration_endpoint(self, request, authn=None, **kwargs):
        logger.debug("@registration_endpoint: <<{}>>".format(sanitize(request)))

        if isinstance(request, dict):
            request = ClientMetadataStatement(**request)
        else:
            try:
                request = ClientMetadataStatement().deserialize(request, "json")
            except ValueError:
                request = ClientMetadataStatement().deserialize(request)

        logger.info(
            "registration_request:{}".format(sanitize(request.to_dict())))

        res = self.federation_entity.get_metadata_statement(request)

        if res:
            fo, _dict = self.federation_entity.pick_by_priority(res)
        else:  # Nothing I can use
            return error(error='invalid_request',
                         descr='No signed metadata statement I could use')

        request = RegistrationRequest(**_dict)
        result = self.client_registration_setup(request)
        if isinstance(result, Response):
            return result

        return Created(result.to_json(), content="application/json",
                       headers=[("Cache-Control", "no-store")])
