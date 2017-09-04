import logging
import sys
import traceback

from fedoidc import ClientMetadataStatement

from oic.oauth2 import error
from oic.oauth2 import Message
from oic.oic import provider
from oic.oic.message import OpenIDSchema
from oic.oic.message import RegistrationRequest
from oic.oic.provider import STR
from oic.utils.http_util import Created
from oic.utils.http_util import Response
from oic.utils.sanitize import sanitize

logger = logging.getLogger(__name__)


class Provider(provider.Provider):
    """ OIDC OP class """
    def __init__(self, name, sdb, cdb, authn_broker, userinfo, authz,
                 client_authn, symkey, urlmap=None, ca_certs="", keyjar=None,
                 hostname="", template_lookup=None, template=None,
                 verify_ssl=True, capabilities=None, schema=OpenIDSchema,
                 jwks_uri='', jwks_name='', baseurl=None, client_cert=None,
                 federation_entity=None, fo_priority=None,
                 response_metadata_statements=None, signer=None):
        provider.Provider.__init__(
            self, name, sdb, cdb, authn_broker, userinfo, authz,
            client_authn, symkey, urlmap=urlmap, ca_certs=ca_certs,
            keyjar=keyjar, hostname=hostname, template_lookup=template_lookup,
            template=template, verify_ssl=verify_ssl, capabilities=capabilities,
            schema=schema, jwks_uri=jwks_uri, jwks_name=jwks_name,
            baseurl=baseurl, client_cert=client_cert)

        self.federation_entity = federation_entity
        self.fo_priority = fo_priority
        self.response_metadata_statements = response_metadata_statements
        self.signer = signer

    def create_signed_provider_info(self, context, fos=None, setup=None):
        """
        Collects metadata about this provider add signing keys and use the
        signer to sign the complete metadata statement.
         
        :param context: In which context the metadata statement is supposed
            to be used.
        :param fos: List of federation operators
        :param setup: Extra keyword arguments to be added to the provider info
        :return: Depends on the signer used
        """
        pcr = self.create_providerinfo(setup=setup)
        _fe = self.federation_entity

        if fos is None:
            fos = _fe.signer.metadata_statement_fos(context)

        logger.info(
            'provider:{}, fos:{}, context:{}'.format(self.name, fos, context))

        _req = _fe.add_signing_keys(pcr)
        return _fe.signer.create_signed_metadata_statement(
            _req, context, fos=fos)

    def create_fed_providerinfo(self, fos=None, pi_args=None):
        """
        Create federation aware provider info.

        :param fos: Which Federation Operators to use, None means all.
        :param pi_args: Extra provider info claims.
        :return: oic.oic.ProviderConfigurationResponse instance 
        """

        _ms = self.create_signed_provider_info('discovery', fos, pi_args)
        pcr = self.create_providerinfo(setup=pi_args)

        pcr = self.federation_entity.extend_with_ms(pcr, _ms)
        return pcr

    def providerinfo_endpoint(self, handle="", **kwargs):
        """
        The Provider info endpoint. A request for provider info should be
        handled by this method. It will work as well for requests from
        federation aware RPs as for non-federation aware RPs.

        :param handle: (key, timestamp) tuple used at cookie construction
        :param kwargs: Extra key word arguments.
        :return: Provider Info response
        """
        logger.info("@providerinfo_endpoint")
        try:
            _response = self.create_fed_providerinfo()
            msg = "provider_info_response: {}"
            logger.info(msg.format(sanitize(_response.to_dict())))
            if self.events:
                self.events.store('Protocol response', _response)

            headers = [("Cache-Control", "no-store"), ("x-ffo", "bar")]
            if handle:
                (key, timestamp) = handle
                if key.startswith(STR) and key.endswith(STR):
                    cookie = self.cookie_func(key, self.cookie_name, "pinfo",
                                              self.sso_ttl)
                    headers.append(cookie)

            resp = Response(_response.to_json(), content="application/json",
                            headers=headers)
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            resp = error('service_error', message)

        return resp

    def registration_endpoint(self, request, authn=None, **kwargs):
        """
        Registration endpoint. This is where a registration request should
        be handled.

        :param request: The request, either as a dictionary or as a JSON
            document
        :param authn: Authentication information
        :param kwargs: Extra key work arguments.
        :return: A request response or an error response.
        """
        logger.debug("@registration_endpoint: <<{}>>".format(sanitize(request)))

        if isinstance(request, dict):
            request = ClientMetadataStatement(**request)
        else:
            try:
                request = ClientMetadataStatement().deserialize(request, "json")
            except ValueError:
                request = ClientMetadataStatement().deserialize(request)

        try:
            request.verify()
        except Exception as err:
            return error('Invalid request')

        logger.info(
            "registration_request:{}".format(sanitize(request.to_dict())))

        ms_list = self.federation_entity.get_metadata_statement(request,
                                                                'registration')

        if ms_list:
            ms = self.federation_entity.pick_by_priority(ms_list)
            self.federation = ms.fo
        else:  # Nothing I can use
            return error(error='invalid_request',
                         descr='No signed metadata statement I could use')

        request = RegistrationRequest(**ms.le)
        result = self.client_registration_setup(request)

        if isinstance(result, Response):
            return result

        # TODO This is where the OP should sign the response
        if ms.fo:
            _fo = ms.fo
            sms = self.signer.create_signed_metadata_statement(
                result, 'response', [_fo], single=True)
            self.federation_entity.extend_with_ms(result, {_fo: sms})

        return Created(result.to_json(), content="application/json",
                       headers=[("Cache-Control", "no-store")])
