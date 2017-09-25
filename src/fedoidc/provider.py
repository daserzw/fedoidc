import json
import logging
import sys
import traceback

from jwkest.jws import factory
from jwkest.jws import JWS
from oic.utils.keyio import KeyJar

from fedoidc import ClientMetadataStatement
from fedoidc import KeyBundle
from fedoidc.signing_service import SigningServiceError

from oic.oauth2 import error
from oic.oic import provider
from oic.oic.message import OpenIDSchema
from oic.oic.message import RegistrationRequest
from oic.oic.provider import STR
from oic.utils.http_util import Created
from oic.utils.http_util import Response
from oic.utils.sanitize import sanitize

from fedoidc.utils import replace_jwks_key_bundle

logger = logging.getLogger(__name__)


class Provider(provider.Provider):
    """ OIDC OP class """

    def __init__(self, name, sdb, cdb, authn_broker, userinfo, authz,
            client_authn, symkey, urlmap=None, ca_certs="", keyjar=None,
            hostname="", template_lookup=None, template=None,
            verify_ssl=True, capabilities=None, schema=OpenIDSchema,
            jwks_uri='', jwks_name='', baseurl=None, client_cert=None,
            federation_entity=None, fo_priority=None,
            response_metadata_statements=None, signer=None,
            signed_jwks_uri=''):
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
        self.signed_jwks_uri = signed_jwks_uri
        self.federation = ''

    def get_signed_keys(self, uri, signing_keys):
        """

        :param uri: Where the signed JWKS can be found
        :param signing_keys: Dictionary representation of a JWKS
        :return: list of KeyBundle instances or None
        """
        r = self.server.http_request(uri, allow_redirects=True)
        if r.status_code == 200:
            _skj = KeyJar()
            _skj.import_jwks(signing_keys, '')

            _jws = factory(r.text)
            _jwks = _jws.verify_compact(r.text, Keys=_skj.get_signing_key())
            _kj = KeyJar()
            _kj.import_jwks(json.loads(_jwks), '')
            return _kj.issuer_keys['']
        else:
            return None

    def _signer(self):
        if self.signer:
            return self.signer
        elif self.federation_entity:
            if self.federation_entity.signer:
                return self.federation_entity.signer

        return None

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
        _sig = self._signer()
        if _sig:
            return _fe.signer.create_signed_metadata_statement(
                _req, context, fos=fos)
        else:
            raise SigningServiceError('No signer')

    def store_signed_jwks_uri(self):
        """
        
        :return: 
        """
        file_name = 'static/signed_jwks'
        _jwks = self.keyjar.export_jwks()
        _jws = JWS(_jwks)
        _jwt = _jws.sign_compact(
            self.federation_entity.keyjar.get_signing_key())
        fp = open(file_name, 'w')
        fp.write(_jwt)
        fp.close()
        return ''.join([self.baseurl, file_name])

    def create_fed_providerinfo(self, fos=None, pi_args=None, signed=True):
        """
        Create federation aware provider info.

        :param fos: Which Federation Operators to use, None means all.
        :param pi_args: Extra provider info claims.
        :return: oic.oic.ProviderConfigurationResponse instance 
        """

        pcr = self.create_providerinfo(setup=pi_args)

        if self.federation_entity.signer.signing_service:
            # Add signed_jwks_uri
            pcr['signed_jwks_uri'] = self.signed_jwks_uri
            _ms = self.create_signed_provider_info('discovery', fos, pi_args)
            pcr = self.federation_entity.extend_with_ms(pcr, _ms)
        else:
            _ms = self.federation_entity.signer.gather_metadata_statements(
                'discovery', fos=fos)
            pcr.update(_ms)

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

        les = self.federation_entity.get_metadata_statement(request,
                                                            'registration')

        if les:
            ms = self.federation_entity.pick_by_priority(les)
            self.federation = ms.fo
        else:  # Nothing I can use
            return error(error='invalid_request',
                         descr='No signed metadata statement I could use')

        _pc = ms.protected_claims()
        if _pc:
            request = RegistrationRequest(**_pc)
        else:
            request = RegistrationRequest(
                **ms.unprotected_and_protected_claims())
        result = self.client_registration_setup(request)
        if 'signed_jwks_uri' in _pc:
            _kb = KeyBundle(source=_pc['signed_jwks_uri'],
                            verify_keys=ms.signing_keys,
                            verify_ssl=False)
            _kb.do_remote()
            replace_jwks_key_bundle(self.keyjar, result['client_id'], _kb)
            result['signed_jwks_uri'] = _pc['signed_jwks_uri']

        if isinstance(result, Response):
            return result

        # TODO This is where the OP should sign the response
        if ms.fo:
            _fo = ms.fo
            _sig = self._signer()

            if _sig:
                sms = _sig.create_signed_metadata_statement(
                    result, 'response', [_fo], single=True)
            else:
                raise SigningServiceError('No Signer')

            self.federation_entity.extend_with_ms(result, {_fo: sms})

        return Created(result.to_json(), content="application/json",
                       headers=[("Cache-Control", "no-store")])
