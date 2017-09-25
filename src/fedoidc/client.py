import json
import logging

import fedoidc
from jwkest.jws import factory
from jwkest.jws import JWS
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar

from fedoidc import ClientMetadataStatement
from fedoidc import ProviderConfigurationResponse

from oic import OIDCONF_PATTERN
from oic import oic
from oic.exception import CommunicationError
from oic.exception import ParameterError
from oic.exception import ParseError
from oic.exception import RegistrationError
from oic.oauth2 import ErrorResponse
from oic.oauth2 import sanitize
from oic.oauth2.message import MissingRequiredAttribute
from oic.oic import RegistrationResponse

from fedoidc.utils import replace_jwks_key_bundle

try:
    from json import JSONDecodeError
except ImportError:  # Only works for >= 3.5
    _decode_err = ValueError
else:
    _decode_err = JSONDecodeError

logger = logging.getLogger(__name__)

__author__ = 'roland'


class Client(oic.Client):
    """
    Federation aware OIDC Client
    """

    def __init__(self, client_id=None, ca_certs=None,
            client_prefs=None, client_authn_method=None, keyjar=None,
            verify_ssl=True, config=None, client_cert=None,
            federation_entity=None, fo_priority=None):
        oic.Client.__init__(
            self, client_id=client_id, ca_certs=ca_certs,
            client_prefs=client_prefs, client_authn_method=client_authn_method,
            keyjar=keyjar, verify_ssl=verify_ssl, config=config,
            client_cert=client_cert)

        self.federation_entity = federation_entity
        self.fo_priority = fo_priority
        self.federation = ''
        self.provider_federations = None
        self.registration_federations = None

    def get_signed_keys(self, uri, signing_keys):
        """

        :param uri: Where the signed JWKS can be found
        :param signing_keys: Dictionary representation of a JWKS
        :return: list of KeyBundle instances or None
        """
        r = self.http_request(uri, allow_redirects=True)
        if r.status_code == 200:

            return _kb
        else:
            return None

    def parse_federation_provider_info(self, resp, issuer):
        """
        Takes a provider info response and parses it.
        If according to the info the OP has more then one federation 
        in common with the client then the decision has to be handled higher up.
        The list of :py:class:`fedoidc.operator.LessOrEqual` instances are 
        stored in *provider_federations*.
        If the OP and RP only has one federation in common then the choice is
        easy and the name of the federation are stored in the *federation* 
        attribute while the provider info are stored in the normal pyoidc 
        Client way.
        
        :param resp: A MetadataStatement instance
        :param issuer: The OpenID Provider ID
        """

        les = self.federation_entity.get_metadata_statement(
            resp, cls=ProviderConfigurationResponse)

        if not les:  # No metadata statement that I can use
            raise ParameterError('No trusted metadata')

        # response is a list of metadata statements

        # At this point in time I may not know within which
        # federation I'll be working.
        if len(les) == 1:
            ms = les[0]
            _claims = ms.protected_claims()
            self.handle_provider_config(ms.protected_claims(), issuer)
            if 'signed_jwks_uri' in _claims:
                _kb = fedoidc.KeyBundle(source=_claims['signed_jwks_uri'],
                                        verify_keys=les.signing_keys,
                                        verify_ssl=False)
                _kb.do_remote()
                replace_jwks_key_bundle(self.keyjar, issuer, _kb)

            self.federation = ms.fo
        else:
            self.provider_federations = les

    def parse_federation_registration(self, resp, issuer):
        """
        Receives a dynamic client registration response, verifies the
        signature and parses the compounded metadata statement.
        If only one federation are mentioned in the response then the name
        of that federation are stored in the *federation* attribute and
        the flattened response is handled in the normal pyoidc way.
        If there are more then one federation involved then the decision
        on which to use has to be made higher up, hence the list of
        :py:class:`fedoidc.operator.LessOrEqual` instances are stored in the
        attribute *registration_federations*
        
        :param resp: A MetadataStatement instance or a dictionary
        :param issuer: Issuer ID
        """
        ms_list = self.federation_entity.get_metadata_statement(
            resp, cls=ClientMetadataStatement)

        if not ms_list:  # No metadata statement that I can use
            raise RegistrationError('No trusted metadata')

        # response is a list of registration infos

        # At this point in time I may not know within which
        # federation I'll be working.
        if len(ms_list) == 1:
            ms = ms_list[0]
            self.store_registration_info(ms.protected_claims())
            self.federation = ms.fo
            self.redirect_uris = self.registration_response['redirect_uris']
        else:
            self.registration_federations = ms_list

    def handle_response(self, response, issuer, func, response_cls):
        """
        Handle a request response. Depending on which type of response 
        it is different functions *func* will be used to handle it.
        If something went wrong an exception will be raised.
        
        :param response: A requests.request response 
        :param issuer: who was the request sent to
        :param func: A function to use for handling a correct response
        :param response_cls: The response should match this class
        """
        err_msg = 'Got error response: {}'
        unk_msg = 'Unknown response: {}'

        if response.status_code in [200, 201]:
            resp = response_cls().deserialize(response.text, "json")

            # Some implementations sends back a 200 with an error message inside
            if resp.verify():  # got a proper response
                func(resp, issuer)
            else:
                resp = ErrorResponse().deserialize(response.text, "json")
                if resp.verify():
                    logger.error(err_msg.format(sanitize(resp.to_json())))
                    if self.events:
                        self.events.store('protocol response', resp)
                    raise RegistrationError(resp.to_dict())
                else:  # Something else
                    logger.error(unk_msg.format(sanitize(response.text)))
                    raise RegistrationError(response.text)
        else:
            try:
                resp = ErrorResponse().deserialize(response.text, "json")
            except _decode_err:
                logger.error(unk_msg.format(sanitize(response.text)))
                raise RegistrationError(response.text)

            if resp.verify():
                logger.error(err_msg.format(sanitize(resp.to_json())))
                if self.events:
                    self.events.store('protocol response', resp)
                raise RegistrationError(resp.to_dict())
            else:  # Something else
                logger.error(unk_msg.format(sanitize(response.text)))
                raise RegistrationError(response.text)

    def chose_federation(self, ms_list):
        """
        Given the set of possible provider info responses I got to chose
        one. This simple method uses *federation_priority* if present.
        
        :param ms_list: List of :py:class:`fedoidc.operator.LessOrEqual` 
            instances.
        :return: A ProviderConfigurationResponse instance
        """
        for fo in self.fo_priority:
            for ms in ms_list:
                if ms.fo == fo:
                    return ms

        return ms_list[0]

    def chose_provider_federation(self, issuer):
        """
        Once a federation has been chose store the provider info in the
        normal pyoidc way.
        
        :param issuer: 
        :return: 
        """
        _leo = self.chose_federation(self.provider_federations)
        self.federation = _leo.fo
        self.handle_provider_config(_leo.protected_claims(), issuer)
        return ProviderConfigurationResponse(**_leo.protected_claims())

    def chose_registration_federation(self):
        """
        Chose one among many possible federations. Once the federation has been
        choosen store the registration info.
        
        :return: The :py:class:`LessOrEqual` instance matching the choosen 
            federation.
        """
        _leo = self.chose_federation(self.registration_federations)
        self.federation = _leo.fo
        self.store_registration_info(_leo.protected_claims)
        return ClientMetadataStatement(**_leo.protected_claims())

    def provider_config(self, issuer, keys=True, endpoints=True,
            response_cls=ProviderConfigurationResponse,
            serv_pattern=OIDCONF_PATTERN):
        """
        The high level method that should be used, by an application, to get 
        the provider info.
        
        :param issuer: The provider/issuer ID
        :param keys: Whether I should store the keys I get back form the OP
        :type keys: Boolean
        :param endpoints: Should I deal with endpoints; that is store them
            as attributes in self. 
        :param response_cls: A class to store the response information in
        :param serv_pattern: A string pattern used to build the 
            query URL.
        :return: A :py:class:`fedoidc.ProviderConfigurationResponse` instance
        """
        if issuer.endswith("/"):
            _issuer = issuer[:-1]
        else:
            _issuer = issuer

        url = serv_pattern % _issuer

        pcr = None
        r = self.http_request(url, allow_redirects=True)
        if r.status_code == 200:
            try:
                pcr = response_cls().from_json(r.text)
            except:
                _err_txt = "Faulty provider config response: {}".format(r.text)
                logger.error(sanitize(_err_txt))
                raise ParseError(_err_txt)

        if 'metadata_statements' not in pcr:
            if 'metadata_statement_uris' not in pcr:
                # Talking to a federation unaware OP
                self.store_response(pcr, r.text)
                self.handle_provider_config(pcr, issuer, keys, endpoints)
                return pcr

        # logger.debug("Provider info: %s" % sanitize(pcr))
        if pcr is None:
            raise CommunicationError(
                "Trying '%s', status %s" % (url, r.status_code))

        # 3 possible outcomes
        # a) No usable provider info -> Exception
        # b) Exactly one possible provider info to use
        # c) 2 or more usable provider info responses
        try:
            self.handle_response(r, _issuer,
                                 self.parse_federation_provider_info,
                                 ProviderConfigurationResponse)
        except RegistrationError as err:
            raise

        if self.provider_federations:
            return self.chose_provider_federation(_issuer)
        else:  # Otherwise there should be exactly one metadata statement I
            return self.provider_info

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

    def federated_client_registration_request(self, **kwargs):
        """
        Constructs a client registration request to be used by a client in a 
        federation.
        
        :param kwargs: A set of claims that should be part of the registration.
        :return: A :py:class:`ClientMetadataStatement` 
        """
        req = ClientMetadataStatement()

        try:
            req['redirect_uris'] = kwargs['redirect_uris']
        except KeyError:
            try:
                req["redirect_uris"] = self.redirect_uris
            except AttributeError:
                raise MissingRequiredAttribute("redirect_uris", kwargs)
        else:
            del kwargs['redirect_uris']

        req.update(kwargs)

        if self.federation:
            return self.federation_entity.update_request(
                req, federation=self.federation)
        elif self.provider_federations:
            return self.federation_entity.update_request(
                req, loes=self.provider_federations)

    def register(self, url, reg_type='federation', **kwargs):
        """
        Do a client registration.
        
        :param url: The registration endpoint 
        :param reg_type: If known to not be in a federation context this should 
            be set to ''.
        :param kwargs: A set of claims that should be part of the registration.
        :return: 
        """
        if reg_type == 'federation':
            req = self.federated_client_registration_request(**kwargs)
        else:
            req = self.create_registration_request(**kwargs)

        if self.events:
            self.events.store('Protocol request', req)

        headers = {"content-type": "application/json"}

        rsp = self.http_request(url, "POST", data=req.to_json(),
                                headers=headers)

        if reg_type == 'federation':
            self.handle_response(rsp, '', self.parse_federation_registration,
                                 RegistrationResponse)

            if self.registration_federations:
                return self.chose_registration_federation()
            else:  # Otherwise there should be exactly one metadata statement I
                return self.registration_response
        else:
            return self.handle_registration_info(rsp)
