import logging

from oic.exception import RegistrationError

from oic import oic
from fedoidc import ClientMetadataStatement
from oic.oauth2 import ErrorResponse
from oic.oauth2 import MissingRequiredAttribute
from oic.oauth2 import sanitize
from oic.oic import RegistrationResponse

try:
    from json import JSONDecodeError
except ImportError:  # Only works for >= 3.5
    _decode_err = ValueError
else:
    _decode_err = JSONDecodeError

logger = logging.getLogger(__name__)

__author__ = 'roland'


class Client(oic.Client):
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

    def parse_federation_provider_info(self, resp):
        """

        :param resp: A MetadataStatement instance
        """
        resp = self.federation_entity.get_metadata_statement(
            resp, cls=RegistrationResponse)

        if not resp:  # No metadata statement that I can use
            raise RegistrationError('No trusted metadata')

        # response is a dictionary with the FO ID as keys and the
        # registration info as values

        # At this point in time I may not know within which
        # federation I'll be working.
        if len(resp) == 1:
            iss = list(resp.keys())[0]
            self.store_registration_info(resp[iss])
            self.federation = iss
        else:
            self.provider_federations = resp

    def handle_registration_info(self, response):
        err_msg = 'Got error response: {}'
        unk_msg = 'Unknown response: {}'

        if response.status_code in [200, 201]:
            resp = RegistrationResponse().deserialize(response.text, "json")

            # Some implementations sends back a 200 with an error message inside
            if resp.verify():  # got a proper registration response
                self.parse_federation_provider_info(resp)
                self.store_response(resp, response.text)
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

        return resp

    def federated_client_registration_request(self, **kwargs):
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

        _fe = self.federation_entity
        if self.federation:
            _cms = _fe.create_metadata_statement_request(req, [self.federation])
            sms = _fe.signer.signing_service(_cms)
            req['metadata_statements'] = [sms]
        else:
            _fos = list(self.provider_federations.keys())
            _cms = _fe.create_metadata_statement_request(req, _fos)
            sms = _fe.signer.signing_service(_cms)
            req['metadata_statements'] = [sms]

        return req

    def register(self, url, **kwargs):
        try:
            reg_type = kwargs['registration_type']
        except KeyError:
            reg_type = 'core'
        else:
            del kwargs['registration_type']

        if reg_type == 'federation':
            req = self.federated_client_registration_request(**kwargs)
        else:
            req = self.create_registration_request(**kwargs)

        if self.events:
            self.events.store('Protocol request', req)

        headers = {"content-type": "application/json"}

        rsp = self.http_request(url, "POST", data=req.to_json(),
                                headers=headers)

        return self.handle_registration_info(rsp)

    def handle_provider_config(self, pcr, issuer, keys=True, endpoints=True):
        pass

    def create_signed_metadata_statement(self, statement, fos=None, setup=None):
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
