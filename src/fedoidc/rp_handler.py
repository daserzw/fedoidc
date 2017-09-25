import hashlib
import logging
import sys
import traceback

from oic.utils.keyio import key_export

from fedoidc import client
from jwkest import as_bytes

from oic import rndstr
from oic.oauth2 import PBase
from oic.oauth2.message import ErrorResponse
from oic.oic.message import AccessTokenResponse
from oic.oic.message import AuthorizationRequest
from oic.oic.message import AuthorizationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.webfinger import WebFinger

__author__ = 'rolandh'

logger = logging.getLogger(__name__)


class HandlerError(Exception):
    pass


def token_secret_key(sid):
    return "token_secret_%s" % sid


SERVICE_NAME = "OIC"
CLIENT_CONFIG = {}


class FedRPHandler(object):
    def __init__(self, base_url='', registration_info=None, flow_type='code',
            federation_entity=None, hash_seed="", scope=None,
            verify_ssl=False, keyjar=None, **kwargs):
        self.federation_entity = federation_entity
        self.flow_type = flow_type
        self.registration_info = registration_info
        self.base_url = base_url
        self.hash_seed = as_bytes(hash_seed)
        self.scope = scope or ['openid']
        self.verify_ssl = verify_ssl
        self.keyjar = keyjar

        if self.base_url.endswith('/'):
            _int = ''
        else:
            _int = '/'

        try:
            self.jwks_uri = '{}{}{}'.format(self.base_url, _int,
                                            kwargs['jwks_path'])
        except KeyError:
            self.jwks_uri = ''
        try:
            self.signed_jwks_uri = '{}{}{}'.format(self.base_url, _int,
                                                  kwargs['signed_jwks_path'])
        except KeyError:
            self.signed_jwks_uri = ''

        self.extra = kwargs

        self.access_token_response = AccessTokenResponse
        self.client_cls = client.Client
        self.authn_method = None
        self.issuer2rp = {}
        self.state2issuer = {}
        self.hash2issuer = {}

    def dynamic(self, callback, logout_callback, issuer):
        try:
            client = self.issuer2rp[issuer]
        except KeyError:
            client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD,
                                     verify_ssl=self.verify_ssl)
            client.redirect_uris = [callback]
            client.post_logout_redirect_uris = [logout_callback]
            client.federation_entity = self.federation_entity
            client.keyjar = self.keyjar
            client.jwks_uri = self.jwks_uri
            client.signed_jwks_uri = self.signed_jwks_uri

            provider_conf = client.provider_config(issuer)

            logger.debug("Got provider config: %s", provider_conf)

            logger.debug("Registering RP")
            _me = self.registration_info.copy()
            _me["redirect_uris"] = [callback]
            if self.jwks_uri:
                _me['jwks_uri'] = self.jwks_uri

            if client.federation:
                if self.signed_jwks_uri:
                    _me['signed_jwks_uri'] = self.signed_jwks_uri
                reg_info = client.register(
                    provider_conf["registration_endpoint"], **_me)
            else:
                reg_info = client.register(
                    provider_conf["registration_endpoint"], reg_type='core',
                    **_me)

            logger.debug("Registration response: %s", reg_info)
            for prop in ["client_id", "client_secret"]:
                try:
                    setattr(client, prop, reg_info[prop])
                except KeyError:
                    pass

            self.issuer2rp[issuer] = client
        return client

    def create_callback(self, issuer):
        _hash = hashlib.sha256()
        _hash.update(self.hash_seed)
        _hash.update(as_bytes(issuer))
        _hex = _hash.hexdigest()
        self.hash2issuer[_hex] = issuer
        return "{}/authz_cb/{}".format(self.base_url, _hex)

    # noinspection PyUnusedLocal
    def begin(self, issuer):
        """
        Make sure we have a client registered at the issuer

        :param issuer: Issuer ID
        """
        try:
            try:
                client = self.issuer2rp[issuer]
            except KeyError:
                callback = self.create_callback(issuer)
                logout_callback = self.base_url
                client = self.dynamic(callback, logout_callback, issuer)

            _state = rndstr(24)
            self.state2issuer[_state] = issuer
            return self.create_authnrequest(client, _state)
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise HandlerError(
                "Cannot find the OP! Please view your configuration.")

    # noinspection PyUnusedLocal
    def create_authnrequest(self, client, state):
        """
        Constructs an Authorization Request

        :param client: A Client instance
        :param state: State variable
        :return: Dictionary with response headers
        """
        try:
            request_args = {
                "response_type": self.flow_type,
                "scope": self.scope,
                "state": state,
            }

            if self.flow_type == "token":
                request_args["nonce"] = rndstr(16)
            else:
                use_nonce = getattr(self, "use_nonce", None)
                if use_nonce:
                    request_args["nonce"] = rndstr(16)

            logger.info("client args: %s", list(client.__dict__.items()))
            logger.info("request_args: %s", request_args)
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise HandlerError(
                "Cannot find the OP! Please view your configuration.")

        try:
            cis = client.construct_AuthorizationRequest(
                request_args=request_args)
            logger.debug("request: %s", cis)

            url, body, ht_args, cis = client.uri_and_body(
                AuthorizationRequest, cis, method="GET",
                request_args=request_args)
            logger.debug("body: %s", body)
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise HandlerError("Authorization request can not be performed!")

        logger.info("URL: %s", url)
        logger.debug("ht_args: %s", ht_args)

        resp_headers = {"Location": str(url)}
        if ht_args:
            resp_headers.update(ht_args)

        logger.debug("resp_headers: %s", resp_headers)
        return resp_headers

    def get_accesstoken(self, client, authresp):
        issuer = client.provider_info["issuer"]
        key = client.keyjar.get_verify_key(owner=issuer)
        kwargs = {"key": key}

        if self.authn_method:
            kwargs["authn_method"] = self.authn_method

        logger.debug('access_token_request args: {}'.format(kwargs))

        # get the access token
        return client.do_access_token_request(
            state=authresp["state"], response_cls=self.access_token_response,
            **kwargs)

    # noinspection PyUnusedLocal
    def verify_token(self, client, access_token):
        return {}

    def get_userinfo(self, client, authresp, access_token, **kwargs):
        # use the access token to get some userinfo
        return client.do_user_info_request(state=authresp["state"],
                                           schema="openid",
                                           access_token=access_token,
                                           **kwargs)

    # noinspection PyUnusedLocal
    def phaseN(self, client, response):
        """Step 2: Once the consumer has redirected the user back to the
        callback URL you can request the access token the user has
        approved."""

        authresp = client.parse_response(AuthorizationResponse, response,
                                         sformat="dict", keyjar=client.keyjar)

        if isinstance(authresp, ErrorResponse):
            return False, "Access denied"

        try:
            client.id_token = authresp["id_token"]
        except KeyError:
            pass

        if self.flow_type == "code":
            # get the access token
            try:
                tokenresp = self.get_accesstoken(client, authresp)
            except Exception as err:
                logger.error("%s", err)
                raise

            if isinstance(tokenresp, ErrorResponse):
                return False, "Invalid response %s." % tokenresp["error"]

            access_token = tokenresp["access_token"]
        else:
            access_token = authresp["access_token"]

        # userinfo = self.verify_token(client, access_token)

        inforesp = self.get_userinfo(client, authresp, access_token)

        if isinstance(inforesp, ErrorResponse):
            return False, "Invalid response %s." % inforesp["error"]

        # tot_info = userinfo.update(inforesp.to_dict())

        logger.debug("UserInfo: %s", inforesp)

        return True, inforesp, access_token, client

    # noinspection PyUnusedLocal
    def callback(self, query, hash):
        """
        This is where we come back after the OP has done the
        Authorization Request.

        :param query:
        :return:
        """

        try:
            assert self.state2issuer[query['state']] == self.hash2issuer[hash]
        except AssertionError:
            raise HandlerError('Got back state to wrong callback URL')
        except KeyError:
            raise HandlerError('Unknown state or callback URL')

        del self.hash2issuer[hash]

        try:
            client = self.issuer2rp[self.state2issuer[query['state']]]
        except KeyError:
            raise HandlerError('Unknown session')

        del self.state2issuer[query['state']]

        try:
            result = self.phaseN(client, query)
            logger.debug("phaseN response: {}".format(result))
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise HandlerError("An unknown exception has occurred.")

        return result

    def find_srv_discovery_url(self, resource):
        """
        Use Webfinger to find the OP, The input is a unique identifier
        of the user. Allowed forms are the acct, mail, http and https
        urls. If no protocol specification is given like if only an
        email like identifier is given. It will be translated if possible to
        one of the allowed formats.

        :param resource: unique identifier of the user.
        :return:
        """

        try:
            wf = WebFinger(httpd=PBase(ca_certs=self.extra["ca_bundle"]))
        except KeyError:
            wf = WebFinger(httpd=PBase(verify_ssl=False))

        return wf.discovery_query(resource)
