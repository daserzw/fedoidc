#!/usr/bin/env python3
import importlib
import json
import logging
import os
import sys
from urllib.parse import quote_plus

import cherrypy
import requests
from jwkest import as_bytes, as_unicode

from oic.exception import MessageException
from oic.oauth2 import VerificationError
from oic.utils.keyio import build_keyjar

from fedoidc import MetadataStatement
from fedoidc.signing_service import InternalSigningService
from fedoidc.signing_service import Signer

logger = logging.getLogger("")


def setup_log(name):
    logfile_name = '{}.log'.format(name)
    hdlr = logging.FileHandler(logfile_name)
    base_formatter = logging.Formatter(
        "%(asctime)s %(name)s:%(levelname)s %(message)s")

    hdlr.setFormatter(base_formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.DEBUG)


class Operator(object):
    def __init__(self, signer):
        self.signer = signer

    @cherrypy.expose
    def index(self, **kwargs):
        if cherrypy.request.process_request_body is True:
            _json_doc = cherrypy.request.body.read()
        else:
            raise cherrypy.HTTPError(400, 'Missing Client registration body')

        if _json_doc == b'':
            raise cherrypy.HTTPError(400, 'Missing Client registration body')

        _args = json.loads(as_unicode(_json_doc))
        _mds = MetadataStatement(**_args)

        try:
            _mds.verify()
        except (MessageException, VerificationError) as err:
            raise cherrypy.CherryPyException(str(err))
        else:
            _jwt = self.signer.create_signed_metadata_statement(_mds,
                                                                single=True)
            cherrypy.response.headers['Content-Type'] = 'application/jwt'
            return as_bytes(_jwt)

    def keys(self):
        return as_bytes(self.signer.signing_service.signing_keys.export_jwks())

    @cherrypy.expose
    def register(self, url):
        if cherrypy.request.process_request_body is True:
            _json_doc = cherrypy.request.body.read()
        else:
            raise cherrypy.HTTPError(400, 'Missing Client registration body')

        if _json_doc == b'':
            raise cherrypy.HTTPError(400, 'Missing Client registration body')

        _args = json.loads(as_unicode(_json_doc))
        _mds = MetadataStatement(**_args)

        try:
            _mds.verify()
        except (MessageException, VerificationError) as err:
            raise cherrypy.CherryPyException(str(err))
        else:
            res = requests.post(url, json=_mds.to_json())
            if 200 <= res.status_code < 300:
                self.signer.metadata_statements[url] = res.text
                cherrypy.response.headers['Content-Type'] = 'application/jwt'
                return as_bytes(res.text)
            else:
                raise cherrypy.HTTPError(message=res.text)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', dest='port', default=80, type=int)
    parser.add_argument('-t', dest='tls', action='store_true')
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    folder = os.path.abspath(os.curdir)

    cherrypy.config.update(
        {'environment': 'production',
         'log.error_file': 'site.log',
         'tools.trailing_slash.on': False,
         'server.socket_host': '0.0.0.0',
         'log.screen': True,
         'tools.sessions.on': True,
         'tools.encode.on': True,
         'tools.encode.encoding': 'utf-8',
         'server.socket_port': args.port
         })

    operator_config = {
        '/': {
            'root_path': 'localhost',
            'log.screen': True
        },
        '/static': {
            'tools.staticdir.dir': os.path.join(folder, 'static'),
            'tools.staticdir.debug': True,
            'tools.staticdir.on': True,
            'log.screen': True,
            'cors.expose_public.on': True
        }}

    # Service specifics

    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)

    if args.port:
        _signer_id = "{}:{}".format(config.SIGNER_ID, args.port)
    else:
        _signer_id = config.SIGNER_ID

    _keydefs = []
    for spec in config.KEYDEFS:
        spec['key'] = spec['key'].format(quote_plus(_signer_id))
        _keydefs.append(spec)

    sig_keys = build_keyjar(_keydefs)[1]
    signing_service = InternalSigningService(iss=_signer_id,
                                             signing_keys=sig_keys)
    signer = Signer(signing_service, config.MS_DIR)

    cherrypy.tree.mount(Operator(signer), '/', operator_config)

    # If HTTPS
    if args.tls:
        cherrypy.server.ssl_certificate = config.SERVER_CERT
        cherrypy.server.ssl_private_key = config.SERVER_KEY
        if config.CA_BUNDLE:
            cherrypy.server.ssl_certificate_chain = config.CA_BUNDLE

    cherrypy.engine.start()
    cherrypy.engine.block()
