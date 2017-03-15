#!/usr/bin/env python3
from urllib.parse import quote_plus, unquote_plus

import cherrypy
import importlib
import logging
import os
import sys

from fedoidc.bundle import FSJWKSBundle
from fedoidc.entity import FederationEntity
from fedoidc.signing_service import Signer, SigningService

from fed_rp.rp_handler import FedRPHandler

from oic.utils.keyio import build_keyjar


logger = logging.getLogger("")
LOGFILE_NAME = 'farp.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)


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

    provider_config = {
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

    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)
    cprp = importlib.import_module('cprp')

    _kj = build_keyjar(config.KEYDEFS)[1]
    signer = Signer(SigningService(config.base_url, _kj), config.ms_dir)
    fo_keybundle = FSJWKSBundle('', fdir='fo_jwks',
                      key_conv={'to': quote_plus, 'from': unquote_plus})

    rp_fed_ent = FederationEntity(None, keyjar=_kj, iss=config.base_url,
                                  signer=signer,
                                  fo_bundle=fo_keybundle)

    rph = FedRPHandler(base_url='', registration_info=None, flow_type='code',
                       federation_entity=None, hash_seed="", scope=None)

    cherrypy.tree.mount(cprp.Consumer(rph), '/', provider_config)

    # If HTTPS
    if args.tls:
        cherrypy.server.ssl_certificate = config.SERVER_CERT
        cherrypy.server.ssl_private_key = config.SERVER_KEY
        if config.CA_BUNDLE:
            cherrypy.server.ssl_certificate_chain = config.CA_BUNDLE

    cherrypy.engine.start()
    cherrypy.engine.block()
