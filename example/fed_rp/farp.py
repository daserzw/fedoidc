#!/usr/bin/env python3
import importlib
import json
import logging
import os
import sys

import cherrypy
from fedoidc.rp_handler import FedRPHandler
from fedoidc.test_utils import create_federation_entity
from fedoidc.test_utils import own_sign_keys

logger = logging.getLogger("")
LOGFILE_NAME = 'farp.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

SIGKEY_NAME = 'sigkey.jwks'

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
         'log.error_file': 'error.log',
         'log.access_file': 'access.log',
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

    if args.port:
        _base_url = "{}:{}".format(config.BASEURL, args.port)
    else:
        _base_url = config.BASEURL

    rph = FedRPHandler(base_url=_base_url,
                       registration_info=config.CONSUMER_CONFIG,
                       flow_type='code', hash_seed="BabyHoldOn",
                       scope=config.CONSUMER_CONFIG['scope'])

    sign_kj = own_sign_keys(SIGKEY_NAME, _base_url, config.SIG_DEF_KEYS)

    # internalized request signing server using the superiors keys
    rp_fed_ent = create_federation_entity(iss=_base_url, ms_dir=config.MS_DIR,
                                          jwks_dir=config.JWKS_DIR,
                                          sup=config.SUPERIOR,
                                          fo_jwks=config.FO_JWKS,
                                          sig_keys=sign_kj,
                                          sig_def_keys=config.SIG_DEF_KEYS)
    rph.federation_entity=rp_fed_ent

    cherrypy.tree.mount(cprp.Consumer(rph, 'html'), '/', provider_config)

    # If HTTPS
    if args.tls:
        cherrypy.server.ssl_certificate = config.SERVER_CERT
        cherrypy.server.ssl_private_key = config.SERVER_KEY
        if config.CA_BUNDLE:
            cherrypy.server.ssl_certificate_chain = config.CA_BUNDLE

    cherrypy.engine.start()
    cherrypy.engine.block()
