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
from jwkest.jws import JWS
from oic.utils.keyio import build_keyjar, KeyJar

from fedoidc.utils import store_signed_jwks

logger = logging.getLogger("")
LOGFILE_NAME = 'farp.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

SIGKEY_NAME = 'sigkey.jwks'


def get_jwks(path, private_path):
    if os.path.isfile(private_path):
        _jwks = open(path, 'r').read()
        _kj = KeyJar()
        _kj.import_jwks(json.loads(_jwks), '')
    else:
        _kj = build_keyjar(config.ENT_KEYS)[1]
        jwks = _kj.export_jwks(private=True)
        fp = open(private_path, 'w')
        fp.write(json.dumps(jwks))
        fp.close()

    jwks = _kj.export_jwks()  # public part
    fp = open(path, 'w')
    fp.write(json.dumps(jwks))
    fp.close()

    return _kj


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
            'tools.staticdir.content_types': {
                'json': 'application/json',
                'jwks': 'application/json',
                'jose': 'application/jose'
            },
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

    _kj = get_jwks(config.JWKS_PATH, 'keys/jwks.json')

    rph = FedRPHandler(base_url=_base_url,
                       registration_info=config.CONSUMER_CONFIG,
                       flow_type='code', hash_seed="BabyHoldOn",
                       scope=config.CONSUMER_CONFIG['scope'],
                       keyjar=_kj,
                       jwks_path=config.JWKS_PATH,
                       signed_jwks_path=config.SIGNED_JWKS_PATH)

    sign_kj = own_sign_keys(SIGKEY_NAME, _base_url, config.SIG_DEF_KEYS)
    store_signed_jwks(_kj, sign_kj, config.SIGNED_JWKS_PATH,
                      config.SIGNED_JWKS_ALG, iss=_base_url)

    # internalized request signing server using the superiors keys
    rp_fed_ent = create_federation_entity(iss=_base_url, ms_dir=config.MS_DIR,
                                          jwks_dir=config.JWKS_DIR,
                                          sup=config.SUPERIOR,
                                          fo_jwks=config.FO_JWKS,
                                          sig_keys=sign_kj,
                                          sig_def_keys=config.SIG_DEF_KEYS)
    rph.federation_entity = rp_fed_ent

    cherrypy.tree.mount(cprp.Consumer(rph, 'html'), '/', provider_config)

    # If HTTPS
    if args.tls:
        cherrypy.server.ssl_certificate = config.SERVER_CERT
        cherrypy.server.ssl_private_key = config.SERVER_KEY
        if config.CA_BUNDLE:
            cherrypy.server.ssl_certificate_chain = config.CA_BUNDLE

    cherrypy.engine.start()
    cherrypy.engine.block()
