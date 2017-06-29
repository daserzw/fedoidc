.. _howto_rp:

How to Implement a Federation aware OIDC Client
===============================================

In the following description it is assumed that you have read the
documentation on how to set up a client using basic pyoidc.
So I will concentrate on what you have to do in addition to that.

There are two places where a federation aware client will do things differently
from a *normal* pyoidc client and that is provider info
discovery and dynamic client registration.

But first before we get into that some necessary basics.

Set up
------

First we must link in the federation functionality. You can do that by
using the Client class from fedoidc.client instead of the one from oic.client.
Hence somewhere in the beginning of your client script you should have

::

    from fedoidc.client import Client
    from fedoidc.entity import FederationEntity
    from oic.utils.authn.client import CLIENT_AUTHN_METHOD
    from oic.utils.keyio import build_keyjar

    KEYDEFS = [
        {"type": "RSA", "key": '', "use": ["sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]}
    ]

    _kj = build_keyjar(KEYDEFS)[1]
    signer = Signer(None, 'sms_dir', 'register')
    rp_fed_ent = FederationEntity(None, keyjar=_kj, iss=uninett_op,
                                  signer=signer, fo_bundle=fo_keybundle)

    client = Client(client_authn_method=CLIENT_AUTHN_METHOD,
                    federation_entity=rp_fed_ent)

I've started with the setup described in the pyoidc documentation and then
added the specific federation parts. I'll go through them one line at the time


Provider Info discovery
-----------------------
