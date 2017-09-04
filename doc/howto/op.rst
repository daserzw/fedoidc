.. _howto_provider:

How to Implement a Federation aware OIDC Provider
=================================================

A federation aware OIDC Provider can do a couple of extra things compare to a
normal OP.

To do this extra things it needs some help. This help is provide by two
class instances:

* federation_entity, a :py:class:`fedoidc.entity.FederationEntity` instance
* signer, a :py:class:`fedoidc.signing_service.Signer` instance

You can learn how to set up a signer in :ref:`howto_signer` and a
federation entity in :ref:`howto_entity` .

Setting up a federation aware Provider then boils down to something like
this. Most of which is exactly the same as if you where to start a
'normal' OIDC OP. The only difference is the last line. ::

    from fedoidc.provider import Provider

    sunet_op = 'https://sunet.se/op'

    op = Provider(sunet_op, SessionDB(sunet_op), {}, AUTHN_BROKER,
        USERINFO, AUTHZ, client_authn=verify_client, symkey=SYMKEY,
        federation_entity=fed_ent, signer=signer)


Now who you use this instance is exactly the same as with a 'normal' OP,
you use the :py:meth:`fedoidc.provider.Provider.providerinfo_endpoint` and
:py:meth:`fedoidc.provider.Provider.registration_endpoint` methods.