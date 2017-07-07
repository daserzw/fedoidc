.. _howto_provider:

How to Implement a Federation aware OIDC Provider
=================================================

A federation aware OIDC Provider can do a couple of extra things compare to a
normal OP.

To do this extra things it needs some help. This help is provide by two
class instances:

* federation_entity, a :py:class:`fedoidc.entity.FederationEntity` instance
* signer, a :py:class:`fedoidc.signing_service.Signer` instance

