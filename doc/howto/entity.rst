.. _howto_entity:

How to Implement a Federation aware entity
==========================================

An Entity is an OIDC entity that participates in a federation.
It builds on :py:class:`fedoidc.operator.Operator` who's usage is
described in :ref:`howto_operator`.

:py:class:`fedoidc.Entity.FederationEntity` is used by a federation
aware OIDC Provider and Client. It can also be used by other
entity types (like a resources server) that you want to make federation aware.

A py:class:`fedoidc.entity.FederationEntity` instance needs a couple of things:

* Keys, in the form of :py:class:`oic.utils:keyio.KeyJar` instance
* A Web client, normally provided by the provider or client. Needed if you expect to use
  *metadata_statement_uris*
* Signer, an :py:class:`fedoidc.signing_service.Signer` that can sign a metadata statement.
* Bundle of Federation operators public keys. A :py:class:`fedoidc.bundle.JWKSBundle` or
  :py:class:`fedoidc.bundle.FSJWKSBundle` instance.

