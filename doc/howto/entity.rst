.. _howto_entity:

How to Implement a Federation aware entity
==========================================

An Entity is an OIDC entity that participates in a federation.
It builds on :py:class:`fedoidc.operator.Operator` who's usage is
described in :ref:`howto_operator`.

:py:class:`fedoidc.Entity.FederationEntity` is used by a federation
aware OIDC Provider and Client. It can also be used by other
entity types (like a resources server) that needs to made federation aware.

A py:class:`fedoidc.entity.FederationEntity` instance needs a couple of things:

* Keys, in the form of :py:class:`oic.utils:keyio.KeyJar` instance that the
  entity can use to sign information.
* A Web client, normally provided by the provider or client. Needed if you
  expect to use *metadata_statement_uris*
* Signer, an :py:class:`fedoidc.signing_service.Signer` that can sign a
  metadata statement.
* Bundle of Federation operators public keys in the form or a
  :py:class:`fedoidc.bundle.JWKSBundle` or
  :py:class:`fedoidc.bundle.FSJWKSBundle` instance.

Provided we have the entity's signing keys in a file as a JWKS, we can do ::

    from fedoidc.bundle import jwks_to_keyjar

    entity_kj = jwks_to_keyjar(open('entity_key.jwks').read())

To instantiate a signer we can do as in :ref:`howto_signer`. ::

    from fedoidc.bundle import jwks_to_keyjar
    from fedoidc.signing_service import InternalSigningService
    from fedoidc.signing_service import Signer

    kj = jwks_to_keyjar(open('sigserv.jwks').read())
    sign_serv = InternalSigningService('https://oa.example.com', kj)
    signer = Signer(sign_serv, 'sms')

Regarding the FO key bundle. If we use a :py:class:`fedoidc.bundle.FSJWKSBundle`,
then we have to provide the directory where the JWKSs are stored (Federator
Operator ID as key/file names and the JWKS as values in the file).

A JWKSBundle/FSJWKSBundle instance can export it's bundle. If so it will need a
key for signing the export, otherwise not. The same with issuer ID.
In this example we assume it will not export it's bundle.
If it's not going to export it also won't need an
ID, so we leave that out to. Which get's ut to ::

    from fedoidc.bundle import FSJWKSBundle

    fsjb = FSJWKSBundle('', None, 'fo_jwks',
                        key_conv={'to': quote_plus, 'from': unquote_plus})


And then to wrap it all up ::

    from fedoidc.entity FederationEntity

    fed_entity = FederationEntity(None, keyjar=entity_kj, signer=signer,
                                  fo_bundle=fsjb)


