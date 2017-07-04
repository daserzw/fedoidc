.. _howto_operator:

How to Implement a Federation aware operator
============================================

An Operator is an entity that participates in a federation.
It can be a shell script run by a person, a service or an OIDC entity.

An Operator needs two things to work.

* KeyJar instance (kj)
* Issuer ID (iss)

Assuming you have those and a file (req_file) containing a request in the
form of a JSON document, you can do this::

    import json
    from oic.utils.keyio import KeyJar
    from fedoidc import MetadataStatement
    from fedoidc.operator import Operator

    op = Operator(keyjar=kj, iss=iss)
    _req = json.loads(open(req_file).read())
    req = MetadataStatement(**_req)
    sms = op.pack_metadata_statement(req)


sms will contain a signed JSON Web token.

More about what you can do with an Operator in
:py:class:`fedoidc.operator.Operator`.

You can also look at the script scripts/packer.py .

If an Operator is expected to unpack signed metadata statements it will need
one or more Federation Operators keys. This is provided using the jwks_bundle
argument.
An example using the same values as above::

    bundle = JWKSBundle('')
    bundle[iss] = kj

    op = Operator(jwks_bundle=bundle)
    pi = op.unpack_metadata_statement(jwt_ms=sms)

The result of the unpacking is an :py:class:`fedoidc.operator.ParseInfo` instance if everything
goes OK.

Going further involves doing evaluate_metadata_statement ::

    loel = op.evaluate_metadata_statement(pi.result)

loel is a list of :py:class:`fedoidc.operator.LessOrEqual` instances.
You can look at the information in the instance like this ::

    federation_operator = loel[0].fo
    protected_claims = loel[0].protected_claims()
    all_claims = loel[0].unprotected_and_protected_claims()

