==================================================
The SWAMID profile for a OpenID Connect federation
==================================================

------------
Introduction
------------

This document describes how the Swedish Academic Identity Federation
(SWAMID) is planning to build an identity federation using OpenID Connect (`OIDC`_).
What is describe here is a profile of the `OIDC federation draft`_

.. _OIDC: http://openid.net/specs/openid-connect-core-1_0.html
.. _OIDC federation draft: http://openid.net/specs/openid-connect-federation-1_0.html).

--------
Entities
--------

RP
    A Relying Party.
OP
    A OpenID Provider.
MDSS
    The Metadata Signing Service for the SWAMID Federation.
FO
    The Federation Operator

-----------------
Division of labor
-----------------

The FO handles the enrolment, verifies the correctness of the entity metadata statement
is responsible for any additions to the metadata that the FO process
demands (like adding entity_categories).

The MDSS gets processed metadata statements from the FO and deals with the signing
and distribution of the signed metadata statements.

-----------------------
The Federation operator
-----------------------

Is anyone that wants to create a multi lateral federation of RPs and OPs.

-------------------
The Signing Service
-------------------

The Signing Service is a key part of the architecture. Each federation MUST deploy one.
A Metadata Signing Service (MDSS) has control over the private part of the Federations signing key.

A MDSS will make the following public API calls available:

- GET */getms/{entityID}*. Returns a signed JWT containing a collection of signed MS for *entityID*.
  This collection is a JSON object whose keys are federation IDs and the values are URLs where the
  corresponding Signed Metadata statements can be found.

 - Simple response example, where "https://fo.example.edu/" is the identifier
   of the FO and "https://rp.example.com/ms.jws" is the RP's entity ID:

   - {"https://fo.example.edu/": "https://mdss.fo.example.edu/getms/https%3A%2F%2Frp.example.com%2Fms.jws/https%3A%2F%2Ffo.example.edu%2F"}

- GET */getms/{entityID}/{FO}*. Returns the Signed Metadata Statement as a signed JSON Web Token for
  *entityID* in the federation *FO*.

------------------------------
Service provided by each RP/OP
------------------------------
Each RP/OP has to provide a web endpoint from which the entity's
metadata statement can be fetch. What's is returned from this endpoint is the
entity's metadata statement signed by the entity's signing key.

---------------------
The enrolment process
---------------------

Entities (RP/OP) can enrol to become part of the federation.
In the description below I will use an RP as the entity who wants
to enrol. If you want to enrol an OP, exactly the same process must
be followed.

The steps are

1 The RP sends

    - the public part of its signing key,
    - the URL the Federation Operator (FO) should use to fetch the RP's
      metadata statement and
    - an entity ID (for an OP this is the issuer ID). The entityID SHOULD be the URL mentioned above.

2 The FO fetched the metadata statement, which is represented as a
  signed JSON Web Token, signed by the RPs private key, and verifies the signature.
  The public part of the RP's signing key are expected to be part
  of the metadata statement.
3 If the FO accepts the metadata statement as syntactically correct and
  adhering to the Federations policy. It will add the metadata statement
  to the list of metadata statements that can be signed by the MDSS.

After this the FO will at intervals do (2). If nothing has
change in the metadata nothing more will happen. If something has changed
then the FO will do (3).

------------------------------------
Using the signed metadata statements
------------------------------------

Once the RP has been accepted by the FO it can start acting within
the federation. This is what happens then:

1 When the RP needs to construct a client registration request it will
  ask the FO for the current set of Federations/Communities it belongs to.
  It does that by doing a GET on */getms/{entityID}*.
2 When the OP receives the client registration request it can use the
  metadata_statement_uris (which all points to the FOs MDSS) to find the signed
  metadata statements. This means that only metadata_statement_uris can be used
  in the client registration request. No metadata_statements by value are allowed.

-------------------------------------------------
What if the RP wants to change it's signing key ?
-------------------------------------------------

At some time after enrolment the RP wants to rotate it's signing key it will
have to do a new enrolment. There is no need at this point for the published URL
or the entity_id to change.

There are reasons for the OP to issue the same client_id to the RP after the
change in signing key. One way of solving this is to use the entity_id (or
a derivative of it) as client_id.