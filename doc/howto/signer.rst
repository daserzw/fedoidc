.. _howto_signer:

How to Implement a signer
=========================

An Signer is an entity that can sign metadata statements. If configured
with one the signer can use a signing_service
(:py:class:`fedoidc.signing_service.SigningService` instance) to do the
actual signing. There are presently only two types of signing services.

* :py:class:`fedoidc.signing_service.InternalSigningService`, is as it says
  an internal service bound to the signer.
* :py:class:`fedoidc.signing_service.WebSigningService` om the other hand, is
  a web client that will use a web based signing service to perform the
  signing. The web based signing service is expected to get a **POST** with
  the request as the body and is supposed to respond with a signed metadata
  statement.

A signer might have a number of signed metadata statements that it can add to
the request before letting the signing service sign the request. These
signed metadata statements are best kept in a directory using a number of
:py:class:`fedoidc.file_system:FileSystem` instances. A *FileSystem* instance
is a simple key, value database where the values are stored in files and the
keys are the names of the files.
Since a signed metadata statement are expected to be used in a special context
(:py:data:`fedoidc.CONTEXTS`) there will be one *FileSystem* instance per
context.

On disc it would look something like this::

    - 'discovery'
         |
         +-- 'https://fo.feide.no/'
         |
         +-- 'https://fo.swamid.se/'


If you had an RP that belong to 2 Federations operators (SWAMID and FEIDE).
In the file ../discovery/https%3A%2F%2Ffo.feide.no%2F you would find a
signed metadata statement, signed by FEIDE.
**Note** that the filename is the FOs ID quote_plus encoded.

Using a *FileSystem* instance allows the administrator to just drop a new
entry into the file system and have the instance imediately pick it up.
Updates can be handled in a similar maner.

So instantiating a Signer can be done like this.

First the signing service. We assume we have JWKS representing the private
keys the signing service will use on disc in a file called 'sigserv.jwks' .::

    from fedoidc.bundle import jwks_to_keyjar
    from fedoidc.signing_service import InternalSigningService

    kj = jwks_to_keyjar(open('sigserv.jwks').read())
    sign_serv = InternalSigningService('https://oa.example.com', kj)

Next the Signer. The Signer needs the signing service and to know where
to find the signed metadata statements that it should add to the request
before handing it over to the signing service. Let's assume that the
directory where the signed metadata statements (or uri's pointing to them)
can be found is named 'sms'::


    signer = Signer(sign_serv, 'sms')

    signer =