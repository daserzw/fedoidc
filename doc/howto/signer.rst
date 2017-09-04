.. _howto_signer:

How to Implement a signer
=========================

An Signer is an entity that can sign metadata statements. If configured
with one the signer can use a signing_service
(`:py:class:`fedoidc.signing_service.SigningService`` instance) to do the
actual signing. There are presently only two types of signing services.

* :py:class:`fedoidc.signing_service.InternalSigningService`, is as it says
  an internal service bound to the signer.
* :py:class:`fedoidc.signing_service.WebSigningService` om the other hand, is
  a web client that will use a web based signing service to perform the
  signing. The web based signing service is expected to get a **POST** with
  the request as the body and is supposed to respond with a signed metadata
  statement.

A signer might have a number of signed metadata statements that it wants to add
to a request before letting the signing service sign the request. These
signed metadata statements are best kept in a directory using a set of
:py:class:`fedoidc.file_system:FileSystem` instances. A *FileSystem* instance
is a simple key, value database where the values are stored in files and the
keys are the names of the files.
Since a signed metadata statement are expected to be used in a special context
(:py:data:`fedoidc.CONTEXTS`) there will be one *FileSystem* instance per
context.

Assume that you have an RP that belong to 2 Federations operators (FOs),
SWAMID and FEIDE, with the Issuer IDs https://fo.feide.no/ and
https://fo.swamid.se/ respectively.

Then the discovery *FileSystem* would look something like this on disc::

    - 'discovery'
         |
         +-- 'https://fo.feide.no/'
         |
         +-- 'https://fo.swamid.se/'


**Note** that in reality the filename is the FOs ID quote_plus encoded.

Therefor in the file ../discovery/https%3A%2F%2Ffo.feide.no%2F you would find a
signed metadata statement, signed by FEIDE.

Using a *FileSystem* instance allows the administrator to just drop a new
entry into the file system and have the instance imediately pick it up.
Updates can be handled in a similar maner.

So instantiating a Signer can be done like this.

First the signing service. We assume we have a JWKS representing the private
keys the signing service will use on disc in a file called 'sigserv.jwks' .::

    from fedoidc.bundle import jwks_to_keyjar
    from fedoidc.signing_service import InternalSigningService

    kj = jwks_to_keyjar(open('sigserv.jwks').read())
    sign_serv = InternalSigningService('https://oa.example.com', kj)

Next the Signer. The Signer needs the signing service and to know where
to find the signed metadata statements that it should add to the request
before handing it over to the signing service. Let's assume that the
directory where the signed metadata statements (or uri's pointing to them)
can be found is named 'sms'. You then get to instanciate like this ::


    signer = Signer(sign_serv, 'sms')

And that's it.

Now to use this signer we will use the method
:py:meth:`fedoidc.signing_service.Signer.create_signed_metadata_statement` .
The two arguments we will care about here is the *request* and the *context*.
*request* is no surprise the statement that should be signed and the
*context* is which context the statement will be used in.
The list of supported contexts can be found here :py:data:`fedoidc.CONTEXTS`.
For our example we use a discovery response that contains only the Issuer id
of the OP::

    req = MetadataStatement(issuer='https://example.org/op')
    sms = signer.create_signed_metadata_statement(req, 'discovery')

