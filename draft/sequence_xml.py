#!/usr/bin/env python3

import json
from jwkest.jws import factory

from fedoidc import MetadataStatement
from fedoidc.bundle import JWKSBundle
from fedoidc.operator import Operator
from oic.oauth2 import Message
from oic.oic.message import RegistrationRequest

from oic.utils.keyio import build_keyjar

__author__ = 'roland'


def paragraph(*lines):
    print("<t>")
    print("\n".join(lines))
    print("</t>")


def print_figure(text, preamble=None):
    print("<figure>")
    if preamble:
        print("<preamble>{}</preamble>".format(preamble))
    print("<artwork> <![CDATA[")
    print("\n".join(text))
    print("]]></artwork ></figure>")


def format_lines(lines, maxlen=68):
    res = []
    for line in lines.split('\n'):
        if len(line) <= maxlen:
            res.append(line)
        else:
            n = maxlen
            for l in [line[i:i + n] for i in range(0, len(line), n)]:
                res.append(l)
    return res


def print_private_key(keyjar, headline=''):
    _jwks = keyjar.issuer_keys[''][0].jwks(private=True)  # Only one bundle
    text = format_lines(json.dumps(json.loads(_jwks), sort_keys=True, indent=2,
                                   separators=(',', ': ')))
    print_figure(text, headline)


def print_metadata_statement(sms, txt=''):
    _jwt = factory(sms)
    _sos = json.loads(_jwt.jwt.part[1].decode('utf8'))
    text = format_lines(json.dumps(_sos, sort_keys=True, indent=2,
                                   separators=(',', ': ')))
    print_figure(text, txt)


def print_request(txt, req):
    text = format_lines(json.dumps(req.to_dict(), sort_keys=True, indent=2,
                                   separators=(',', ': ')))
    print_figure(text, txt)


def close_section():
    print('</section>')


def sub_section(title, anchor=''):
    if anchor:
        print('<section anchor="{}" title="{}">'.format(anchor, title))
    elif title:
        print('<section title="{}">'.format(title))


def section(title, anchor=''):
    close_section()
    if anchor:
        print('<section anchor="{}" title="{}">'.format(anchor, title))
    elif title:
        print('<section title="{}">'.format(title))


key_conf = [
    {"type": "RSA", "use": ["sig"]},
]

sub_section(anchor="app-additional", title="Example")  # A

paragraph(
    "The story is that the organisation UNINETT has applied and been accepted",
    "as a member of two federations: Feide and SWAMID."
)

paragraph(
    "Now UNINETT is running a service",
    "(Foodle) that needs signed metadata statements to prove that it belongs",
    "to the federation that the OP belongs to when a user of the Foodle",
    "service wants to log in using an OP that belongs to either or both of",
    "the federations."
)

sub_section(title="At the beginning of time") # A.1

# -----------------------------------------------------------------------------
# FO get's its key pair
# -----------------------------------------------------------------------------

# A.1.1
sub_section("SWAMID gets a  key pair for signing Metadata Statements")
swamid = Operator(iss='https://swamid.sunet.se/',
                  keyjar=build_keyjar(key_conf)[1], lifetime=30 * 86400)
print_private_key(swamid.keyjar)

# A.1.2
section("Feide gets a key pair for signing Metadata Statements")
feide = Operator(iss='https://www.feide.no',
                 keyjar=build_keyjar(key_conf)[1], lifetime=30 * 86400)
print_private_key(feide.keyjar)

# -----------------------------------------------------------------------------
# Create initial Organisation key pair (OA)
# -----------------------------------------------------------------------------

# A.1.3
section("UNINETT gets a key pair for signing Metadata Statements")
uninett = Operator(iss='https://www.uninett.no',
                   keyjar=build_keyjar(key_conf)[1], lifetime=86400)
print_private_key(feide.keyjar)

# -----------------------------------------------------------------------------
# -- construct JSON document to be signed by Feide
# -----------------------------------------------------------------------------
close_section()
close_section()

# A.2
sub_section('A while ago')
paragraph("Now is the time to construct the signed metadata statements",
          "and get them signed by the federations.",
          "We'll start with Feide and UNINETT")

# A.2.1
sub_section(
    title="UNINETT constructs a signing request containing only the public "
          "parts of the UNINETT signing keys")

uninett_feide_msreq = MetadataStatement(
    federation_usage="registration",
    signing_keys=uninett.signing_keys_as_jwks()
)
print_request('UNINETT Metadata Statement request', uninett_feide_msreq)

# -----------------------------------------------------------------------------
# The Feide FO constructs Metadata statement
# -----------------------------------------------------------------------------

paragraph(
    "UNINETT sends the Metadata statement signing request to Feide and ",
    "Feide adds claims representing the Feide federation policiy.")

uninett_feide_msreq.update({
    'id_token_signing_alg_values_supported': ['RS256', 'RS512'],
    'claims': ['sub', 'name', 'email', 'picture']
})

uninett_feide_ms = feide.pack_metadata_statement(uninett_feide_msreq)

# A.2.1.1
sub_section(title="Signed Metadata statement created by Feide")
print_metadata_statement(uninett_feide_ms)
close_section()

# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------

# A.2.2
sub_section("The same process is repeated for UNINETT/SWAMID")

paragraph("SUNET gets the same signing request as Feide got but adds ",
          "a different set of policy claims")

uninett_sunet_msreq = MetadataStatement(
    federation_usage="registration",
    signing_keys=uninett.signing_keys_as_jwks()
)

uninett_sunet_msreq.update({
    "response_types": ["code", "token"],
    "token_endpoint_auth_method": "private_key_jwt",
    "scopes": ['openid', 'email']
})

uninett_swamid_ms = swamid.pack_metadata_statement(uninett_sunet_msreq)

# A.2.2.1
sub_section(title="The by SWAMID signed metadata statement")
print_metadata_statement(uninett_swamid_ms)
close_section()
close_section()

# A.2.3
section('@UNINETT')
paragraph("",
          "Now UNINETT sits with two signed metadata statements one for each "
          "of the federations it belongs to")

close_section()
# A.3
section('Recent')
paragraph("Time to create the Foodle (RP) metadata statement")
paragraph(
    "We take a road similar to the request/request_uri path. That is we",
    "include all the information about the client that needs to be",
    "protect from tampering by a MITM and places it in the ",
    "metadata statement signing request.")

# -----------------------------------------------------------------------------
# The RP as federation entity
# -----------------------------------------------------------------------------

paragraph("But first Foodle needs it's own signing keys. Not for signing",
          "Metadata Statements but for signing the JWKS document found at",
          "the URI pointed to by jwks_uri.",
          "It is vital to protect this key information from tampering since",
          "a lot of the security of the future OIDC communication will",
          "depend on the correctness of the keys found at the jwks_uri.")

foodle_rp = Operator(iss='https://foodle.uninett.no',
                     keyjar=build_keyjar(key_conf)[1], lifetime=14400)

print_private_key(foodle_rp.keyjar,
                  "Foodle gets a key pair for signing the JWKS documents")

# -----------------------------------------------------------------------------
# -- construct Registration Request to be signed by organisation
# -----------------------------------------------------------------------------

# A.4
section(title="And now for the registration request")

rreq = RegistrationRequest()
print_request('Client Registration request', rreq)

# -----------------------------------------------------------------------------
# SUNET signs Registration Request once per federation
# -----------------------------------------------------------------------------

paragraph("The Client Registration Request is sent to UNINETT",
          "who adds the two signed metadata staments it has.",
          "One for each of SWAMID and Feide."
          "Since it knows that it is the Foodle RP which is the subject",
          "of the JWT it adds Foodle's identifier as 'sub'")

rreq.update({
    "metadata_statements": [uninett_swamid_ms, uninett_feide_ms],
})

jwt_args = {"sub": foodle_rp.iss}

foodle_uninett = uninett.pack_metadata_statement(rreq, jwt_args=jwt_args)

# A.4.1
sub_section('Metadata statement about Foodle signed by UNINETT')

print_metadata_statement(foodle_uninett)

close_section()
# ----------------------------------------------------------------------------
# The RP publishes Registration Request
# ----------------------------------------------------------------------------

# A.5
section('Foodle client registration')
paragraph('Now, when Foodle wants to register as a client with an OP it adds',
          "the signed Metadata statement it received from UNINETT to",
          "the client registration request.",
          "Note that 'redirect_uri' MUST be in the registration request as",
          "this is requied by the OIDC standard."
          "If the 'redirect_uris' values that are transfered unprotected ",
          "where to differ from what's in the signed metadata",
          "statement the OP MUST refuse the registration.")

rere = Message(
    redirect_uris=['https://foodle.uninett.no/callback'],
    metadata_statements=[foodle_uninett]
)

print_request('Registration Request published by RP', rere)

# ### ======================================================================
# #   On the OP
# ### ======================================================================

# A.6
section('Unpacking the client registration request')
paragraph("An OP that has the public part of the signing keys for both the",
    "SWAMID and Feide federations can now verify the signature chains all the",
    "way from the Metadata statement signed by UNINETT up to the FOs.",
    "If that works it can then flatten the compounded metadata statements.")

_jb = JWKSBundle('https://foodle.uninett.no')
_jb[swamid.iss] = swamid.signing_keys_as_jwks()
_jb[feide.iss] = feide.signing_keys_as_jwks()

uninett_op = Operator(iss='https://op.uninett.no', jwks_bundle=_jb)

# -----------------------------------------------------------------------------
# Unpacking the russian doll (= the metadata_statements)
# -----------------------------------------------------------------------------

_cms = uninett_op.unpack_metadata_statement(json_ms=rere)
res = uninett_op.evaluate_metadata_statement(_cms.result)

# A.7
section('Unpacked and flattened metadata statement per FO')
i = 0
for fms in res:
    if i == 0:
        sub_section("*** {} ***".format(fms.iss))
    else:
        section("*** {} ***".format(fms.iss))
    print_figure(format_lines(json.dumps(fms.le, sort_keys=True, indent=2,
                                         separators=(',', ': '))))
    i += 1

close_section()
close_section()
close_section()