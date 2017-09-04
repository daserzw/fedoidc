.. _howto_bundle:

How to deal with key bundles
============================

When dealing with federations as envisaged in the *draft* an entity MUST
be able to handle sets of keys per federation operator.

A set of keys for one entity is handled as a
`JWK Set <https://tools.ietf.org/html/rfc7517>`.

A set of JWKS Sets are called a bundle in this documentation.

The base class is :py:class:`fedoidc.bundle.JWKSBundle` . This class
keeps the bundle in memory which limits its usability to special use
cases.

:py:class:`fedoidc.bundle.FSJWKSBundle` on the other hand keeps the bundle
in a :py:class:`fedoidc.file_system.FileSystem` instance.

Usage
+++++

A JWKSBundle can be treated as a dictionary::

    from fedoidc.bundle import JWKSBundle
    from oic.utils.keyio import build_keyjar
    from oic.utils.keyio import KeyJar

    ISS = 'https://example.com'

    KEYDEFS = [
        {"type": "RSA", "key": '', "use": ["sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]}
    ]

    SIGN_KEYS = build_keyjar(KEYDEFS)[1]

    bundle = JWKSBundle(ISS, SIGN_KEYS)

    kj = KeyJar()
    kj.import_jwks(json.loads(open('swamid.jwks'), 'https://swamid.sunet.se')
    bundle['https://swamid.sunet.se'] = kj

The export format for a JWKSBundle is an extension to a JWK Set, namely a
dictionary with the Federation Operators IDs as keys an a JWK Set representation
of the keys as the values:

An example::

    {
      "https://www.feide.no": {
        "keys": [
          {
            "e": "AQAB",
            "kid": "7AQCO4UK4_bS2-s8XmVFEfK7r7HnFv8jUhY0Ke2-G5c",
            "kty": "RSA",
            "n": "utyZH_CMdT9nEEBR3EWAdaNZQJjSkHQH9H09FtrgVJYTE7ANySX17cusH-cx
              An5gHzfpUvpLVFMJrllrq-UsREd8EbI7Qf-q0eDUnj9tz_mB3xSxg7dsssbFuPGh
              x8oA2Ky3jhOvlIu4lvbsCTvRVOxuoXyIuu7sqhoSqakBg5E8iCsZ1zkX43tTOXdg
              KICazjDkkqdogPhos887a7S94gCVo0FrjCS5f0YR-NMDgfhSCkjU9cWaGYU5n624
              iHcBX388xTbYE4B9Rs9HfQ1ioBnre-5ZYr7WCAx7_HvJMan3HT75jFlSwTBzk1a4
              -lvkDL9RE0lBJj9o0-Gp9Ltdbw",
            "use": "sig"
          },
          {
            "crv": "P-256",
            "kid": "cPDzkl1QK6rn9H9w3wpwzerps7SsUWsQSyTZX_jBASM",
            "kty": "EC",
            "use": "sig",
            "x": "43FfA0Izr0xwmu5ItFgGnHFR3cugB3DBza_0HXEIZx0",
            "y": "-P4fMe6mO3F2erTolLv-h5ptURL0HLFzGRzPnILBAu8"
          }
        ]
      },
      "https://www.swamid.se": {
        "keys": [
          {
            "e": "AQAB",
            "kid": "UAyDbISpRXuqqE39GhdOpdPg9tsVKQ6P9m8dXOifH-E",
            "kty": "RSA",
            "n": "7cIYHB3N1cgFmrTOJBR07Yrgr6co3Vp59YtIOUpLQdVCbPAWh_QHIQiENr9t
              efznwkhYC3E0a_rocKclkBkbUFkjDD91bsPQkT4jbfVwceIEIHFSvDscTvJlVY0v
              ootkeirrf_aZ6j6ikgsoPfCt4Y_iBuik1dDKR0_FLnVJeX8xRntHn1s6kWkZIKUo
              0gt8W-1yuxCI1YpNjC5Jbhrm2XwpbDYEcC0xzWp6ujzvE934eiC_6Bq5gsrH-nfG
              9GFr4jkBEKLa1-9vsuSEIQuDub5D22jBuDS-h_gjVkH00BZrm5WG6Q_ri1VOUNdF
              swh3rGuWWFCwYc_U6dU3IKdxKQ",
            "use": "sig"
          },
          {
            "crv": "P-256",
            "kid": "D8P61knwyP_GSu_ltVtYfhYbTtojoCPVtUwab83T8S8",
            "kty": "EC",
            "use": "sig",
            "x": "hA6PiSlKWUyhH51EqZkia-_NyWPa0hxCFjXQ3G6LPZE",
            "y": "_5dFLVTlOyV_M-jhksMxoOp21B91FkoTRqJexAQegpg"
          }
        ]
      }
    }

