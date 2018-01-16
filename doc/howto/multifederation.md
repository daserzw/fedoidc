# Deploying multiple R&E communities with OIDCFed

## Introduction

This document provides an initial step by step description of the technical solution agreed during the Federation Tools for OIDCFed Workshop that took place in Amsterdam on the 10-11th  of January 2018. Its purpose is twofold. First, serve as a confirmation that everyone understood the same sequence. Second, as a reference for future implementation and deployment.

The description of the steps is based on the diagram that Steffen draw in the board.


## Entities
* `RP1`. A Relying Party.
* `OP1`. A OpenID Provider.
* `MSS_FA`. The Metadata Signing Service for Federation A (`FA`).
* `MSS_FB`. The Metadata Signing Service for Federation B (`FB`).
* `MSS_CE`. The Metadata Signing Service for the community of federations E (`CE`). This might be eduGAIN-OIDC.


## Remarks

* A `RP`/`OP` that talks to `MSS_FA` is called `member of federation A`
* A `RP`/`OP` might be part of multiple federations when talking to multiple MSS.
* A `RP`/`OP` might be part of multiple communities. It might even be part of the same community multiple times via membership in several federations.
* No revocation mechanism for either keys and/or signed MS is considered. Instead revocations should be handled by short-lived signatures, i.e. 15 minutes.


## The Signing Service
The Signing Service is a key part of the architecture. Each federation MUST deploy one.
A Metadata Signing Service (MSS) has control over the private part of the Federation Key. Entities (RP1/OP1/MSS) can enrol to become part of the federation. The MSS gets access to the public parts of the signing_key of the enrolled entities and use them to generate signed Metadata Statement (`MS`) for them.

The MSS *MUST* be notified every time the `RP1` does key rotation of its signing keys.

A MSS has the following public API calls available:
* GET `/getms/{entity}`. Returns a signed JWT containing a collection of signed MS for `entity`. This collection is a JSON object whose keys are federation IDs and the values are the corresponding signed MS.
* GET `/getms/{entity}/{FO}`. Returns the signed MS for `entity` in the federation `FO`.


## Sequence of steps
Note: processes are described as if they were always performed in a reactive way. Caches and proactive behaviour MUST be in-place to avoid delays in the processes. Think of them as regular cron-jobs.

1. `MSS_FA` generates and/or gets its own signed MSs. A Signing Service will always have a self-signed MS. Additionally, it will have a signed MS per any superior Metadata Signing Service (federation / community) it has enrolled into (see below). For now only the self-signed one is available:
    ```
    {
        "FA": JWT signed by MSS_FA {
            "signing_keys": "MSS_FA_key",
        }
    }
    ```
1. `RP1` enrols to become member of `FA`. This process is out of the scope of this document, but as a result, `MSS_FA` gets access to the public parts of `RP1`'s signing key and vice versa.
1. Once this has been completed, `RP1` decides to retrieve its signed MS from `MSS_FA`.
    1. `RP1` sends a query to `MSS_FA` API to get the collection of signed MS (GET https://MSS_FA/getms/RP1).
    1. For each one of `MSS_FA` signed MS, `MSS_FA` generates a corresponding signed MS for  `RP1`, consisting of the public parts of `RP1`'s signing_key, any additional claim `MSS_FA` wants to introduce, and `MSS_FA`'s signed MS as the `metadata_statements` claim. The collection of signed MS are packed into a JSON object keyed by federation name. Finally, the response to the `RP1` consists of a signed JWT of such JSON object:
        ```
        JWT signed by MSS_FA {
            "FA": JWT signed by MSS_FA {
                "signing_keys": "RP1_key",
                MSS_FA introduced claims,
                "metadata_statements": {
                    "FA": JWT signed by MSS_FA {
                        "signing_keys": "MSS_FA_key",
                    }
                }
            }
        }
        ```
    1. `RP1` verifies the response and learns the supported federations: `FA`
1. In a similar way, `OP1` enrols to become part of `FB` and gets its signed MS from `MSS_FB` (https://MSS_FB/getms/OP1).
    ```
    JWT signed by MSS_FB {
        "FB": JWT signed by MSS_FB {
            "signing_keys": "OP1_key",
            MSS_FB introduced claims,
            "metadata_statements": {
                "FB": JWT signed by MSS_FB {
                    "signing_keys": "MSS_FB_key",
                }
            }
        }
    }
    ```
1. At some moment, `RP1` wants to register with `OP1`.
    1.  `RP1` gets `OP1`'s configuration information as usual, from https://OP1/.well-known/openid-configuration. This is what it gets.
        ```
        {
            OP1's claims,
            "metadata_statements": {
                "FB": JWT signed by OP1 {
                    OP1's claims,
                    "signing_key": "OP1_key",
                    "metadata_statements": {
                        "FB": JWT signed by MSS_FB {
                            "signing_keys": "OP1_key",
                            MSS_FB introduced claims,
                            "metadata_statements": {
                                "FB": JWT signed by MSS_FB {
                                    "signing_keys": "MSS_FB_key",
                                }
                            }
                        }
                    }
                }
            }
        }
        ```
        Or the same with URI references:
        ```
        {
            OP1's claims,
            "metadata_statements": {
                "FB": JWT signed by OP1 {
                    OP1's claims,
                    "signing_key": "OP1_key",
                    "metadata_statement_uris": {
                        "FB": "https://MSS_FB/getms/OP1/FB"
                    }
                }
            }
        }
        ```
    1. Since `FB` is not in `RP1`'s federation list, registration is not even attempted.
1. After some time, `MSS_FA` and `MSS_FB` enrol to become part of eduGAIN-OIDC.
1. `MSS_FA` then gets its signed MS from the eduGAIN MSS:
   1. `MSS_FA` sends a GET query to `MSS_CE` (https://MSS_CE/getms/MSS_FA).
   1. `MSS_CE` generates its self-signed MS.
        ```
        {
            "CE": JWT signed by MSS_CE {
                "signing_keys": "MSS_CE_key",
            }
        }
        ```
   1. And then generates the response for `MSS_FA`.
        ```
        JWT signed by MSS_CE {
            "CE": JWT signed by MSS_CE {
                "signing_keys": "MSS_FA_key",
                MSS_CE introduced claims,
                "metadata_statements": {
                    "CE": JWT signed by MSS_CE {
                        "signing_keys": "MSS_CE_key",
                    }
                }
            }
        }
        ```
   1. `MSS_FA` verifies, parses and caches the response.
1. `MSS_FB` gets its signed MS from eduGAIN, following a similar process:
    ```
    JWT signed by MSS_CE {
        "CE": JWT signed by MSS_CE {
            "signing_keys": "MSS_FB_key",
            MSS_CE introduced claims,
            "metadata_statements": {
                "CE": JWT signed by MSS_CE {
                    "signing_keys": "MSS_CE_key",
                }
            }
        }
    }
    ```
1. After some more time, `RP1` decides to refresh its signed MS (e.g. because they are about to expire).
   1. `RP1` queries `MSS_FA` (e.g. https://MSS_FA/getms/RP1).
   1. `MSS_FA` generates/gets its signed MSs. In this case, MSS_FA has the self-signed MS and the one signed by eduGAIN:
        ```
        {
            "FA": JWT signed by MSS_FA {
                "signing_keys": "MSS_FA_key",
            },
            "CE": JWT signed by MSS_CE {
                "signing_keys": "MSS_FA_key",
                MSS_CE introduced claims,
                "metadata_statements": {
                    "CE": JWT signed by MSS_CE {
                        "signing_keys": "MSS_CE_key",
                    }
                }
            }
        }
        ```
   1. `MSS_FA` generates the collection of signed MSs for `RP1`:
        ```
        JWT signed by MSS_FA {
            "FA": JWT signed by MSS_FA {
                "signing_keys": "RP1_key",
                MSS_FA introduced claims,
                "metadata_statements": {
                    "FA": JWT signed by MSS_FA {
                        "signing_keys": "MSS_FA_key",
                    }
                }
            },
            "CE": JWT signed by MSS_FA {
                "signing_keys": "RP1_key",
                MSS_FA introduced claims,
                "metadata_statements": {
                    "CE": JWT signed by MSS_CE {
                        "signing_keys": "MSS_FA_key",
                        MSS_CE introduced claims,
                        "metadata_statements": {
                            "CE": JWT signed by MSS_CE {
                                "signing_keys": "MSS_CE_key",
                            }
                        }
                    }
                }
            }
        }
        ```
   1. `RP1` verifies and parses the signed response, and learns which federations are included (`FA` and `CE`).
1. Similarly, `OP1` decides to refresh its signed MS from https://MSS_FB/getms/OP1), and it gets:
    ```
    JWT signed by MSS_FB {
        "FB": JWT signed by MSS_FB {
            "signing_keys": "OP1_key",
            MSS_FB introduced claims,
            "metadata_statements": {
                "FB": JWT signed by MSS_FB {
                    "signing_keys": "MSS_FB_key",
                }
            }
        },
        "CE": JWT signed by MSS_FB {
            "signing_keys": "OP1_key",
            MSS_FB introduced claims,
            "metadata_statements": {
                "CE": JWT signed by MSS_CE {
                    "signing_keys": "MSS_FB_key",
                    MSS_CE introduced claims,
                    "metadata_statements": {
                        "CE": JWT signed by MSS_CE {
                            "signing_keys": "MSS_CE_key",
                        }
                    }
                }
            }
        }
    }
    ```
1. `RP1` attempts to register with `OP1` again.
    1.  `RP1` gets `OP1`'s configuration information, from https://OP1/.well-known/openid-configuration. This is what it gets.
        ```
        {
            OP1's claims,
            "metadata_statements": {
                "FB": JWT signed by OP1 {
                    OP1's claims,
                    "signing_key": "OP1_key",
                    "metadata_statements": {
                        "FB": JWT signed by MSS_FB {
                            "signing_keys": "OP1_key",
                            MSS_FB introduced claims,
                            "metadata_statements": {
                                "FB": JWT signed by MSS_FB {
                                    "signing_keys": "MSS_FB_key",
                                }
                            }
                        }
                    }
                },
                "CE": JWT signed by OP1 {
                    OP1's claims,
                    "signing_key": "OP1_key",
                    "metadata_statements": {
                        "CE": JWT signed by MSS_FB {
                            "signing_keys": "OP1_key",
                            MSS_FB introduced claims,
                            "metadata_statements": {
                                "CE": JWT signed by MSS_CE {
                                    "signing_keys": "MSS_FB_key",
                                    MSS_CE introduced claims,
                                    "metadata_statements": {
                                        "CE": JWT signed by MSS_CE {
                                            "signing_keys": "MSS_CE_key",
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        ```
        Or just with references:
        ```
        {
            OP1's claims,
            "metadata_statements": {
                "FB": JWT signed by OP1 {
                    OP1's claims,
                    "signing_key": "OP1_key",
                    "metadata_statement_uris": {
                        "FB": "https://MSS_FB/getms/OP1/FB",
                    }
                },
                "CE": JWT signed by OP1 {
                    OP1's claims,
                    "signing_key": "OP1_key",
                    "metadata_statement_uris": {
                        "CE": "https://MSS_FB/getms/CE"
                    }
                }
            }
        }
        ```
    1. Since `RP1` is in `CE`, it validates the MS making use of the known `CE` public key (found in the inner-most part of its own MS for `CE`).
    1. Then `RP1` can proceed with the registration, sending a registration request:
        ```
        {
            RP1's claims,
            "metadata_statements": {
                "FA": JWT signed by RP1 {
                    RP1's claims,
                    "signing_key": "RP1_key",
                    "metadata_statements": {
                        "FA": JWT signed by MSS_FA {
                            "signing_keys": "RP1_key",
                            MSS_FA introduced claims,
                            "metadata_statements": {
                                "FA": JWT signed by MSS_FA {
                                    "signing_keys": "MSS_FA_key",
                                }
                            }
                        }
                    }
                },
                "CE": JWT signed by RP1 {
                    RP1's claims,
                    "signing_key": "RP1_key",
                    "metadata_statements": {
                        "CE": JWT signed by MSS_FA {
                            "signing_keys": "RP1_key",
                            MSS_FA introduced claims,
                            "metadata_statements": {
                                "CE": JWT signed by MSS_CE {
                                    "signing_keys": "MSS_FA_key",
                                    MSS_CE introduced claims,
                                    "metadata_statements": {
                                        "CE": JWT signed by MSS_CE {
                                            "signing_keys": "MSS_CE_key",
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        ```
        Or the same with URI references:
        ```
        {
            RP1's claims,
            "metadata_statements": {
                "FA": JWT signed by RP1 {
                    RP1's claims,
                    "signing_key": "RP1_key",
                    "metadata_statement_uris": {
                        "FA": "https://MSS_FA/getms/RP1/FA"
                    }
                },
                "CE": JWT signed by RP1 {
                    RP1's claims,
                    "signing_key": "RP1_key",
                    "metadata_statement_uris": {
                        "CE": "https://MSS_FA/getms/RP1/CE"
                    }
                }
            }
        }
        ```
    1. Similarly, `OP1` verifies `RP1`'s MS using `CE`'s key found inside its own signed MS for `CE`.
