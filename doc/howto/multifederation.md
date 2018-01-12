# Deploying multiple R&E communities with OIDCFed

## Introduction

This document provides an initial step by step description of the technical solution agreed during the Federation Tools for OIDCFed Workshop that took place in Amsterdam on the 10-11th  of January 2018. Its purpose is twofold. First, serve as a confirmation that everyone understood the same sequence. Second, as a reference for future implementation and deployment.

The description of the steps is based on the diagram that Steffen draw in the board. 

## Entitites
* `RP`. A Relying Party.
* `OP`. A OpenID Provider.
* `SS_FA`. The Signing Service for Federation A (`FA`).
* `SS_FB`. The Signing Service for Federation B (`FB`).
* `SS_FE`. The Signing Service for the EduGAIN federation (`FE`).

## The Signing Service
The Signing Service is a key part of the architecture. Each federation MUST deploy one.
A Signing Service (SS) has control over the private part of the Federation Key. Entities (RP/OP/SS) can enrol to become part of the federation. The SS learns the signing_key of the enrolled entities and use them to generate signed MS for them.

A SS has the folling API calls available:
* `/getms/{entity}`. Returns a signed JWT containing a collection of signed MS for `entity`. This collection is a JSON object whose keys are federation IDs and the values are the corresponding signed MS.
* `/getms/{entity}/{FO}`. Returns the signed MS for `entity` in the federation `FO`.

## Sequence of steps
Note: processes are described as if they were always performed in a reactive way. Caches and proactive behaviour MUST be in-place to avoid delays in the processes.

1. `RP` enrols to become part of `FA`. This process is out of the scope of this document, but as a result, `SS_FA` learns `RP`'s signing key.
1. Once this has been completed, `RP` decides to retrieve its signed MS from `SS_FA`.
    1. `RP` sends a query to `SS_FA` API to get the collection of signed MS (https://SS_FA/getms/RP).
    1. `SS_FA` generates and/or gets its own signed MSs first. Note that these are not specific to the requesting `RP`, and will be used for any other RP member of `FA` if cached. A Signing Service will always have a self-signed MS. Additionally, it will have a signed MS per any superior Signing Service (federation) it has enrolled into. In this example, only the self-signed one is available.
        ```
        { 
            "FA": JWT signed by SS_FA {
                "signing_keys": "SS_FA_key",
            }
        }   
        ```
    1. For each one of `SS_FA` signed MS, `SS_FA` generates a corresponding signed MS for  `RP`, consisting of `RP`'s signing_key, any additional claim `SS_FA` wants to introduce, and `SS_FA`'s signed MS as the `metadata_statements` claim. The collection of signed MS are packed into a JSON object keyed by federation name. Finally, the response to the `RP` consists of a signed JWT of such JSON object:
        ```
        JWT signed by SS_FA {
            "FA": JWT signed by SS_FA {
                "signing_keys": "RP_key",
                SS_FA introduced claims,
                "metadata_statements": { 
                    "FA": JWT signed by SS_FA {
                        "signing_keys": "SS_FA_key",
                    }
                }
            }
        }
        ```
    1. `RP` verifies the response and learns the supported federations: `FA`
1. In a similar way, `OP` enrols to become part of `FB` and gets its signed MS from `SS_FB` (https://SS_FB/getms/OP).
    ```
    JWT signed by SS_FB {
        "FB": JWT signed by SS_FB {
            "signing_keys": "OP_key",
            SS_FB introduced claims,
            "metadata_statements": {
                "FB": JWT signed by SS_FB {
                    "signing_keys": "SS_FB_key",
                }
            }
        }
    }        
    ```
1. At some moment, the `RP` wants to register with `OP`.
    1.  `RP` gets `OP`'s configuration information as usual, from https://OP/.well-known/openid-configuration. This is what it gets.
        ```
        {
            OP's claims,
            "metadata_statements": {
                "FB": JWT signed by OP {
                    OP's claims,
                    "signing_key": "OP_key",
                    "metadata_statements": {
                        "FB": JWT signed by SS_FB {
                            "signing_keys": "OP_key",
                            SS_FB introduced claims,
                            "metadata_statements": {
                                "FB": JWT signed by SS_FB {
                                    "signing_keys": "SS_FB_key",
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
            OP's claims,
            "metadata_statements": {
                "FB": JWT signed by OP {
                    OP's claims,
                    "signing_key": "OP_key",
                    "metadata_statement_uris": {
                        "FB": "https://SS_FB/getms/OP/FB"
                    }                     
                }
            }
        }
        ```        
    1. Since `FB` is not in `RP`'s federation list, registration is not even attempted.
1. After some time, `SS_FA` and `SS_FB` enrol to become part of Edugain.
1. `SS_FA` then gets its signed MS from Edugain.
   1. `SS_FA` sends a GET query to `SS_FE` (https://SS_FE/getms/SS_FA).
   1. `SS_FE` generates its self-signed MS.
        ```
        {
            "FE": JWT signed by SS_FE {
                "signing_keys": "SS_FE_key",
            }
        }
        ```
   1. And then generates the response for `SS_FA`.
        ```
        JWT signed by SS_FE {
            "FE": JWT signed by SS_FE {
                "signing_keys": "SS_FA_key",
                SS_FE introduced claims,
                "metadata_statements": {
                    "FE": JWT signed by SS_FE {
                        "signing_keys": "SS_FE_key",
                    }
                }
            }
        }
        ```
   1. `SS_FA` verifies, parses and caches the response.
1. `SS_FB` gets its signed MS from Edugain, following a similar process:
    ```
    JWT signed by SS_FE {
        "FE": JWT signed by SS_FE {
            "signing_keys": "SS_FB_key",
            SS_FE introduced claims,
            "metadata_statements": {
                "FE": JWT signed by SS_FE {
                    "signing_keys": "SS_FE_key",
                }
            }
        }
    }
    ```
1. After some more time, `RP` decides to refresh its signed MS (e.g. because they are about to expire).
   1. `RP` quries `SS_FA` (e.g. https://SS_FA/getms/RP).
   1. `SS_FA` generates/gets its signed MSs. In this case, SS_FA has the self-signed MS and the one signed by Edugain.
        ```
        {
            "FA": JWT signed by SS_FA {
                "signing_keys": "SS_FA_key",
            },
            "FE": JWT signed by SS_FE {
                "signing_keys": "SS_FA_key",
                SS_FE introduced claims,
                "metadata_statements": {
                    "FE": JWT signed by SS_FE {
                        "signing_keys": "SS_FE_key",
                    }
                }
            }
        }
        ```
   1. `SS_FA` generates the collection of signed MSs for `RP`:
        ```
        JWT signed by SS_FA {
            "FA": JWT signed by SS_FA {
                "signing_keys": "RP_key",
                SS_FA introduced claims,
                "metadata_statements": {
                    "FA": JWT signed by SS_FA {
                        "signing_keys": "SS_FA_key",
                    }
                }
            },
            "FE": JWT signed by SS_FA {
                "signing_keys": "RP_key",
                SS_FA introduced claims,
                "metadata_statements": {
                    "FE": JWT signed by SS_FE {
                        "signing_keys": "SS_FA_key",
                        SS_FE introduced claims,
                        "metadata_statements": {
                            "FE": JWT signed by SS_FE {
                                "signing_keys": "SS_FE_key",
                            }
                        }
                    }
                }
            }
        }
        ```
   1. `RP` verifies and parses the signed response, and learns which Federations are included (`FA` and `FE`).
1. Similarly, `OP` decides to refresh its signed MS from https://SS_FB/getms/OP), and it gets:
    ```
    JWT signed by SS_FB {
        "FB": JWT signed by SS_FB {
            "signing_keys": "OP_key",
            SS_FB introduced claims,
            "metadata_statements": {
                "FB": JWT signed by SS_FB {
                    "signing_keys": "SS_FB_key",
                }
            }
        },
        "FE": JWT signed by SS_FB {
            "signing_keys": "OP_key",
            SS_FB introduced claims,
            "metadata_statements": {
                "FE": JWT signed by SS_FE {
                    "signing_keys": "SS_FB_key",
                    SS_FE introduced claims,
                    "metadata_statements": {
                        "FE": JWT signed by SS_FE {
                            "signing_keys": "SS_FE_key",
                        }
                    }
                }
            }
        }
    }
    ```
1. `RP` attempts to register with `OP` again.
    1.  `RP` gets `OP`'s configuration information, from https://OP/.well-known/openid-configuration. This is what it gets.
        ```
        {
            OP's claims,
            "metadata_statements": {
                "FB": JWT signed by OP {
                    OP's claims,
                    "signing_key": "OP_key",
                    "metadata_statements": {
                        "FB": JWT signed by SS_FB {
                            "signing_keys": "OP_key",
                            SS_FB introduced claims,
                            "metadata_statements": {
                                "FB": JWT signed by SS_FB {
                                    "signing_keys": "SS_FB_key",
                                }
                            }
                        }                       
                    }                     
                },
                "FE": JWT signed by OP {
                    OP's claims,
                    "signing_key": "OP_key",
                    "metadata_statements": {
                        "FE": JWT signed by SS_FB {
                            "signing_keys": "OP_key",
                            SS_FB introduced claims,
                            "metadata_statements": {
                                "FE": JWT signed by SS_FE {
                                    "signing_keys": "SS_FB_key",
                                    SS_FE introduced claims,
                                    "metadata_statements": {
                                        "FE": JWT signed by SS_FE {
                                            "signing_keys": "SS_FE_key",
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
            OP's claims,
            "metadata_statements": {
                "FB": JWT signed by OP {
                    OP's claims,
                    "signing_key": "OP_key",
                    "metadata_statement_uris": {
                        "FB": "https://SS_FB/getms/OP/FB",
                    }
                },
                "FE": JWT signed by OP {
                    OP's claims,
                    "signing_key": "OP_key",
                    "metadata_statement_uris": {
                        "FE": "https://SS_FB/getms/FE"
                    }                     
                }
            }
        }
        ```        
    1. Since `RP` is in `FE`, it validates the MS making use of the known `FE` public key (found in the inner-most part of its own MS for `FE`).
    1. Then `RP` can proceed with the registration, sending a registration request:
        ```
        {
            RP's claims,
            "metadata_statements": {
                "FA": JWT signed by RP {
                    RP's claims,
                    "signing_key": "RP_key",
                    "metadata_statements": {
                        "FA": JWT signed by SS_FA {
                            "signing_keys": "RP_key",
                            SS_FA introduced claims,
                            "metadata_statements": {
                                "FA": JWT signed by SS_FA {
                                    "signing_keys": "SS_FA_key",
                                }
                            }
                        }
                    }                     
                },
                "FE": JWT signed by RP {
                    RP's claims,
                    "signing_key": "RP_key",
                    "metadata_statements": {
                        "FE": JWT signed by SS_FA {
                            "signing_keys": "RP_key",
                            SS_FA introduced claims,
                            "metadata_statements": {
                                "FE": JWT signed by SS_FE {
                                    "signing_keys": "SS_FA_key",
                                    SS_FE introduced claims,
                                    "metadata_statements": {
                                        "FE": JWT signed by SS_FE {
                                            "signing_keys": "SS_FE_key",
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
        Or the same with URI references.
        ```
        {
            RP's claims,
            "metadata_statements": {
                "FA": JWT signed by RP {
                    RP's claims,
                    "signing_key": "RP_key",
                    "metadata_statement_uris": {
                        "FA": "https://SS_FA/getms/RP/FA"
                    }
                },
                "FE": JWT signed by RP {
                    RP's claims,
                    "signing_key": "RP_key",
                    "metadata_statement_uris": {
                        "FE": "https://SS_FA/getms/RP/FE"
                    }                     
                }
            }
        }
        ```  
    1. Similarly, `OP` verifies `RP`'s MS using `FE`'s key found inside its own signed MS for `FE`.
