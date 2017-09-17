.. _fed_example:

How to setup an example federation
==================================

This is a desciption on how you can set up an extremely simple federation.
The federation consists of one Federation Operator (FO) 'SWAMID' and one
organisation 'SUNET' who has two entities in the federation. One OP and one RP.

There are a number of steps that has to be followed to do the setup.
These are them

Step 1 - Create a directory tree containing all the necessary parts.
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Using the fed_oprp_setup.py, the command is::

    fed_oprp_setup.py <absolute path to the fedoidc source tree> <name of the new tree>

On my laptop I ran::

    fed_oprp_setup.py ~/code/fedoidc mini_fed

This should create the federation directory containing a number of scripts
and 2 directories (*op* and *rp*).

I'll use *mini_fed* as the name of the federation directory below

Step 2 - Copy and modify configuration
++++++++++++++++++++++++++++++++++++++

Rename the configuration files and modify them if necessary::

    cd mini_fed
    cd op
    cp fed_op_config.py config.py
    cd ../rp
    cp fed_rp_conf.py config.py
    cd ..

You should now have 2 configuration files both named 'config.py'.
One each in the *op* and the *rp* directories.
Make sure the configuration is to your liking.
When running this the first time you should just keep it as it is.
Later you can start modifying.

Step 3 - Running the Setup script
+++++++++++++++++++++++++++++++++

Run the setup script::

    ./setup.sh

This may print some lines that looks like this::

    /Library/Frameworks/Python.framework/Versions/3.5/lib/python3.5/site-packages/Cryptodome/Math/_Numbers_gmp.py:230: UserWarning: implicit cast to 'char *' from a different pointer type: will be forbidden in the future (check that the types are as you expect; use an explicit ffi.cast() if they are correct)
        _gmp.gmp_snprintf(buf, c_size_t(buf_len), b("%Zd"), self._mpz_p)

or::

    Could not access fo_jwks/https%3A%2F%2Fswamid.sunet.se

or::

    cp: jwks_bundle/fo_jwks is a directory (not copied).

You can ignore them.


Setup.py does a lot of things. Like creating key material for all the
participants in the federation (FO=swamid and OA=SUNET) in the *fo_jwks* directory.
It also creates a set of signed metadata statements. Kept in the *ms* directory.
The *jwks_bundle* directory will hold the participants public keys.

Step 4 - Add TLS certificates
+++++++++++++++++++++++++++++

For me this was done by doing::

    cd op/certs
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -nodes -out cert.pem -days 365
    cd ../../rp/certs
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -nodes -out cert.pem -days 365
    cd ../..

Step 5 - Run the RP and the OP
++++++++++++++++++++++++++++++

If you get here everything should be setup and ready to go::

    ./run.sh

If everything has gone without a hitch you should now have an RP running on port 8888
and an OP on 8777. Provided you have not modified the configurations.

To verify the setup use a webbrowser and open the webpage
https://localhost:8888 and enter ‘diana@localhost:8777’
in the input window and press ‘Start’.

Userid: diana
Password: krall

If everything worked OK you should now see a page with some information from the
session.

— Roland




