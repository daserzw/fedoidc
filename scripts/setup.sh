#!/usr/bin/env bash

./fed_setup.py

cp jwks_bundle/* op/jwks_dir
cp jwks_bundle/* rp/jwks_dir

cd op
./faop.py -C discovery -p 8777 config > discovery.json
./faop.py -C response -p 8777 config > response.json
cd ..
./oa_sign.py -i https://sunet.se -c discovery -t op/ms_dir op/discovery.json
./oa_sign.py -i https://sunet.se -c response -t op/ms_dir op/response.json

#cd rp
#./farp.py -I -p 8888 config > clinfo.json
#cd ..
#./oa_sign.py -i https://sunet.se -c registration -t rp/ms_dir rp/clinfo.json
