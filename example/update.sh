#!/usr/bin/env bash

./ms_update.py

cd op
./faop.py -C discovery -p 8777 config > discovery.json
./faop.py -C response -p 8777 config > response.json
cd ..
./oa_sign.py -i https://sunet.se -c discovery -t op/ms_dir op/discovery.json
./oa_sign.py -i https://sunet.se -c response -t op/ms_dir op/response.json
