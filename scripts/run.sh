#!/usr/bin/env bash

cd op
./faop.py -p 8777 -k -t config >& faop.log &

cd ../rp
./farp.py -p 8888 -k -t config >& farp.log &

cd ..
