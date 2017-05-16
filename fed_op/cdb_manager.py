#!/usr/bin/env python3
import json
import time
from urllib.parse import splitquery

from jwkest import as_bytes
from oic import rndstr
from oic.oic.provider import secret
from oic.utils import shelve_wrapper
from oic.utils.time_util import utc_time_sans_frac


def remove_old(cdb):
    remove = []
    now = int(time.time())
    for key in cdb.keys():
        _d = cdb[key]
        if isinstance(_d, dict):
            if _d['client_secret_expires_at'] < now:
                del cdb[key]
            else:
                remove.append(_d['registration_access_token'])

    for key in remove:
        del cdb[key]


def list_clients(cdb):
    for key in cdb.keys():
        _d = cdb[key]
        if isinstance(_d, dict):
            print(_d['client_id'])


def print_client(cdb, cid):
    print(json.dumps(cdb[cid]))


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-l', dest='list', action='store_true')
    parser.add_argument('-c', dest='clear', action='store_true')
    parser.add_argument('-p', dest='print')
    parser.add_argument('-n', dest='new')
    parser.add_argument('-d', dest='delete')
    args = parser.parse_args()

    cdb = shelve_wrapper.open("client_db")

    if args.clear:
        remove_old(cdb)

    if args.delete:
        del cdb[args.delete]

    if args.list:
        list_clients(cdb)

    if args.print:
        print_client(cdb, args.print)

    if args.new:
        _info = json.loads(args.new)
        # MUST contain redirect_uris
        assert 'redirect_uris' in _info

        _info['redirect_uris'] = [splitquery(uri) for uri in
                                  _info['redirect_uris']]

        new = {"client_id_issued_at": utc_time_sans_frac(),
               "client_salt": rndstr(8)}
        try:
            client_id = _info['client_id']
        except KeyError:
            client_id = rndstr(12)
            while client_id in cdb:
                client_id = rndstr(12)
            new['client_id'] = client_id

        try:
            client_secret = _info['client_secret']
        except KeyError:
            seed = as_bytes(rndstr())
            client_secret = secret(seed, as_bytes(client_id))
            new['client_secret'] = client_secret

        _info.update(new)

        cdb[client_id] = _info
