#!/usr/bin/env python
import os
import sys

import shutil

from fedoidc.site_setup import fedoidc_op_setup
from fedoidc.site_setup import fedoidc_rp_setup

DIR = {
    'op': fedoidc_op_setup,
    'rp': fedoidc_rp_setup,
}

if len(sys.argv) != 3:
    print('Usage: fed_setup.py <root of fedoidc src> <federation site dir>')
    exit()

_fedoidc_dir = sys.argv[1]
_root = sys.argv[2]
if os.path.isdir(_root) is False:
    os.makedirs(_root)

_src_dir = os.path.join(_fedoidc_dir, 'example')

os.chdir(_root)
for file in ['fed_setup.py', 'oa_sign.py', 'clear.sh', 'setup.sh', 'run.sh']:
    shutil.copy(os.path.join(_src_dir, file), '.')


for _dir, func in DIR.items():
    if os.path.isdir(_dir) is False:
        os.mkdir(_dir)
    os.chdir(_dir)
    func(_src_dir)
    os.chdir('..')
