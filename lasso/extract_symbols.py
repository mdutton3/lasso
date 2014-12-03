#! /usr/bin/env python

import glob
import re
import sys
import six

enable_wsf = False

if '-wsf' in sys.argv:
    enable_wsf = True

if len(sys.argv) == 2+enable_wsf:
    srcdir = sys.argv[1]
else:
    srcdir = '.'

regex = re.compile('LASSO_EXPORT[^;(]*(lasso_[a-zA-Z0-9_]+)', re.MULTILINE)

symbols = []
for header_file in glob.glob('%s/*/*.h' % srcdir) + glob.glob('%s/*.h' % srcdir) + \
        glob.glob('%s/*/*/*.h' % srcdir):
    if ('/id-wsf/' in header_file or '/id-wsf-2.0' in header_file) and not enable_wsf:
        continue
    symbols.extend(regex.findall(open(header_file).read().replace('\\\n', '')))

wsf = ['lasso_disco_', 'lasso_dst_', 'lasso_is_', 'lasso_profile_service_',
        'lasso_discovery', 'lasso_wsf', 'lasso_interaction_', 'lasso_utility_',
        'lasso_sa_', 'lasso_soap_binding', 'lasso_authentication', 'lasso_wsse_',
        'lasso_sec_', 'lasso_idwsf2', 'lasso_wsf2', 'lasso_wsa_',
        'lasso_wsu_']
if enable_wsf:
    wsf = []

for s in symbols:
    for t in wsf:
        if s.startswith(t):
            break
    else:
        six.print_(s)

