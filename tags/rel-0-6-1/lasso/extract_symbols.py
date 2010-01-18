#! /usr/bin/env python

import glob
import re
import sys

enable_wsf = 0

if '-wsf' in sys.argv:
    enable_wsf = 1

if len(sys.argv) == 2+enable_wsf:
    srcdir = sys.argv[1]
else:
    srcdir = '.'

regex = re.compile('LASSO_EXPORT.*(lasso_[a-zA-Z0-9_]+).*\(')

symbols = []
for header_file in glob.glob('%s/*/*.h' % srcdir) + glob.glob('%s/*.h' % srcdir):
    symbols.extend(regex.findall(file(header_file).read().replace('\\\n', '')))

wsf = ['lasso_disco', 'lasso_dst', 'lasso_is', 'lasso_profile_service',
        'lasso_discovery', 'lasso_wsf', 'lasso_interaction', 'lasso_utility' ]
if enable_wsf:
    wsf = []

for s in symbols:
    for t in wsf:
        if s.startswith(t):
            break
    else:
        print s

