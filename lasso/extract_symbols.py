#! /usr/bin/env python

import glob
import re
import sys

if len(sys.argv) == 2:
    srcdir = sys.argv[1]
else:
    srcdir = '.'

symbols = []
for header_file in glob.glob('%s/*/*.h' % srcdir) + glob.glob('%s/*.h' % srcdir):
    symbols.extend(re.findall('LASSO_EXPORT.*(lasso_[a-zA-Z0-9_]+).*\(', file(header_file).read()))

for s in symbols:
    print s

