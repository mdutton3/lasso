#! /usr/bin/env python

import glob
import re
import sys

if len(sys.argv) == 2:
    srcdir = sys.argv[1]
else:
    srcdir = '.'

regex = re.compile('LASSO_EXPORT.*(lasso_[a-zA-Z0-9_]+).*\(')

symbols = []
for header_file in glob.glob('%s/*/*.h' % srcdir) + glob.glob('%s/*.h' % srcdir):
    symbols.extend(regex.findall(file(header_file).read().replace('\\\n', '')))

for s in symbols:
    print s

