#! /usr/bin/env python
#
# Checks a documentation file for functions that do not exist

import os
import re
import sys

functions = {}
for filename in os.listdir('.'):
    if filename[-4:] not in ('.txt', '.rst'):
        continue
    for line in file(filename):
        if not 'lasso_' in line:
            continue
        if not '(' in line:
            continue
        for f in re.findall(r'(lasso_[a-zA-Z_]+?)\(', line):
            functions[f] = 1

#for f in functions:
#    print f

known_symbols = [x.strip() for x in file('../reference/build/lasso-decl-list.txt')]

failure = 0
for f in functions:
    if not f in known_symbols:
        print f
        failure = 1

sys.exit(failure)

