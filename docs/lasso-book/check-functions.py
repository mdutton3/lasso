#! /usr/bin/env python
#
# Checks a documentation file for functions that do not exist

import re
import sys

functions = {}
for line in file(sys.argv[1]):
    if not "lasso_" in line:
        continue
    if not "(" in line:
        continue
    for f in re.findall(r"(lasso_[a-zA-Z_]+?)\(", line):
        functions[f] = 1

known_symbols = [x.strip() for x in file("../reference/build/lasso-decl-list.txt")]

for f in functions:
    if not f in known_symbols:
        print f

