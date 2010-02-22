#! /usr/bin/env python

from cStringIO import StringIO
import glob
import re
import sys
import os

srcdir = sys.argv[1]

hlines = file('%s/errors.h' % srcdir,'r').readlines()
messages = dict()
description = ''

for line in hlines:
    m = re.match(r'^ \* LASSO.*ERROR', line)
    if m:
        description = ''
        continue
    m = re.match(r'^ \* (.*[^:])$', line)
    if m:
        description += m.group(1)
    m = re.match(r'#define (LASSO_\w*ERROR\w+)', line)
    if m and description:
        description = re.sub(r'[ \n]+', ' ', description).strip()
        messages[m.group(1)] = description
        description = ''
    else:
        m = re.match(r'#define (LASSO_\w*ERROR\w+)',line)
        if m:
            messages[m.group(1)] = m.group(1)

clines = file('%s/errors.c.in' % srcdir,'r').readlines()
for line in clines:
    if '@ERROR_CASES@' in line:
        keys = messages.keys()
        keys.sort()
        for k in keys:
            print """		case %s:
			return "%s";""" % (k,messages[k].rstrip('\n'))
    else:
        print line,
