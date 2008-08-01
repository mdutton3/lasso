#! /usr/bin/env python

from cStringIO import StringIO
import glob
import re
import sys
import os

srcdir = sys.argv[1]

hlines = file('%s/errors.h' % srcdir,'r').readlines()
messages = dict()

for line in hlines:
	m = re.match(r'#define (LASSO_\w+).*\/\*\s*(.*?)\s*\*\/', line)
	if m:
		messages[m.group(1)] = m.group(2)
	else:
		m = re.match(r'#define (LASSO_\w+)',line)
		if m:
			messages[m.group(1)] = m.group(1)

clines = file('%s/errors.c.in' % srcdir,'r').readlines()
for line in clines:
	if '@ERROR_CASES@' in line:
		for k in messages:
			print """		case %s:
			return "%s";""" % (k,messages[k])
	else:
		print line,
