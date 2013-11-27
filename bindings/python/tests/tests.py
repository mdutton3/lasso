#! /usr/bin/env python
# -*- coding: UTF-8 -*-
#
# $Id: tests.py 3425 2007-10-10 09:31:03Z dlaniel $
#
# Python unit tests for Lasso library
#
# Copyright (C) 2004-2007 Entr'ouvert
# http://lasso.entrouvert.org
#
# Authors: See AUTHORS file in top-level directory.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.


import __builtin__
import imp
from optparse import OptionParser
import os
import sys
import time
import unittest

from XmlTestRunner import XmlTestRunner

if not '..' in sys.path:
    sys.path.insert(0, '..')
if not '../.libs' in sys.path:
    sys.path.insert(0, '../.libs')


testSuites = [
    'binding_tests',
    'profiles_tests',
    ]

import lasso
if lasso.WSF_SUPPORT:
    testSuites.append('idwsf1_tests')
    testSuites.append('idwsf2_tests')


# Parse command line options.
parser = OptionParser()
parser.add_option(
    '-x', '--xml', dest = 'xmlMode', help = 'enable XML output',
    action = 'store_true', default = False)
parser.add_option(
    '-s', '--source-dir', dest = 'srcDir', help = 'path of source directory',
    metavar = 'DIR', default = os.getcwd())
(options, args) = parser.parse_args()
__builtin__.__dict__['dataDir'] = os.path.join(options.srcDir, '../../../tests/data')

if options.xmlMode:
    print """<?xml version="1.0"?>"""
    print """<testsuites xmlns="http://check.sourceforge.net/ns">"""
    print """  <title>Python Bindings</title>"""
    print """  <datetime>%s</datetime>""" % time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

success = True
for testSuite in testSuites:
    fp, pathname, description = imp.find_module(testSuite)
    try:
        module = imp.load_module(testSuite, fp, pathname, description)
    finally:
        if fp:
            fp.close()
    if not module:
        print >> sys.stderr, 'Unable to load test suite:', testSuite
        continue

    if module.__doc__:
        doc = module.__doc__
    else:
        doc = testSuite

    if options.xmlMode:
        runner = XmlTestRunner()
    else:
        runner = unittest.TextTestRunner(verbosity=2)
        print
        print '-' * len(doc)
        print doc
        print '-' * len(doc)
    result = runner.run(module.allTests)
    success = success and result.wasSuccessful()

if options.xmlMode:
    print """</testsuites>"""

sys.exit(not success)
