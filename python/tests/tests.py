#! /usr/bin/env python
# -*- coding: UTF-8 -*-


# PyLasso -- Python bindings for Lasso library
#
# Copyright (C) 2004 Entr'ouvert
# http://lasso.entrouvert.org
# 
# Authors: Nicolas Clapies <nclapies@entrouvert.com>
#          Valery Febvre <vfebvre@easter-eggs.com>
#          Emmanuel Raviart <eraviart@entrouvert.com>
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


import imp
import sys
import time
import unittest

from XmlTestRunner import XmlTestRunner

sys.path.insert(0, '..')
sys.path.insert(0, '../.libs')


testSuites = (
    'login_tests',
    )

if "--xml" in sys.argv:
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

    if "--xml" in sys.argv:
        runner = XmlTestRunner()
    else:
        runner = unittest.TextTestRunner(verbosity=2)
        print
        print '-' * len(doc)
        print doc
        print '-' * len(doc)
    result = runner.run(module.allTests)
    success = success and result.wasSuccessful()

if "--xml" in sys.argv:
    print """</testsuites>"""

sys.exit(not success)

