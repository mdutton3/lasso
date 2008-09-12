# -*- coding: UTF-8 -*-
#
# $Id: XmlTestRunner.py 3254 2007-06-05 21:23:57Z fpeters $
#
# XmlTestRunner
#
# Copyright (C) 2004-2007 Entr'ouvert
#
# Authors: Frederic Peters <fpeters@entrouvert.com>
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


import unittest
import time
import sys

def xml(text):
    if not text:
        return ""
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

class XmlTestResult(unittest.TestResult):
    def addSuccess(self, test):
        print """    <test result="success">
      <id>%s</id>
      <description>%s</description>
    </test>""" % (test.id(), xml(test.shortDescription()))

    def addError(self, test, err):
        unittest.TestResult.addError(self, test, err)
        print """    <test result="error">
      <id>%s</id>
      <description>%s</description>
    </test>""" % (test.id(), xml(test.shortDescription()))
        # TODO: add err

    def addFailure(self, test, err):
        unittest.TestResult.addFailure(self, test, err)
        print """    <test result="failure">
      <id>%s</id>
      <description>%s</description>
    </test>""" % (test.id(), xml(test.shortDescription()))
        # TODO: add err


class XmlTestRunner:
    def _makeResult(self):
        return XmlTestResult()

    def run(self, test):
        print "<suite>"
        result = self._makeResult()
        startTime = time.time()
        test(result)
        stopTime = time.time()
        timeTaken = float(stopTime - startTime)
        print "  <duration>%s</duration>" % timeTaken
        print "</suite>"

        return result

