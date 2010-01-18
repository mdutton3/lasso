#! /usr/bin/env python
# -*- coding: UTF-8 -*-
#
# $Id$
#
# Python unit tests for Lasso library
#
# Copyright (C) 2004, 2005 Entr'ouvert
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


import os
import unittest
import sys

if not '..' in sys.path:
    sys.path.insert(0, '..')
if not '../.libs' in sys.path:
    sys.path.insert(0, '../.libs')

import lasso


try:
    dataDir
except NameError:
    dataDir = '../../tests/data'


class ErrorCheckingTestCase(unittest.TestCase):
    def test01(self):
        """Instanciate Login with None as Server"""
        try:
            lasso.Login(None).msgUrl
        except:
            pass

    def test02(self):
        """Instanciate Logout with None as Server"""
        # Same as test01; replace Login by Logout
        try:
            lasso.Logout(None, lasso.providerTypeSp).msgUrl
        except:
            pass

    def test03(self):
        """Process empty string as authnrequest msg"""
        # This time; we got something wrong as query string; we pass it to
        # initFromAuthnRequestMsg; surely it shouldn't segfault
        server = lasso.Server(
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        login = lasso.Login(server)
        try:
            login.processAuthnRequestMsg("")
        except lasso.Error:
            pass


suite1 = unittest.makeSuite(ErrorCheckingTestCase, 'test')

allTests = unittest.TestSuite((suite1,))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity=2).run(allTests).wasSuccessful())

