#! /usr/bin/env python
# -*- coding: UTF-8 -*-


# Python unit tests for Lasso library
# By: Frederic Peters <fpeters@entrouvert.com>
#     Emmanuel Raviart <eraviart@entrouvert.com>
#
# Copyright (C) 2004 Entr'ouvert
# http://lasso.entrouvert.org
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
import sys

if not '..' in sys.path:
    sys.path.insert(0, '..')
if not '../.libs' in sys.path:
    sys.path.insert(0, '../.libs')

import lasso


class ErrorCheckingTestCase(unittest.TestCase):
    def DISABLEDtest01(self):
        # the user should call lasso.Login.new(); but what if it doesn't ?
        # An exception should be raised; the program should not segfault.
        try:
            lasso.Login(None).msg_url
        except:
            pass

    def DISABLEDtest02(self):
        # Same as test01; replace Login by Logout
        try:
            lasso.Logout(None, lasso.providerTypeSp).msg_url
        except:
            pass

    def test03(self):
        # This time; we got something wrong as query string; we pass it to
        # init_from_authn_request_msg; surely it shouldn't segfault
        server = lasso.Server.new(
            '../../tests/data/idp1-la/metadata.xml',
            None, # '../../tests/data/idp1-la/public-key.pem' is no more used
            '../../tests/data/idp1-la/private-key-raw.pem',
            '../../tests/data/idp1-la/certificate.pem',
            lasso.signatureMethodRsaSha1)
        login = lasso.Login.new(server)
        try:
            login.init_from_authn_request_msg("", lasso.httpMethodRedirect)
        except:
            pass


suite1 = unittest.makeSuite(ErrorCheckingTestCase, 'test')

allTests = unittest.TestSuite((suite1,))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity=2).run(allTests).wasSuccessful())

