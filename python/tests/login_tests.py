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


import unittest

import lasso
lasso.init()


class LoginTestCase(unittest.TestCase):
    def generateIdentityProviderContextDump(self):
        serverContext = lasso.Server.new(
            "../../examples/data/idp-metadata.xml",
            "../../examples/idp-public-key.pem",
            "../../examples/idp-private-key.pem",
            "../../examples/idp-crt.pem",
            lasso.signatureMethodRsaSha1)
        serverContext.add_provider(
            "../../examples/data/sp-metadata.xml",
            "../../examples/sp-public-key.pem",
            "../../examples/ca-crt.pem")
        serverContextDump = serverContext.dump()
        serverContext.destroy()
        return serverContextDump

    def generateServiceProviderContextDump(self):
        serverContext = lasso.Server.new(
            "../../examples/data/sp-metadata.xml",
            "../../examples/sp-public-key.pem",
            "../../examples/sp-private-key.pem",
            "../../examples/sp-crt.pem",
            lasso.signatureMethodRsaSha1)
        serverContext.add_provider(
            "../../examples/data/idp-metadata.xml",
            "../../examples/idp-public-key.pem",
            "../../examples/ca-crt.pem")
        serverContextDump = serverContext.dump()
        serverContext.destroy()
        return serverContextDump

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test01_generateServersContextDumps(self):
        """Generate identity & service provider context dumps"""
        identityProviderContextDump = self.generateIdentityProviderContextDump()
        self.failUnless(identityProviderContextDump)
        serviceProviderContextDump = self.generateServiceProviderContextDump()
        self.failUnless(serviceProviderContextDump)


suite1 = unittest.makeSuite(LoginTestCase, 'test')

allTests = unittest.TestSuite((suite1,))

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(allTests)

