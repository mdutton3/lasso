#! /usr/bin/env python
# -*- coding: UTF-8 -*-


# Python unit tests for Lasso library
#
# Copyright (C) 2004 Entr'ouvert
# http://lasso.entrouvert.org
# 
# Authors: Emmanuel Raviart <eraviart@entrouvert.com>
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

sys.path.insert(0, '..')
sys.path.insert(0, '../.libs')

import lasso

from IdentityProvider import IdentityProvider
from ServiceProvider import ServiceProvider
from websimulator import *


class LoginTestCase(unittest.TestCase):
    def generateIdpSite(self, internet):
        site = IdentityProvider(self, internet, 'https://identity-provider/')
        site.providerId = 'https://identity-provider/metadata'

        server = lasso.Server.new(
            '../../examples/data/idp-metadata.xml',
            '../../examples/data/idp-public-key.pem',
            '../../examples/data/idp-private-key.pem',
            '../../examples/data/idp-crt.pem',
            lasso.signatureMethodRsaSha1)
        server.add_provider(
            '../../examples/data/sp-metadata.xml',
            '../../examples/data/sp-public-key.pem',
            '../../examples/data/ca-crt.pem')
        site.serverDump = server.dump()
        self.failUnless(site.serverDump)
        server.destroy()

        site.addWebUser('Chantereau')
        site.addWebUser('Clapies')
        site.addWebUser('Febvre')
        site.addWebUser('Nowicki')
        # Frederic Peters has no account on identity provider.
        return site

    def generateSpSite(self, internet):
        site = ServiceProvider(self, internet, 'https://service-provider/')
        site.providerId = 'https://service-provider/metadata'

        server = lasso.Server.new(
            '../../examples/data/sp-metadata.xml',
            '../../examples/data/sp-public-key.pem',
            '../../examples/data/sp-private-key.pem',
            '../../examples/data/sp-crt.pem',
            lasso.signatureMethodRsaSha1)
        server.add_provider(
            '../../examples/data/idp-metadata.xml',
            '../../examples/data/idp-public-key.pem',
            '../../examples/data/ca-crt.pem')
        site.serverDump = server.dump()
        self.failUnless(site.serverDump)
        server.destroy()

        site.addWebUser('Nicolas')
        site.addWebUser('Romain')
        site.addWebUser('Valery')
        # Christophe Nowicki has no account on service provider.
        site.addWebUser('Frederic')
        return site

##     def setUp(self):
##         pass

##     def tearDown(self):
##         pass

    def test01(self):
        """Service provider initiated login using HTTP redirect and service provider initiated logout using SOAP."""

        internet = Internet()
        idpSite = self.generateIdpSite(internet)
        spSite = self.generateSpSite(internet)
        spSite.idpSite = idpSite
        principal = Principal(internet, 'Romain Chantereau')
        principal.keyring[idpSite.url] = 'Chantereau'
        principal.keyring[spSite.url] = 'Romain'

        httpResponse = spSite.doHttpRequest(HttpRequest(principal, 'GET', '/loginUsingRedirect'))
        self.failUnlessEqual(httpResponse.statusCode, 200)
        httpResponse = spSite.doHttpRequest(HttpRequest(principal, 'GET', '/logoutUsingSoap'))
        self.failUnlessEqual(httpResponse.statusCode, 200)

    def test02(self):
        """Service provider initiated login using HTTP redirect and service provider initiated logout using SOAP. Done twice."""

        internet = Internet()
        idpSite = self.generateIdpSite(internet)
        spSite = self.generateSpSite(internet)
        spSite.idpSite = idpSite
        principal = Principal(internet, 'Romain Chantereau')
        principal.keyring[idpSite.url] = 'Chantereau'
        principal.keyring[spSite.url] = 'Romain'

        httpResponse = spSite.doHttpRequest(HttpRequest(principal, 'GET', '/loginUsingRedirect'))
        self.failUnlessEqual(httpResponse.statusCode, 200)
        httpResponse = spSite.doHttpRequest(HttpRequest(principal, 'GET', '/logoutUsingSoap'))
        self.failUnlessEqual(httpResponse.statusCode, 200)

        # Once again, but now the principal already has a federation between spSite and idpSite.
        httpResponse = spSite.doHttpRequest(HttpRequest(principal, 'GET', '/loginUsingRedirect'))
        self.failUnlessEqual(httpResponse.statusCode, 200)
        httpResponse = spSite.doHttpRequest(HttpRequest(principal, 'GET', '/logoutUsingSoap'))
        self.failUnlessEqual(httpResponse.statusCode, 200)

    def test03(self):
        """Service provider initiated login using HTTP redirect, but user fail to authenticate himself on identity provider."""

        internet = Internet()
        idpSite = self.generateIdpSite(internet)
        spSite = self.generateSpSite(internet)
        spSite.idpSite = idpSite
        principal = Principal(internet, 'Frederic Peters')
        # Frederic Peters has no account on identity provider.
        principal.keyring[spSite.url] = 'Frederic'

        httpResponse = spSite.doHttpRequest(HttpRequest(principal, 'GET', '/loginUsingRedirect'))
        self.failUnlessEqual(httpResponse.statusCode, 401)

##     def test06(self):
##         """Service provider LECP login."""

##         # LECP has asked service provider for login.
##         spServer = self.getServer()

##         # FIXME: Why doesn't lasso.Lecp.new have spServer as argument?
##         # spLecp = lasso.Lecp.new(spServer)
##         spLecp = lasso.Lecp.new()
##         spLecp.init_authn_request_envelope(sp, )
##         lasso_lecp_init_authn_request_envelope(sp_lecp, spserver, authnRequest);
##         lasso_lecp_build_authn_request_envelope_msg(sp_lecp);
##         msg = g_strdup(sp_lecp->msg_body);
##         lasso_lecp_destroy(sp_lecp);


suite1 = unittest.makeSuite(LoginTestCase, 'test')

allTests = unittest.TestSuite((suite1,))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity=2).run(allTests).wasSuccessful())

