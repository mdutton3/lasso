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

import builtins
from IdentityProvider import IdentityProvider
from LibertyEnabledClient import LibertyEnabledClient
from ServiceProvider import ServiceProvider
from websimulator import *


class LoginTestCase(unittest.TestCase):
    def generateIdpSite(self, internet):
        site = IdentityProvider(internet, 'https://identity-provider/')
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
        failUnless(site.serverDump)
        server.destroy()

        site.addWebUser('Chantereau')
        site.addWebUser('Clapies')
        site.addWebUser('Febvre')
        site.addWebUser('Nowicki')
        # Frederic Peters has no account on identity provider.
        return site

    def generateLibertyEnabledClient(self, internet):
        client = LibertyEnabledClient(internet)
        # FIXME: Lasso should provide a way for Liberty-enabled client to create a "server" without
        # metadata, instead of using 'singleSignOnServiceUrl'.
##         server = lasso.Server.new(
##             None, # A LECP has no metadata.
##             '../../examples/data/client-public-key.pem',
##             '../../examples/data/client-private-key.pem',
##             '../../examples/data/client-crt.pem',
##             lasso.signatureMethodRsaSha1)
##         server.add_provider(
##             '../../examples/data/idp-metadata.xml',
##             '../../examples/data/idp-public-key.pem',
##             '../../examples/data/ca-crt.pem')
##         client.server = server
        client.idpSingleSignOnServiceUrl = 'https://identity-provider/singleSignOn'
        return client
        
    def generateSpSite(self, internet):
        site = ServiceProvider(internet, 'https://service-provider/')
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
        failUnless(site.serverDump)
        server.destroy()

        site.addWebUser('Nicolas')
        site.addWebUser('Romain')
        site.addWebUser('Valery')
        # Christophe Nowicki has no account on service provider.
        site.addWebUser('Frederic')
        return site

    def setUp(self):
        for name in ('fail', 'failIf', 'failIfAlmostEqual', 'failIfEqual', 'failUnless',
                     'failUnlessAlmostEqual', 'failUnlessRaises', 'failUnlessEqual'):
            builtins.set(name, getattr(self, name))

    def tearDown(self):
        for name in ('fail', 'failIf', 'failIfAlmostEqual', 'failIfEqual', 'failUnless',
                     'failUnlessAlmostEqual', 'failUnlessRaises', 'failUnlessEqual'):
            builtins.delete(name)

    def test00(self):
        """LECP login."""
        internet = Internet()
        idpSite = self.generateIdpSite(internet)
        spSite = self.generateSpSite(internet)
        spSite.idpSite = idpSite
        lec = self.generateLibertyEnabledClient(internet)
        principal = Principal(internet, 'Romain Chantereau')
        principal.keyring[idpSite.url] = 'Chantereau'
        principal.keyring[spSite.url] = 'Romain'
        httpResponse = lec.login(principal, spSite, '/login')
        raise str((httpResponse.headers['Content-Type'], httpResponse.body))

    def test01(self):
        """Service provider initiated login using HTTP redirect and service provider initiated logout using SOAP."""

        internet = Internet()
        idpSite = self.generateIdpSite(internet)
        spSite = self.generateSpSite(internet)
        spSite.idpSite = idpSite
        principal = Principal(internet, 'Romain Chantereau')
        principal.keyring[idpSite.url] = 'Chantereau'
        principal.keyring[spSite.url] = 'Romain'

        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/login')
        failUnlessEqual(httpResponse.statusCode, 200)
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/logoutUsingSoap')
        failUnlessEqual(httpResponse.statusCode, 200)
        failIf(spSite.webSessions)
        failIf(idpSite.webSessions)

    def test02(self):
        """Service provider initiated login using HTTP redirect and service provider initiated logout using SOAP. Done three times."""

        internet = Internet()
        idpSite = self.generateIdpSite(internet)
        spSite = self.generateSpSite(internet)
        spSite.idpSite = idpSite
        principal = Principal(internet, 'Romain Chantereau')
        principal.keyring[idpSite.url] = 'Chantereau'
        principal.keyring[spSite.url] = 'Romain'

        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/login')
        failUnlessEqual(httpResponse.statusCode, 200)
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/logoutUsingSoap')
        failUnlessEqual(httpResponse.statusCode, 200)

        # Once again. Now the principal already has a federation between spSite and idpSite.
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/login')
        failUnlessEqual(httpResponse.statusCode, 200)
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/logoutUsingSoap')
        failUnlessEqual(httpResponse.statusCode, 200)

        # Once again. Do a new passive login between normal login and logout.
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/login')
        failUnlessEqual(httpResponse.statusCode, 200)
        del principal.keyring[idpSite.url] # Ensure identity provider will be really passive.
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/login?isPassive=1')
        failUnlessEqual(httpResponse.statusCode, 200)
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/logoutUsingSoap')
        failUnlessEqual(httpResponse.statusCode, 200)

        # Once again, with isPassive and the user having no web session.
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/login?isPassive=1')
        failUnlessEqual(httpResponse.statusCode, 401)

    def test03(self):
        """Service provider initiated login using HTTP redirect, but user fail to authenticate himself on identity provider. Then logout, with same problem."""

        internet = Internet()
        idpSite = self.generateIdpSite(internet)
        spSite = self.generateSpSite(internet)
        spSite.idpSite = idpSite
        principal = Principal(internet, 'Frederic Peters')
        # Frederic Peters has no account on identity provider.
        principal.keyring[spSite.url] = 'Frederic'

        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/login')
        failUnlessEqual(httpResponse.statusCode, 401)
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/logoutUsingSoap')
        failUnlessEqual(httpResponse.statusCode, 401)

    def test04(self):
        """Service provider initiated login using HTTP redirect, but user has no account on service
        provider and doesn't create one."""

        internet = Internet()
        idpSite = self.generateIdpSite(internet)
        spSite = self.generateSpSite(internet)
        spSite.idpSite = idpSite
        principal = Principal(internet, 'Christophe Nowicki')
        principal.keyring[idpSite.url] = 'Nowicki'
        # Christophe Nowicki has no account on service provider.

        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/login')
        failUnlessEqual(httpResponse.statusCode, 401)
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/logoutUsingSoap')
        failUnlessEqual(httpResponse.statusCode, 401)

    def test05(self):
        """Service provider initiated login using HTTP redirect with isPassive for a user without federation yet."""

        internet = Internet()
        idpSite = self.generateIdpSite(internet)
        spSite = self.generateSpSite(internet)
        spSite.idpSite = idpSite
        principal = Principal(internet, 'Romain Chantereau')
        principal.keyring[idpSite.url] = 'Chantereau'
        principal.keyring[spSite.url] = 'Romain'

        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/login?isPassive=1')
        failUnlessEqual(httpResponse.statusCode, 401)

    def test06(self):
        """Testing forceAuthn flag."""

        internet = Internet()
        idpSite = self.generateIdpSite(internet)
        spSite = self.generateSpSite(internet)
        spSite.idpSite = idpSite
        principal = Principal(internet, 'Romain Chantereau')
        principal.keyring[idpSite.url] = 'Chantereau'
        principal.keyring[spSite.url] = 'Romain'

        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/login?forceAuthn=1')
        failUnlessEqual(httpResponse.statusCode, 200)
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/logoutUsingSoap')
        failUnlessEqual(httpResponse.statusCode, 200)

        # Ask user to reauthenticate while he is already logged.
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/login?forceAuthn=1')
        failUnlessEqual(httpResponse.statusCode, 200)
        del principal.keyring[idpSite.url] # Ensure user can't authenticate.
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/login?forceAuthn=1')
        failUnlessEqual(httpResponse.statusCode, 401)
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/logoutUsingSoap')
        failUnlessEqual(httpResponse.statusCode, 200)

        # Force authentication, but user won't authenticate.
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/login?forceAuthn=1')
        failUnlessEqual(httpResponse.statusCode, 401)
        httpResponse = principal.sendHttpRequestToSite(spSite, 'GET', '/logoutUsingSoap')
        failUnlessEqual(httpResponse.statusCode, 401)

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

