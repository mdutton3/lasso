#! /usr/bin/env python
# -*- coding: UTF-8 -*-
#
# $Id: profiles_tests.py 3254 2007-06-05 21:23:57Z fpeters $
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
    srcdir = os.environ.get('srcdir', '.')
    dataDir = '%s/../../../tests/data' % srcdir


class ServerTestCase(unittest.TestCase):
    def test01(self):
        """Server construction, dump & newFromDump."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        lassoServer.addProvider(
            lasso.PROVIDER_ROLE_IDP,
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/public-key.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        dump = lassoServer.dump()
        lassoServer2 = lassoServer.newFromDump(dump)
        dump2 = lassoServer2.dump()
        self.failUnlessEqual(dump, dump2)

    def test02(self):
        """Server construction without argument, dump & newFromDump."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'sp1-la/metadata.xml'))
        lassoServer.addProvider(
            lasso.PROVIDER_ROLE_IDP,
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/public-key.pem'))
        dump = lassoServer.dump()
        lassoServer2 = lassoServer.newFromDump(dump)
        dump2 = lassoServer2.dump()
        self.failUnlessEqual(dump, dump2)


class LoginTestCase(unittest.TestCase):
    def test01(self):
        """SP login; testing access to authentication request."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        lassoServer.addProvider(
            lasso.PROVIDER_ROLE_IDP,
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/public-key.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        login = lasso.Login(lassoServer)
        login.initAuthnRequest()
        login.request
        login.request.protocolProfile = lasso.LIB_PROTOCOL_PROFILE_BRWS_ART
        self.failUnlessEqual(login.request.protocolProfile, lasso.LIB_PROTOCOL_PROFILE_BRWS_ART)

    def test02(self):
        """SP login; testing processing of an empty Response."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        lassoServer.addProvider(
            lasso.PROVIDER_ROLE_IDP,
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/public-key.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        login = lasso.Login(lassoServer)
        try:
            login.processResponseMsg('')
        except lasso.Error, error:
            if error[0] != lasso.PROFILE_ERROR_INVALID_MSG:
                raise

    def test03(self):
        """Conversion of a lib:AuthnRequest with an AuthnContext into a query and back."""

        sp = lasso.Server(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        sp.addProvider(
            lasso.PROVIDER_ROLE_IDP,
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/public-key.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        spLogin = lasso.Login(sp)
        spLogin.initAuthnRequest()
        requestAuthnContext = lasso.LibRequestAuthnContext()
        authnContextClassRefsList = []
        authnContextClassRefsList.append(
            lasso.LIB_AUTHN_CONTEXT_CLASS_REF_PASSWORD)
        requestAuthnContext.authnContextClassRef = tuple(authnContextClassRefsList)
        spLogin.request.requestAuthnContext = requestAuthnContext
        spLogin.request.protocolProfile = lasso.LIB_PROTOCOL_PROFILE_BRWS_ART
        spLogin.buildAuthnRequestMsg()
        authnRequestUrl = spLogin.msgUrl
        authnRequestQuery = spLogin.msgUrl[spLogin.msgUrl.index('?') + 1:]
        idp = lasso.Server(
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        idp.addProvider(
            lasso.PROVIDER_ROLE_SP,
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/public-key.pem'),
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        idpLogin = lasso.Login(idp)
        idpLogin.processAuthnRequestMsg(authnRequestQuery)
        self.failUnless(idpLogin.request.requestAuthnContext)
        authnContextClassRefsList = idpLogin.request.requestAuthnContext.authnContextClassRef
        self.failUnlessEqual(len(authnContextClassRefsList), 1)
        self.failUnlessEqual(authnContextClassRefsList[0],
                             lasso.LIB_AUTHN_CONTEXT_CLASS_REF_PASSWORD)

    def test04(self):
        """Conversion of a lib:AuthnRequest with extensions into a query and back."""

        sp = lasso.Server(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        sp.addProvider(
            lasso.PROVIDER_ROLE_IDP,
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/public-key.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        spLogin = lasso.Login(sp)
        spLogin.initAuthnRequest()
        requestAuthnContext = lasso.LibRequestAuthnContext()
        extensionList = []
        for extension in (
                '<action>do</action>',
                '<action2>do action 2</action2><action3>do action 3</action3>'):
            extensionList.append(
                '<lib:Extension xmlns:lib="urn:liberty:iff:2003-08">%s</lib:Extension>'
                % extension)
        spLogin.request.extension = tuple(extensionList)
        spLogin.request.protocolProfile = lasso.LIB_PROTOCOL_PROFILE_BRWS_ART
        spLogin.buildAuthnRequestMsg()
        authnRequestUrl = spLogin.msgUrl
        authnRequestQuery = spLogin.msgUrl[spLogin.msgUrl.index('?') + 1:]
        idp = lasso.Server(
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        idp.addProvider(
            lasso.PROVIDER_ROLE_SP,
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/public-key.pem'),
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        idpLogin = lasso.Login(idp)
        idpLogin.processAuthnRequestMsg(authnRequestQuery)
        self.failUnless(idpLogin.request.extension)
        extensionsList = idpLogin.request.extension
        self.failUnlessEqual(len(extensionsList), 1)
        self.failUnless('<action>do</action>' in extensionsList[0])
        self.failUnless('<action2>do action 2</action2>' in extensionsList[0])
        self.failUnless('<action3>do action 3</action3>' in extensionsList[0])
        

class LogoutTestCase(unittest.TestCase):
    def test01(self):
        """SP logout without session and identity; testing initRequest."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        lassoServer.addProvider(
            lasso.PROVIDER_ROLE_IDP,
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/public-key.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        logout = lasso.Logout(lassoServer)
        try:
            logout.initRequest()
        except lasso.Error, error:
            if error[0] != lasso.PROFILE_ERROR_SESSION_NOT_FOUND:
                raise
        else:
            self.fail('logout.initRequest without having set identity before should fail')

    def test02(self):
        """IDP logout without session and identity; testing logout.getNextProviderId."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        lassoServer.addProvider(
            lasso.PROVIDER_ROLE_SP,
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/public-key.pem'),
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        logout = lasso.Logout(lassoServer)
        self.failIf(logout.getNextProviderId())

    def test03(self):
        """IDP logout; testing processRequestMsg with non Liberty query."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        lassoServer.addProvider(
            lasso.PROVIDER_ROLE_SP,
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/public-key.pem'),
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        logout = lasso.Logout(lassoServer)
        # The processRequestMsg should fail but not abort.
        try:
            logout.processRequestMsg('passport=0&lasso=1')
        except lasso.Error, error:
            if error[0] != lasso.PROFILE_ERROR_INVALID_MSG:
                raise
        else:
            self.fail('Logout processRequestMsg should have failed.')

    def test04(self):
        """IDP logout; testing processResponseMsg with non Liberty query."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        lassoServer.addProvider(
            lasso.PROVIDER_ROLE_SP,
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/public-key.pem'),
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        logout = lasso.Logout(lassoServer)
        # The processResponseMsg should fail but not abort.
        try:
            logout.processResponseMsg('liberty=&alliance')
        except lasso.Error, error:
            if error[0] != lasso.PROFILE_ERROR_INVALID_MSG:
                raise
        else:
            self.fail('Logout processResponseMsg should have failed.')

    def test05(self):
        """IDP logout; testing logout dump & newFromDump()."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        lassoServer.addProvider(
            lasso.PROVIDER_ROLE_SP,
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/public-key.pem'),
            os.path.join(dataDir, 'sp1-la/certificate.pem'))


class DefederationTestCase(unittest.TestCase):
    def test01(self):
        """IDP initiated defederation; testing processNotificationMsg with non Liberty query."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        lassoServer.addProvider(
            lasso.PROVIDER_ROLE_SP,
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/public-key.pem'),
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        defederation = lasso.Defederation(lassoServer)
        # The processNotificationMsg should fail but not abort.
        try:
            defederation.processNotificationMsg('nonLibertyQuery=1')
        except lasso.Error, error:
            if error[0] != lasso.PROFILE_ERROR_INVALID_MSG:
                raise
        else:
            self.fail('Defederation processNotificationMsg should have failed.')


class IdentityTestCase(unittest.TestCase):
    def test01(self):
        """Identity newFromDump & dump."""
        return
        # test disabled since dump format changed
        identityDump = """<Identity xmlns="http://www.entrouvert.org/namespaces/lasso/0.0" Version="1"><Federations><Federation xmlns="http://www.entrouvert.org/namespaces/lasso/0.0" Version="1" RemoteProviderID="https://sp1.entrouvert.lan/metadata"><LocalNameIdentifier><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://proxy2.entrouvert.lan/metadata" Format="urn:liberty:iff:nameid:federated">_CD739B41C602EAEA93626EBD1751CB46</saml:NameIdentifier></LocalNameIdentifier></Federation><Federation xmlns="http://www.entrouvert.org/namespaces/lasso/0.0" Version="1" RemoteProviderID="https://idp1.entrouvert.lan/metadata"><RemoteNameIdentifier><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://idp1.entrouvert.lan/metadata" Format="urn:liberty:iff:nameid:federated">_11EA77A4FED32C41824AC5DE87298E65</saml:NameIdentifier></RemoteNameIdentifier></Federation></Federations></Identity>"""
        identity = lasso.Identity.newFromDump(identityDump)
        newIdentityDump = identity.dump()
        self.failUnlessEqual(identityDump, newIdentityDump)


serverSuite = unittest.makeSuite(ServerTestCase, 'test')
loginSuite = unittest.makeSuite(LoginTestCase, 'test')
logoutSuite = unittest.makeSuite(LogoutTestCase, 'test')
defederationSuite = unittest.makeSuite(DefederationTestCase, 'test')
identitySuite = unittest.makeSuite(IdentityTestCase, 'test')

allTests = unittest.TestSuite((serverSuite, loginSuite, logoutSuite, defederationSuite,
                               identitySuite))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity = 2).run(allTests).wasSuccessful())

