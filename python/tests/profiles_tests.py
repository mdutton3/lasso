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


class BindingTestCase(unittest.TestCase):
    def test01(self):
        """Create and delete nodes."""

        authnRequest = lasso.LibAuthnRequest()
        del authnRequest

    def test02(self):
        """Get & set simple attributes of nodes."""

        authnRequest = lasso.LibAuthnRequest()

        # Test a string attribute.
        self.failUnlessEqual(authnRequest.consent, None)
        authnRequest.consent = lasso.libConsentObtained
        self.failUnlessEqual(authnRequest.consent, lasso.libConsentObtained)
        authnRequest.consent = None
        self.failUnlessEqual(authnRequest.consent, None)

        # Test a renamed string attribute.
        self.failUnlessEqual(authnRequest.relayState, None)
        authnRequest.relayState = 'Hello World!'
        self.failUnlessEqual(authnRequest.relayState, 'Hello World!')
        authnRequest.relayState = None
        self.failUnlessEqual(authnRequest.relayState, None)

        # Test an integer attribute.
        self.failUnlessEqual(authnRequest.majorVersion, 0)
        authnRequest.majorVersion = 314
        self.failUnlessEqual(authnRequest.majorVersion, 314)

        del authnRequest

    def test03(self):
        """Get & set attributes of nodes of type string list."""

        authnRequest = lasso.LibAuthnRequest()

        self.failUnlessEqual(authnRequest.respondWith, None)

        respondWith = lasso.StringList()
        self.failUnlessEqual(len(respondWith), 0)
        respondWith.append('first string')
        self.failUnlessEqual(len(respondWith), 1)
        self.failUnlessEqual(respondWith[0], 'first string')
        self.failUnlessEqual(respondWith[0], 'first string')
        respondWith.append('second string')
        self.failUnlessEqual(len(respondWith), 2)
        self.failUnlessEqual(respondWith[0], 'first string')
        self.failUnlessEqual(respondWith[1], 'second string')
        respondWith.append('third string')
        self.failUnlessEqual(len(respondWith), 3)
        self.failUnlessEqual(respondWith[0], 'first string')
        self.failUnlessEqual(respondWith[1], 'second string')
        self.failUnlessEqual(respondWith[2], 'third string')
        authnRequest.respondWith = respondWith
        self.failUnlessEqual(authnRequest.respondWith[0], 'first string')
        self.failUnlessEqual(authnRequest.respondWith[1], 'second string')
        self.failUnlessEqual(authnRequest.respondWith[2], 'third string')
        self.failUnlessEqual(respondWith[0], 'first string')
        self.failUnlessEqual(respondWith[1], 'second string')
        self.failUnlessEqual(respondWith[2], 'third string')
        del respondWith
        self.failUnlessEqual(authnRequest.respondWith[0], 'first string')
        self.failUnlessEqual(authnRequest.respondWith[1], 'second string')
        self.failUnlessEqual(authnRequest.respondWith[2], 'third string')
        respondWith = authnRequest.respondWith
        self.failUnlessEqual(respondWith[0], 'first string')
        self.failUnlessEqual(respondWith[1], 'second string')
        self.failUnlessEqual(respondWith[2], 'third string')
        del respondWith
        self.failUnlessEqual(authnRequest.respondWith[0], 'first string')
        self.failUnlessEqual(authnRequest.respondWith[1], 'second string')
        self.failUnlessEqual(authnRequest.respondWith[2], 'third string')
        authnRequest.respondWith = None
        self.failUnlessEqual(authnRequest.respondWith, None)

        del authnRequest

    def test04(self):
        """Get & set attributes of nodes of type node list."""

        response = lasso.SamlpResponse()

        self.failUnlessEqual(response.assertion, None)

        assertions = lasso.NodeList()
        self.failUnlessEqual(len(assertions), 0)
        assertion1 = lasso.SamlAssertion()
        assertion1.assertionId = 'assertion 1'
        assertions.append(assertion1)
        self.failUnlessEqual(len(assertions), 1)
        self.failUnlessEqual(assertions[0].assertionId, 'assertion 1')
        self.failUnlessEqual(assertions[0].assertionId, 'assertion 1')
        assertion2 = lasso.SamlAssertion()
        assertion2.assertionId = 'assertion 2'
        assertions.append(assertion2)
        self.failUnlessEqual(len(assertions), 2)
        self.failUnlessEqual(assertions[0].assertionId, 'assertion 1')
        self.failUnlessEqual(assertions[1].assertionId, 'assertion 2')
        assertion3 = lasso.SamlAssertion()
        assertion3.assertionId = 'assertion 3'
        assertions.append(assertion3)
        self.failUnlessEqual(len(assertions), 3)
        self.failUnlessEqual(assertions[0].assertionId, 'assertion 1')
        self.failUnlessEqual(assertions[1].assertionId, 'assertion 2')
        self.failUnlessEqual(assertions[2].assertionId, 'assertion 3')
        response.assertion = assertions
        self.failUnlessEqual(response.assertion[0].assertionId, 'assertion 1')
        self.failUnlessEqual(response.assertion[1].assertionId, 'assertion 2')
        self.failUnlessEqual(response.assertion[2].assertionId, 'assertion 3')
        self.failUnlessEqual(assertions[0].assertionId, 'assertion 1')
        self.failUnlessEqual(assertions[1].assertionId, 'assertion 2')
        self.failUnlessEqual(assertions[2].assertionId, 'assertion 3')
        del assertions
        self.failUnlessEqual(response.assertion[0].assertionId, 'assertion 1')
        self.failUnlessEqual(response.assertion[1].assertionId, 'assertion 2')
        self.failUnlessEqual(response.assertion[2].assertionId, 'assertion 3')
        assertions = response.assertion
        self.failUnlessEqual(assertions[0].assertionId, 'assertion 1')
        self.failUnlessEqual(assertions[1].assertionId, 'assertion 2')
        self.failUnlessEqual(assertions[2].assertionId, 'assertion 3')
        del assertions
        self.failUnlessEqual(response.assertion[0].assertionId, 'assertion 1')
        self.failUnlessEqual(response.assertion[1].assertionId, 'assertion 2')
        self.failUnlessEqual(response.assertion[2].assertionId, 'assertion 3')
        response.assertion = None
        self.failUnlessEqual(response.assertion, None)

        del response

    def test05(self):
        """Get & set attributes of nodes of type XML list."""

        authnRequest = lasso.LibAuthnRequest()

        self.failUnlessEqual(authnRequest.extension, None)

        actionString1 = """\
<lib:Extension xmlns:lib="urn:liberty:iff:2003-08">
  <action>do 1</action>
</lib:Extension>"""
        actionString2 = """\
<lib:Extension xmlns:lib="urn:liberty:iff:2003-08">
  <action>do 2</action>
</lib:Extension>"""
        actionString3 = """\
<lib:Extension xmlns:lib="urn:liberty:iff:2003-08">
  <action>do 3</action>
</lib:Extension>"""
        extension = lasso.StringList()
        self.failUnlessEqual(len(extension), 0)
        extension.append(actionString1)
        self.failUnlessEqual(len(extension), 1)
        self.failUnlessEqual(extension[0], actionString1)
        self.failUnlessEqual(extension[0], actionString1)
        extension.append(actionString2)
        self.failUnlessEqual(len(extension), 2)
        self.failUnlessEqual(extension[0], actionString1)
        self.failUnlessEqual(extension[1], actionString2)
        extension.append(actionString3)
        self.failUnlessEqual(len(extension), 3)
        self.failUnlessEqual(extension[0], actionString1)
        self.failUnlessEqual(extension[1], actionString2)
        self.failUnlessEqual(extension[2], actionString3)
        authnRequest.extension = extension
        self.failUnlessEqual(authnRequest.extension[0], actionString1)
        self.failUnlessEqual(authnRequest.extension[1], actionString2)
        self.failUnlessEqual(authnRequest.extension[2], actionString3)
        self.failUnlessEqual(extension[0], actionString1)
        self.failUnlessEqual(extension[1], actionString2)
        self.failUnlessEqual(extension[2], actionString3)
        del extension
        self.failUnlessEqual(authnRequest.extension[0], actionString1)
        self.failUnlessEqual(authnRequest.extension[1], actionString2)
        self.failUnlessEqual(authnRequest.extension[2], actionString3)
        extension = authnRequest.extension
        self.failUnlessEqual(extension[0], actionString1)
        self.failUnlessEqual(extension[1], actionString2)
        self.failUnlessEqual(extension[2], actionString3)
        del extension
        self.failUnlessEqual(authnRequest.extension[0], actionString1)
        self.failUnlessEqual(authnRequest.extension[1], actionString2)
        self.failUnlessEqual(authnRequest.extension[2], actionString3)
        authnRequest.extension = None
        self.failUnlessEqual(authnRequest.extension, None)

        del authnRequest

    def test06(self):
        """Get & set attributes of nodes of type node."""

        login = lasso.Login(lasso.Server())

        self.failUnlessEqual(login.request, None)
        login.request = lasso.LibAuthnRequest()
        login.request.consent = lasso.libConsentObtained
        self.failUnlessEqual(login.request.consent, lasso.libConsentObtained)
        login.request = None
        self.failUnlessEqual(login.request, None)

        del login


class ServerTestCase(unittest.TestCase):
    def test01(self):
        """Server construction, dump & newFromDump."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        lassoServer.addProvider(
            lasso.providerRoleIdp,
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/public-key.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        dump = lassoServer.dump()
        lassoServer2 = lassoServer.newFromDump(dump)
        dump2 = lassoServer2.dump()
        self.failUnlessEqual(dump, dump2)

    def test02(self):
        """Server construction without argument, dump & newFromDump."""

        lassoServer = lasso.Server()
        lassoServer.addProvider(
            lasso.providerRoleIdp, os.path.join(dataDir, 'idp1-la/metadata.xml'))
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
            lasso.providerRoleIdp,
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/public-key.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        login = lasso.Login(lassoServer)
        login.initAuthnRequest()
        login.request
        login.request.protocolProfile = lasso.libProtocolProfileBrwsArt
        self.failUnlessEqual(login.request.protocolProfile, lasso.libProtocolProfileBrwsArt)

    def test02(self):
        """SP login; testing processing of an empty Response."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        lassoServer.addProvider(
            lasso.providerRoleIdp,
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/public-key.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        login = lasso.Login(lassoServer)
        try:
            login.processResponseMsg('')
        except lasso.Error, error:
            if error[0] != lasso.PROFILE_ERROR_INVALID_MSG:
                raise


class LogoutTestCase(unittest.TestCase):
    def test01(self):
        """SP logout without session and identity; testing initRequest."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        lassoServer.addProvider(
            lasso.providerRoleIdp,
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
            lasso.providerRoleSp,
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
            lasso.providerRoleSp,
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
            lasso.providerRoleSp,
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
            lasso.providerRoleSp,
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
            lasso.providerRoleSp,
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


bindingSuite = unittest.makeSuite(BindingTestCase, 'test')
serverSuite = unittest.makeSuite(ServerTestCase, 'test')
loginSuite = unittest.makeSuite(LoginTestCase, 'test')
logoutSuite = unittest.makeSuite(LogoutTestCase, 'test')
defederationSuite = unittest.makeSuite(DefederationTestCase, 'test')
identitySuite = unittest.makeSuite(IdentityTestCase, 'test')

allTests = unittest.TestSuite((bindingSuite, serverSuite, loginSuite, logoutSuite,
                               defederationSuite, identitySuite))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity = 2).run(allTests).wasSuccessful())

