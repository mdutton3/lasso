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


class ServerTestCase(unittest.TestCase):
    def test01(self):
        """Server construction, dump & newFromDump."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            None, # os.path.join(dataDir, 'sp1-la/public-key.pem') is no more used
            os.path.join(dataDir, 'sp1-la/private-key-raw.pem'),
            os.path.join(dataDir, 'sp1-la/certificate.pem'),
            lasso.signatureMethodRsaSha1)
        lassoServer.addProvider(
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
        lassoServer.addProvider(os.path.join(dataDir, 'idp1-la/metadata.xml'))
        dump = lassoServer.dump()
        lassoServer2 = lassoServer.newFromDump(dump)
        dump2 = lassoServer2.dump()
        self.failUnlessEqual(dump, dump2)


class LoginTestCase(unittest.TestCase):
    def test01(self):
        """SP login; testing access to authentication request."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            None, # os.path.join(dataDir, 'sp1-la/public-key.pem') is no more used
            os.path.join(dataDir, 'sp1-la/private-key-raw.pem'),
            os.path.join(dataDir, 'sp1-la/certificate.pem'),
            lasso.signatureMethodRsaSha1)
        lassoServer.addProvider(
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/public-key.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        login = lasso.Login(lassoServer)
        login.initAuthnRequest(lasso.httpMethodRedirect)
        login.authnRequest
        login.authnRequest.protocolProfile = lasso.libProtocolProfileBrwsArt


class LogoutTestCase(unittest.TestCase):
    def test01(self):
        """SP logout without session and identity; testing initRequest."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            None, # os.path.join(dataDir, 'sp1-la/public-key.pem') is no more used
            os.path.join(dataDir, 'sp1-la/private-key-raw.pem'),
            os.path.join(dataDir, 'sp1-la/certificate.pem'),
            lasso.signatureMethodRsaSha1)
        lassoServer.addProvider(
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            os.path.join(dataDir, 'idp1-la/public-key.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'))
        logout = lasso.Logout(lassoServer, lasso.providerTypeSp)
        try:
            logout.initRequest()
        except RuntimeError, error:
            errorCode = int(error.args[0].split(' ', 1)[0])
            if errorCode != -1:
                raise
        else:
            self.fail('logout.initRequest without having set identity before should fail')

    def test02(self):
        """IDP logout without session and identity; testing logout.getNextProviderId."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            None, # os.path.join(dataDir, 'idp1-la/public-key.pem') is no more used
            os.path.join(dataDir, 'idp1-la/private-key-raw.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'),
            lasso.signatureMethodRsaSha1)
        lassoServer.addProvider(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/public-key.pem'),
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        logout = lasso.Logout(lassoServer, lasso.providerTypeIdp)
        self.failIf(logout.getNextProviderId())

    def test03(self):
        """IDP logout; testing processRequestMsg with non Liberty query."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            None, # os.path.join(dataDir, 'idp1-la/public-key.pem') is no more used
            os.path.join(dataDir, 'idp1-la/private-key-raw.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'),
            lasso.signatureMethodRsaSha1)
        lassoServer.addProvider(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/public-key.pem'),
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        logout = lasso.Logout(lassoServer, lasso.providerTypeIdp)
        # The processRequestMsg should fail but not abort.
        try:
            logout.processRequestMsg('passport=0&lasso=1', lasso.httpMethodRedirect)
        except SyntaxError:
            pass
        else:
            self.fail('Logout processRequestMsg should have failed.')

    def test04(self):
        """IDP logout; testing processResponseMsg with non Liberty query."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            None, # os.path.join(dataDir, 'idp1-la/public-key.pem') is no more used
            os.path.join(dataDir, 'idp1-la/private-key-raw.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'),
            lasso.signatureMethodRsaSha1)
        lassoServer.addProvider(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/public-key.pem'),
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        logout = lasso.Logout(lassoServer, lasso.providerTypeIdp)
        # The processResponseMsg should fail but not abort.
        try:
            logout.processResponseMsg('liberty=&alliance', lasso.httpMethodRedirect)
        except SyntaxError:
            pass
        else:
            self.fail('Logout processResponseMsg should have failed.')

    def test05(self):
        """IDP logout; testing logout dump & newFromDump()."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            None, # os.path.join(dataDir, 'idp1-la/public-key.pem') is no more used
            os.path.join(dataDir, 'idp1-la/private-key-raw.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'),
            lasso.signatureMethodRsaSha1)
        lassoServer.addProvider(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/public-key.pem'),
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        lassoLogoutDump = """
<Logout xmlns="http://www.entrouvert.org/namespaces/lasso/0.0"><lib:LogoutRequest xmlns:lib="urn:liberty:iff:2003-08" RequestID="_6857939027AA10E2E8DDE40559BAD155" MajorVersion="1" MinorVersion="2" IssueInstant="2004-08-31T22:49:35Z"><lib:ProviderID>https://idp1/metadata</lib:ProviderID><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://idp1/metadata" Format="urn:liberty:iff:nameid:federated">_68D63AFCDE6A9CB4DBDBA5C411ED086F</saml:NameIdentifier></lib:LogoutRequest><NameIdentifier>_68D63AFCDE6A9CB4DBDBA5C411ED086F</NameIdentifier><RemoteProviderID>https://sp1/metadata</RemoteProviderID><MsgUrl>https://sp1:2006/singleLogout?NameIdentifier=_68D63AFCDE6A9CB4DBDBA5C411ED086F&amp;Format=urn%3Aliberty%3Aiff%3Anameid%3Afederated&amp;NameQualifier=https%3A%2F%2Fidp1%2Fmetadata&amp;ProviderID=https%3A%2F%2Fidp1%2Fmetadata&amp;IssueInstant=2004-08-31T22%3A49%3A35Z&amp;MinorVersion=2&amp;MajorVersion=1&amp;RequestID=_6857939027AA10E2E8DDE40559BAD155&amp;SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&amp;Signature=law0RBgfmWoJ61u1aCzMhD59cFFh5O%2FY62P7C%2F2UKmOL4Ay7Gln5kI4jtgsbJkBe%0AKM5reehsofqGufpArbOFxEVlsV8To8S1zfXla1yDVB2aLZUb8qnrfrcW3rQoJbMd%0AJSUZ8i5JnADBn1ql31Eh%2BtcXrKDJVAFVZa0%2BHQMpDT1y0n2tsC49gsesLr9bXDHy%0A7Nia7%2Bl9qJfOzMGoiXlP6ClfT8LzjYxtdM7yfSDz%2FY4LcGGcjlGvsmG7tgUeYHPG%0AI6zixoTr2i6AS7PSZ41FosmVZTugBIueWWWtxffXp6BNQbzJqUojyZeGMhNeVtS8%0AaKQZ8KsYgOSAeMAA2v%2FbHw%3D%3D</MsgUrl><RequestType>0</RequestType><ResponseType>0</ResponseType><ProviderType>2</ProviderType></Logout>
""".strip() # Emacs Python Mode trick: "
        for i in range(20):
            # The newFromDump should not segfault from time to time.
            logout = lasso.Logout.newFromDump(lassoServer, lassoLogoutDump)
            self.failUnlessEqual(logout.dump(), lassoLogoutDump)


class DefederationTestCase(unittest.TestCase):
    def test01(self):
        """IDP initiated defederation; testing processNotificationMsg with non Liberty query."""

        lassoServer = lasso.Server(
            os.path.join(dataDir, 'idp1-la/metadata.xml'),
            None, # os.path.join(dataDir, 'idp1-la/public-key.pem') is no more used
            os.path.join(dataDir, 'idp1-la/private-key-raw.pem'),
            os.path.join(dataDir, 'idp1-la/certificate.pem'),
            lasso.signatureMethodRsaSha1)
        lassoServer.addProvider(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/public-key.pem'),
            os.path.join(dataDir, 'sp1-la/certificate.pem'))
        defederation = lasso.Defederation(lassoServer, lasso.providerTypeIdp)
        # The processNotificationMsg should fail but not abort.
        try:
            defederation.processNotificationMsg('nonLibertyQuery=1', lasso.httpMethodRedirect)
        except SyntaxError:
            pass
        else:
            self.fail('Defederation processNotificationMsg should have failed.')


suite1 = unittest.makeSuite(ServerTestCase, 'test')
suite2 = unittest.makeSuite(LoginTestCase, 'test')
suite3 = unittest.makeSuite(LogoutTestCase, 'test')
suite4 = unittest.makeSuite(DefederationTestCase, 'test')

allTests = unittest.TestSuite((suite1, suite2, suite3, suite4))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity = 2).run(allTests).wasSuccessful())

