#! /usr/bin/env python
# -*- coding: UTF-8 -*-
#
# $Id: binding_tests.py 3283 2007-06-11 09:10:18Z dlaniel $
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
# along with this program; if not, see <http://www.gnu.org/licenses/>.


import unittest
import sys
import os
import logging

logging.basicConfig()

if not '..' in sys.path:
    sys.path.insert(0, '..')
if not '../.libs' in sys.path:
    sys.path.insert(0, '../.libs')

import lasso

try:
    dataDir
except NameError:
    srcdir = os.environ.get('TOP_SRCDIR', '.')
    dataDir = '%s/tests/data' % srcdir


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
        authnRequest.consent = lasso.LIB_CONSENT_OBTAINED
        self.failUnlessEqual(authnRequest.consent, lasso.LIB_CONSENT_OBTAINED)
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

        self.failUnlessEqual(authnRequest.respondWith, ())

        respondWith = []
        self.failUnlessEqual(len(respondWith), 0)
        respondWith.append('first string')
        self.failUnlessEqual(len(respondWith), 1)
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
        authnRequest.respondWith = tuple(respondWith)
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
        self.failUnlessEqual(authnRequest.respondWith, ())

        del authnRequest

    def test04(self):
        """Get & set attributes of nodes of type node list."""

        response = lasso.SamlpResponse()

        self.failUnlessEqual(response.assertion, ())

        assertions = []
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
        response.assertion = tuple(assertions)
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
        self.failUnlessEqual(response.assertion, ())

        del response

    def test05(self):
        """Get & set attributes of nodes of type XML list."""

        authnRequest = lasso.LibAuthnRequest()

        self.failUnlessEqual(authnRequest.extension, ())

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
        extension = []
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
        authnRequest.extension = tuple(extension)
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
        self.failUnlessEqual(authnRequest.extension, ())

        del authnRequest

    def test06(self):
        """Get & set attributes of nodes of type node."""

        login = lasso.Login(lasso.Server(
            os.path.join(dataDir, 'sp1-la/metadata.xml'),
            os.path.join(dataDir, 'sp1-la/private-key-raw.pem'),
            None,
            os.path.join(dataDir, 'sp1-la/certificate.pem')))

        self.failUnlessEqual(login.request, None)
        login.request = lasso.LibAuthnRequest()
        login.request.consent = lasso.LIB_CONSENT_OBTAINED
        self.failUnlessEqual(login.request.consent, lasso.LIB_CONSENT_OBTAINED)
        login.request = None
        self.failUnlessEqual(login.request, None)

        del login

    def test07(self):
        '''Check reference counting'''
        s = lasso.Samlp2AuthnRequest()
        cptr = s._cptr
        a = sys.getrefcount(s._cptr)
        del(s)
        b = sys.getrefcount(cptr)
        self.failUnlessEqual(b, a-1)

    def test08(self):
        '''Test an integer attribute'''
        authnRequest = lasso.LibAuthnRequest()
        authnRequest.majorVersion = 314
        self.failUnlessEqual(authnRequest.majorVersion, 314)

    def test09(self):
        '''Test dictionary attributes'''
        identity = lasso.Identity.newFromDump(file(
                    os.path.join(dataDir, 'sample-identity-dump-1.xml')).read())
        self.failUnlessEqual(len(identity.federations.keys()), 2)
        self.failIf(not 'http://idp1.lasso.lan' in identity.federations.keys())
        self.failUnlessEqual(
                identity.federations['http://idp1.lasso.lan'].localNameIdentifier.content,
                'first name id')

    def test10(self):
        '''Test Server.setEncryptionPrivateKeyWithPassword'''
        pkey_path = os.path.join(
            dataDir, 'idp5-saml2', 'private-key.pem')
        server = lasso.Server(os.path.join(dataDir, 'idp5-saml2', 'metadata.xml'),
                pkey_path)
        # from file
        server.setEncryptionPrivateKeyWithPassword(pkey_path)
        # from buffer
        server.setEncryptionPrivateKeyWithPassword(open(pkey_path).read())
        # reset
        server.setEncryptionPrivateKeyWithPassword()

    def test11(self):
        '''Test saving and reloading a Server using an encrypted private key'''
        pkey = os.path.join(dataDir, 'sp7-saml2', 'private-key.pem')
        mdata = os.path.join(dataDir, 'sp7-saml2', 'metadata.xml')
        password = file(os.path.join(dataDir, 'sp7-saml2', 'password')).read().strip()
        server = lasso.Server(mdata, pkey, password)
        assert isinstance(server, lasso.Server)
        server_dump = server.dump()
        assert server_dump
        server = lasso.Server.newFromDump(server_dump)
        assert isinstance(server, lasso.Server)

bindingSuite = unittest.makeSuite(BindingTestCase, 'test')

allTests = unittest.TestSuite((bindingSuite, ))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity = 2).run(allTests).wasSuccessful())

