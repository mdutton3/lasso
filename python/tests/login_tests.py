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
            "../../examples/data/idp-public-key.pem",
            "../../examples/data/idp-private-key.pem",
            "../../examples/data/idp-crt.pem",
            lasso.signatureMethodRsaSha1)
        serverContext.add_provider(
            "../../examples/data/sp-metadata.xml",
            "../../examples/data/sp-public-key.pem",
            "../../examples/data/ca-crt.pem")
        serverContextDump = serverContext.dump()
        serverContext.destroy()
        return serverContextDump

    def generateServiceProviderContextDump(self):
        serverContext = lasso.Server.new(
            "../../examples/data/sp-metadata.xml",
            "../../examples/data/sp-public-key.pem",
            "../../examples/data/sp-private-key.pem",
            "../../examples/data/sp-crt.pem",
            lasso.signatureMethodRsaSha1)
        serverContext.add_provider(
            "../../examples/data/idp-metadata.xml",
            "../../examples/data/idp-public-key.pem",
            "../../examples/data/ca-crt.pem")
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

    def test02_serviceProviderLogin(self):
        """Service provider initiated login"""

        # Service provider login using HTTP redirect.
        spContextDump = self.generateServiceProviderContextDump()
        self.failUnless(spContextDump)
        spContext = lasso.Server.new_from_dump(spContextDump)
        spLoginContext = lasso.Login.new(spContext)
        self.failUnlessEqual(spLoginContext.init_authn_request(
            "https://identity-provider:1998/liberty-alliance/metadata"), 0)
        spLoginContext.request.set_isPassive(False)
        spLoginContext.request.set_nameIDPolicy(lasso.libNameIDPolicyTypeFederated)
        spLoginContext.request.set_consent(lasso.libConsentObtained)
        relayState = "fake"
        spLoginContext.request.set_relayState(relayState)
        self.failUnlessEqual(spLoginContext.build_authn_request_msg(), 0)
        authnRequestUrl = spLoginContext.msg_url
        authnRequestQuery = authnRequestUrl.split("?", 1)[1]
        method = lasso.httpMethodRedirect

        # Identity provider singleSignOn, for a user having no federation.
        idpContextDump = self.generateIdentityProviderContextDump()
        self.failUnless(idpContextDump)
        idpContext = lasso.Server.new_from_dump(idpContextDump)
        idpLoginContext = lasso.Login.new(idpContext)
        self.failUnlessEqual(
            idpLoginContext.init_from_authn_request_msg(authnRequestQuery, method), 0)
        self.failUnless(idpLoginContext.must_authenticate())

        userAuthenticated = True
        authenticationMethod = lasso.samlAuthenticationMethodPassword
        self.failUnlessEqual(idpLoginContext.protocolProfile, lasso.loginProtocolProfileBrwsArt)
        self.failUnlessEqual(idpLoginContext.build_artifact_msg(
            userAuthenticated, authenticationMethod, "FIXME: reauthenticateOnOrAfter",
            lasso.httpMethodRedirect), 0)
        responseUrl = idpLoginContext.msg_url
        responseQuery = responseUrl.split("?", 1)[1]
        responseMsg = idpLoginContext.response_dump
        artifact = idpLoginContext.assertionArtifact
        nameIdentifier = idpLoginContext.nameIdentifier
        method = lasso.httpMethodRedirect

        # Service provider assertion consumer.
        spContextDump = self.generateServiceProviderContextDump()
        self.failUnless(spContextDump)
        spContext = lasso.Server.new_from_dump(spContextDump)
        spLoginContext = lasso.Login.new(spContext)
        self.failUnlessEqual(spLoginContext.init_request(responseQuery, method), 0)
        self.failUnlessEqual(spLoginContext.build_request_msg(), 0)
        soapEndpoint = spLoginContext.msg_url
        soapRequestMsg = spLoginContext.msg_body

##         soapResponseMsg = self.callSoap(loginContext.msg_url, loginContext.msg_body)
##         logs.debug("soapResponseMsg = %s" % soapResponseMsg)
##         errorCode = loginContext.process_response_msg(soapResponseMsg)
##         if errorCode:
##             raise Exception("Lasso login error %s" % errorCode)
##         nameIdentifier = loginContext.nameIdentifier


suite1 = unittest.makeSuite(LoginTestCase, 'test')

allTests = unittest.TestSuite((suite1,))

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(allTests)

