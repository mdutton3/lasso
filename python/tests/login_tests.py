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
import sys

sys.path.insert(0, '..')
sys.path.insert(0, '../.libs')


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
        """Generate identity and service provider context dumps"""
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
        self.failUnlessEqual(spLoginContext.request_type, lasso.messageTypeAuthnRequest)
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
        idpIdentityContextDump = idpLoginContext.get_identity().dump()
        self.failUnless(idpIdentityContextDump)
        idpSessionContextDump = idpLoginContext.get_session().dump()
        self.failUnless(idpSessionContextDump)
        responseUrl = idpLoginContext.msg_url
        responseQuery = responseUrl.split("?", 1)[1]
        soapResponseMsg = idpLoginContext.response_dump
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

        # Identity provider SOAP endpoint.
        requestType = lasso.get_request_type_from_soap_msg(soapRequestMsg)
        self.failUnlessEqual(requestType, lasso.requestTypeLogin)

        # Service provider assertion consumer (step 2: process SOAP response).
        self.failUnlessEqual(spLoginContext.process_response_msg(soapResponseMsg), 0)
        self.failUnlessEqual(spLoginContext.nameIdentifier, nameIdentifier)
        # The user doesn't have any federation yet.
        self.failUnlessEqual(spLoginContext.accept_sso(), 0)
        spIdentityContext = spLoginContext.get_identity()
        self.failUnless(spIdentityContext)
        spIdentityContextDump = spIdentityContext.dump()
        self.failUnless(spIdentityContextDump)
        spSessionContext = spLoginContext.get_session()
        self.failUnless(spSessionContext)
        spSessionContextDump = spSessionContext.dump()
        self.failUnless(spSessionContextDump)
        authenticationMethod = spSessionContext.get_authentication_method()
        self.failUnlessEqual(authenticationMethod, lasso.samlAuthenticationMethodPassword)

        # Service provider logout.
        spContextDump = self.generateServiceProviderContextDump()
        self.failUnless(spContextDump)
        spContext = lasso.Server.new_from_dump(spContextDump)
        self.failUnless(spContext)
        spLogoutContext = lasso.Logout.new(spContext, lasso.providerTypeSp)
        self.failUnless(spIdentityContextDump)
        spLogoutContext.set_identity_from_dump(spIdentityContextDump)
        self.failUnless(spSessionContextDump)
        spLogoutContext.set_session_from_dump(spSessionContextDump)
        self.failUnlessEqual(spLogoutContext.init_request(), 0)
        self.failUnlessEqual(spLogoutContext.build_request_msg(), 0)
        soapEndpoint = spLogoutContext.msg_url
        soapRequestMsg = spLogoutContext.msg_body

        # Identity provider SOAP endpoint.
        requestType = lasso.get_request_type_from_soap_msg(soapRequestMsg)
        self.failUnlessEqual(requestType, lasso.requestTypeLogout)
        idpContextDump = self.generateIdentityProviderContextDump()
        self.failUnless(idpContextDump)
        idpContext = lasso.Server.new_from_dump(idpContextDump)
        self.failUnless(idpContext)
        idpLogoutContext = lasso.Logout.new(idpContext, lasso.providerTypeIdp)
        self.failUnlessEqual(
            idpLogoutContext.load_request_msg(soapRequestMsg, lasso.httpMethodSoap), 0)
        self.failUnlessEqual(idpLogoutContext.nameIdentifier, nameIdentifier)
        self.failUnless(idpIdentityContextDump)
        self.failUnlessEqual(idpLogoutContext.set_identity_from_dump(idpIdentityContextDump), 0)
        self.failUnless(idpSessionContextDump)
        self.failUnlessEqual(idpLogoutContext.set_session_from_dump(idpSessionContextDump), 0)
        self.failUnlessEqual(idpLogoutContext.process_request(), 0)
        idpIdentityContext = idpLogoutContext.identity
        self.failUnless(idpIdentityContext)
        idpIdentityContextDump = idpIdentityContext.dump()
        self.failUnless(idpIdentityContextDump)
        # There is no other service provider from which the user must be logged out.
        self.failUnlessEqual(idpLogoutContext.get_next_providerID(), None)
        self.failUnlessEqual(idpLogoutContext.build_response_msg(), 0)
        soapResponseMsg = idpLogoutContext.msg_body

        # Service provider logout (step 2: process SOAP response).
        self.failUnlessEqual(
            spLogoutContext.process_response_msg(soapResponseMsg, lasso.httpMethodSoap), 0)
        spIdentityContextDump = spLogoutContext.identity.dump()
        self.failUnless(spIdentityContextDump)


suite1 = unittest.makeSuite(LoginTestCase, 'test')

allTests = unittest.TestSuite((suite1,))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity=2).run(allTests).wasSuccessful())

