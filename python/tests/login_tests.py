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
        idpIdentityContext = idpLogoutContext.get_identity()
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
        spIdentityContextDump = spLogoutContext.get_identity().dump()
        self.failUnless(spIdentityContextDump)

    def test03(self):
        """Identity Provider single sign-on when identity and session already exist."""
        idpContextDump = self.generateIdentityProviderContextDump()
        self.failUnless(idpContextDump)
        idpContext = lasso.Server.new_from_dump(idpContextDump)
        idpLoginContext = lasso.Login.new(idpContext)
        idpIdentityContextDump = """\
<LassoIdentity><LassoFederations><LassoFederation RemoteProviderID="https://service-provider:2003/liberty-alliance/metadata"><LassoLocalNameIdentifier><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">NjMxMEMzRTlEMDA4NTNEMEZGNDI1MEM0QzY4NUNBNzY=</saml:NameIdentifier></LassoLocalNameIdentifier></LassoFederation></LassoFederations></LassoIdentity>
"""
        self.failUnlessEqual(idpLoginContext.set_identity_from_dump(idpIdentityContextDump), 0)
        idpSessionContextDump = """
<LassoSession><LassoAssertions><LassoAssertion RemoteProviderID="https://service-provider:2003/liberty-alliance/metadata"><lib:Assertion xmlns:lib="urn:liberty:iff:2003-08" AssertionID="Q0QxQzNFRTVGRTZEM0M0RjY2MTZDNTEwOUY4MDQzRTI=" MajorVersion="1" MinorVersion="2" IssueInstance="2004-08-02T18:51:43Z" Issuer="https://identity-provider:1998/liberty-alliance/metadata" InResponseTo="OEQ0OEUzODhGRTdGMEVFMzQ5Q0Q0QzYzQjk4MjUwNjQ="><lib:AuthenticationStatement xmlns:lib="urn:liberty:iff:2003-08" AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="2004-08-02T18:51:43Z" ReauthenticateOnOrAfter="FIXME: reauthenticateOnOrAfter"><lib:Subject xmlns:lib="urn:liberty:iff:2003-08"><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">NjMxMEMzRTlEMDA4NTNEMEZGNDI1MEM0QzY4NUNBNzY=</saml:NameIdentifier><lib:IDPProvidedNameIdentifier xmlns:lib="urn:liberty:iff:2003-08" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">NjMxMEMzRTlEMDA4NTNEMEZGNDI1MEM0QzY4NUNBNzY=</lib:IDPProvidedNameIdentifier><saml:SubjectConfirmation xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"><saml:SubjectConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:SubjectConfirmationMethod></saml:SubjectConfirmation></lib:Subject></lib:AuthenticationStatement><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference>
<Transforms>
<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>ZRe7eb5JuhgL6W/Le1oMezbEHnA=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>CYOtlOvHtpkQsLA87GrtHs1WuoPVXHiPkVsmce2X1+PUslYpKLKp3cuNTVo1Z7+k
Iku+DThYC9EvR7gprVQW2Y3CpCPanWs2A6j21SrlfqGFffpUtOFuiv3L1rfGKjPJ
eMWehfc/SEi3+/JT22RejeYrSA61YLwsfItB7Ie4L0TRuZuxxu++CsidIEu2iv7l
fI79SMn5hF7j/oFU9IODFhCArNLgBiOxA9rnRNvXwRFFmRN3qvdEuXuAZBthRhoa
BRcL2T7tLxIVV+8y1fUjkliV1QgvOeus9g1bib1FLHdzHZ6KNGLPkZiXuM7ZPT1B
G8WStJalTeH81AE7Ol4pcg==</SignatureValue>
<KeyInfo>
<X509Data>
<X509Certificate>MIIDKTCCAhECAQEwDQYJKoZIhvcNAQEEBQAwWzELMAkGA1UEBhMCSVQxDzANBgNV
BAcTBlBvbXBlaTEQMA4GA1UEChMHVmVzdXZpbzEpMCcGA1UEAxMgVmVzdXZpbyBM
aWJlcnR5IEFsbGlhbmNlIFJvb3QgQ0EwHhcNMDQwNDIwMTQwMzQ1WhcNMDUwNDIw
MTQwMzQ1WjBaMQswCQYDVQQGEwJJVDEPMA0GA1UEBxMGUG9tcGVpMR4wHAYDVQQK
ExVJZGVudGl0eSBQcm92aWRlciBJbmMxGjAYBgNVBAMTEWlkZW50aXR5LXByb3Zp
ZGVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4SGH3FPnhpQ8rCED
RmC+NEkJQ6ZrG1jRL1kNx3wNu1xRZgFPiEDFnu9p/muVQkRAzK4txgC5i0ymwgRZ
uan2yFrdq7Kpc9r0cM1S/q63aQeOMXQszz6G0NIY9DOzdrdlTc2uToBpIPA4a/Tf
NWpMFZ7zGB9ThJ4+S5MAIA6y3SRWYHOqdlwjo/R0P4C3y8wIClgI0ZTdS6/Rkr59
XC4WRocMzGCSsk+1F1tAZoR77ummLcY4nFkbtawyeRXEUpSpDaxgVEEmvH+/Kqx5
NhVzeCZkm8szOzMea+QT4Uh3F7GVwY/7+JV23eCGyr2n3EhXgCqw0nnGSGR7vrNl
Ue1oswIDAQABMA0GCSqGSIb3DQEBBAUAA4IBAQAFyYC/V49X7ZNLpYI8jx1TE9X3
J4c47cCLaxslrhi0/X6nCOEcBckXtbL+ZhIiHfI6PWizHMjTCEkJOYMVOsXyWN73
XdzfIZVrThQRsYvQZqUH8cZZH3fFg/RyEM3fzlFDsuIxfg7+NIDNmSFbt/YdFL0T
3sB7jYSkKr4buX9ZewdOfRxwN4MZIE32SoBo+UOgNrMM2hcQTStBK09vzJiWQE/4
aWbZJT9jtBPGWTsMS8g1x9WAmJHV2BpUiSfY39895a5T7kbbqZ3rp7DM9dgLjdXC
jFL7NhzvY02aBTLhm22YOLYnlycKm64NGne+siooDCi5tel2/vcx+e+btX9x</X509Certificate>
</X509Data>
</KeyInfo>
</Signature></lib:Assertion></LassoAssertion></LassoAssertions></LassoSession>
"""
        # " <-- Trick for Emacs Python mode.
        self.failUnlessEqual(idpLoginContext.set_session_from_dump(idpSessionContextDump), 0)
        authnRequestQuery = """NameIDPolicy=federated&IsPassive=false&ProviderID=https%3A%2F%2Fservice-provider%3A2003%2Fliberty-alliance%2Fmetadata&consent=urn%3Aliberty%3Aconsent%3Aobtained&IssueInstance=2004-08-02T20%3A33%3A58Z&MinorVersion=2&MajorVersion=1&RequestID=ODVGNkUyMzY5N0MzOTY4QzZGOUYyNzEwRTJGMUNCQTI%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=fnSL5Mgp%2BV%2FtdUuYQJmFKvFY8eEco6sypmejvP4sD0v5ApywV94mUo6BxE29o1KW%0AGFXiMG7puhTwRSlKDo1vlh5iHNqVfjKcbx2XhfoDfplqLir102dyHxB5GedEQvqw%0AbTFtFrB6SnHi5facrYHCn7b58CxAWv9XW4DIfcVCOSma2OOBCm%2FzzCSiZpOtbRk9%0AveQzace41tDW0XLlbRdWpvwsma0yaYSkqYvTV3hmvgkWS5x9lzcm97oME4ywzwbU%0AJAyG8BkqMFoG7FPjwzR8qh7%2FWi%2BCzxxqfczxSGkUZUmsQdxyxazjhDpt1X8i5fan%0AnaF1vWF3GmS6G4t7mrkItA%3D%3D"""
        method = lasso.httpMethodRedirect
        self.failUnlessEqual(
            idpLoginContext.init_from_authn_request_msg(authnRequestQuery, method), 0)
        self.failIf(idpLoginContext.must_authenticate())
        userAuthenticated = True
        authenticationMethod = lasso.samlAuthenticationMethodPassword
        self.failUnlessEqual(idpLoginContext.protocolProfile, lasso.loginProtocolProfileBrwsArt)
        idpLoginContext.build_artifact_msg(
            userAuthenticated, authenticationMethod, "FIXME: reauthenticateOnOrAfter",
            lasso.httpMethodRedirect)
        self.failUnless(idpLoginContext.msg_url)
        self.failUnless(idpLoginContext.assertionArtifact)
        self.failUnless(idpLoginContext.response_dump)
        self.failUnless(idpLoginContext.nameIdentifier)

    def test04(self):
        """Identity Provider logout."""
        idpContextDump = self.generateIdentityProviderContextDump()
        self.failUnless(idpContextDump)
        idpContext = lasso.Server.new_from_dump(idpContextDump)

        soapRequestMessage = """\
<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"><soap-env:Body xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"><lib:LogoutRequest xmlns:lib="urn:liberty:iff:2003-08" RequestID="RDIwMUYzM0Q1MzdFMjMzQzk0NTM4QUNEQUQ0MURBMEE=" MajorVersion="1" MinorVersion="2" IssueInstance="2004-08-03T11:56:15Z"><lib:ProviderID>https://service-provider:2003/liberty-alliance/metadata</lib:ProviderID><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">QkM3M0M4MTYxREQzNEYwNEI4M0I4MUVERDUyQUUyMjA=</saml:NameIdentifier><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference>
<Transforms>
<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>NlVszQnxIyPU7zbJYadQmTnFAsI=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>h0lB2hBstgxlNYnVQ4xzmXIi2APqNxKEEfUqYm3NeGmddbazg0/Y/SdcqLlto9fy
ML34w/TJG7DnCdeUQVxdxhzmJlv3X2U5qDAYh6gX4g36wJCntderC5LtNkZhhTWt
m9NWGszFhCm9nSaGATdj4JGqJNc+LUIt3EvXHDIqQ/LU2g3hxZQ4Hs5Fg9yqRS98
5CWPtckYcGPcG8kFuTKNos2F4KQPyXJRX0KF+9FbkBX0RsblstzL0CiFUlor4m+R
ejvMcEt/nGCGj7F5mRPYcW3ZxTw4J2wAqS52Tu41fyeKw5SHIJQNmwV25P/hINim
hd2ybn/G3vK2If0+rUjA8Q==</SignatureValue>
<KeyInfo>
<X509Data>
<X509Certificate>MIIDJzCCAg8CAQIwDQYJKoZIhvcNAQEEBQAwWzELMAkGA1UEBhMCSVQxDzANBgNV
BAcTBlBvbXBlaTEQMA4GA1UEChMHVmVzdXZpbzEpMCcGA1UEAxMgVmVzdXZpbyBM
aWJlcnR5IEFsbGlhbmNlIFJvb3QgQ0EwHhcNMDQwNDIwMTQyMDMxWhcNMDUwNDIw
MTQyMDMxWjBYMQswCQYDVQQGEwJJVDEPMA0GA1UEBxMGUG9tcGVpMR0wGwYDVQQK
ExRTZXJ2aWNlIFByb3ZpZGVyIEluYzEZMBcGA1UEAxMQc2VydmljZS1wcm92aWRl
cjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALIjOIroSVwUaMOyFlGL
p6oCDkI14ssZRec/l2Z+p89kwVF+vkyhE7LHkaIgE1RnmPhcudzMCNFc6okpHdtV
yU+GTSXhRN7/BGYBoDpfNpTMP0aUpw/BQOhL+zeb0nSsSf7ejNeKyvR+q5ia+3N4
dm9vgUPWZk0iN0URMSRxzIA3nEsR+B9JV7BFFyfbBxwLR4Aht667cuSeFnAUnynp
JiHiKF/r5yXk+EKK++8NpjflpJnFVT1mSfj+6iYutiOrgUKgCANsaXr0WomR4oKg
kqzP2DLDwnwi73vUAW4y9CBNk7nDtZJFhUxKa63i1HgHCKNvHfVjvKPz844PnLw/
CWMCAwEAATANBgkqhkiG9w0BAQQFAAOCAQEAOfAVexQY2ImgBWjcAkGAYfLwMZ2k
8jtQGRgbPuD1DBQ+oZm+Ykuw30orVAo8/S5PcSNdRawOVoTY60oRupGBctoqSzmp
SiBkWOwb4wBZOHfSNRFDS83N0ewHk4FFY6t5NPlhUORC07xl4GaVUb5LjyDKMh2j
RtLaR85lCV8xVvM+jdBzBM2FxOQ0WdhphMjO4gj5ene791iT4PpA69o7wuZ9g728
CGb/HRUx5EPgbIy52G224ITlQWadD1Z6y4PFTowDjkaRVerjUVRJZ/a5QVNsI4Du
/z71zAbdg4NfTfXjAXHRhEGappHVBROAQFchQ0oKhCTkICN4TUSuodgy/A==</X509Certificate>
</X509Data>
</KeyInfo>
</Signature></lib:LogoutRequest></soap-env:Body></soap-env:Envelope>
"""
        # " <-- Trick for Emacs Python mode.
        requestType = lasso.get_request_type_from_soap_msg(soapRequestMessage)
        self.failUnlessEqual(requestType, lasso.requestTypeLogout)
        idpLogoutContext = lasso.Logout.new(idpContext, lasso.providerTypeIdp)
        self.failUnless(idpLogoutContext)
        self.failUnlessEqual(
            idpLogoutContext.load_request_msg(soapRequestMessage, lasso.httpMethodSoap), 0)
        self.failUnless(idpLogoutContext.nameIdentifier)
        idpIdentityContextDump = """\
<LassoIdentity><LassoFederations><LassoFederation RemoteProviderID="https://service-provider:2003/liberty-alliance/metadata"><LassoLocalNameIdentifier><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">QkM3M0M4MTYxREQzNEYwNEI4M0I4MUVERDUyQUUyMjA=</saml:NameIdentifier></LassoLocalNameIdentifier></LassoFederation></LassoFederations></LassoIdentity>
"""
        self.failUnlessEqual(idpLogoutContext.set_identity_from_dump(idpIdentityContextDump), 0)
        idpSessionContextDump = """
<LassoSession><LassoAssertions><LassoAssertion RemoteProviderID="https://service-provider:2003/liberty-alliance/metadata"><lib:Assertion xmlns:lib="urn:liberty:iff:2003-08" AssertionID="QUVENUJCNzRFOUQ3MEZFNEYzNUUwQTA5OTRGMEYzMDg=" MajorVersion="1" MinorVersion="2" IssueInstance="2004-08-03T11:55:55Z" Issuer="https://identity-provider:1998/liberty-alliance/metadata" InResponseTo="N0VEQzE0QUE1NTYwQTAzRjk4Njk3Q0JCRUU0RUZCQkY="><lib:AuthenticationStatement xmlns:lib="urn:liberty:iff:2003-08" AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="2004-08-03T11:55:55Z" ReauthenticateOnOrAfter="FIXME: reauthenticateOnOrAfter"><lib:Subject xmlns:lib="urn:liberty:iff:2003-08"><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">QkM3M0M4MTYxREQzNEYwNEI4M0I4MUVERDUyQUUyMjA=</saml:NameIdentifier><lib:IDPProvidedNameIdentifier xmlns:lib="urn:liberty:iff:2003-08" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">QkM3M0M4MTYxREQzNEYwNEI4M0I4MUVERDUyQUUyMjA=</lib:IDPProvidedNameIdentifier><saml:SubjectConfirmation xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"><saml:SubjectConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:SubjectConfirmationMethod></saml:SubjectConfirmation></lib:Subject></lib:AuthenticationStatement><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference>
<Transforms>
<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>TqCKQTLsexix/tIqEabjBPcYby8=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>l96xDhc0/nevhvx79eyYvGknXDJMcykiomKOLMiL0FcxOglaKi/aNOGNA5VdT0mh
EdlAynOOVy9xXphy9kLyXXSMcYV5UMeqCIi0ro5cvMP1xBfEqBHAHaYQR+TXbGdn
bPCkIvGwzLDVr8bvwWnPjHqaXffswlfzjrDYq726Sx37s3UBgcViEVG0HTGe2X+f
Kx2iahOjVLvR9bBWOdsiKNisK3GtZPGFmxIXALg8oZnwJA4JKodzh+o1synKoLn3
2WigVh7r43LISSkCHx1C7qIK2zFz8YtPtaHa4xfMWT6QwZRngsXRcUcUibWZyoYt
950ly3lp1XkexL0uRXPvKw==</SignatureValue>
<KeyInfo>
<X509Data>
<X509Certificate>MIIDKTCCAhECAQEwDQYJKoZIhvcNAQEEBQAwWzELMAkGA1UEBhMCSVQxDzANBgNV
BAcTBlBvbXBlaTEQMA4GA1UEChMHVmVzdXZpbzEpMCcGA1UEAxMgVmVzdXZpbyBM
aWJlcnR5IEFsbGlhbmNlIFJvb3QgQ0EwHhcNMDQwNDIwMTQwMzQ1WhcNMDUwNDIw
MTQwMzQ1WjBaMQswCQYDVQQGEwJJVDEPMA0GA1UEBxMGUG9tcGVpMR4wHAYDVQQK
ExVJZGVudGl0eSBQcm92aWRlciBJbmMxGjAYBgNVBAMTEWlkZW50aXR5LXByb3Zp
ZGVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4SGH3FPnhpQ8rCED
RmC+NEkJQ6ZrG1jRL1kNx3wNu1xRZgFPiEDFnu9p/muVQkRAzK4txgC5i0ymwgRZ
uan2yFrdq7Kpc9r0cM1S/q63aQeOMXQszz6G0NIY9DOzdrdlTc2uToBpIPA4a/Tf
NWpMFZ7zGB9ThJ4+S5MAIA6y3SRWYHOqdlwjo/R0P4C3y8wIClgI0ZTdS6/Rkr59
XC4WRocMzGCSsk+1F1tAZoR77ummLcY4nFkbtawyeRXEUpSpDaxgVEEmvH+/Kqx5
NhVzeCZkm8szOzMea+QT4Uh3F7GVwY/7+JV23eCGyr2n3EhXgCqw0nnGSGR7vrNl
Ue1oswIDAQABMA0GCSqGSIb3DQEBBAUAA4IBAQAFyYC/V49X7ZNLpYI8jx1TE9X3
J4c47cCLaxslrhi0/X6nCOEcBckXtbL+ZhIiHfI6PWizHMjTCEkJOYMVOsXyWN73
XdzfIZVrThQRsYvQZqUH8cZZH3fFg/RyEM3fzlFDsuIxfg7+NIDNmSFbt/YdFL0T
3sB7jYSkKr4buX9ZewdOfRxwN4MZIE32SoBo+UOgNrMM2hcQTStBK09vzJiWQE/4
aWbZJT9jtBPGWTsMS8g1x9WAmJHV2BpUiSfY39895a5T7kbbqZ3rp7DM9dgLjdXC
jFL7NhzvY02aBTLhm22YOLYnlycKm64NGne+siooDCi5tel2/vcx+e+btX9x</X509Certificate>
</X509Data>
</KeyInfo>
</Signature></lib:Assertion></LassoAssertion></LassoAssertions></LassoSession>
"""
        # " <-- Trick for Emacs Python mode.
        self.failUnlessEqual(idpLogoutContext.set_session_from_dump(idpSessionContextDump), 0)

        self.failIf(idpLogoutContext.is_identity_dirty())
        self.failUnless(idpLogoutContext.is_session_dirty())
        idpSessionContextDump = idpLogoutContext.get_session().dump()
        self.failUnless(idpSessionContextDump)
        self.failIf(idpLogoutContext.get_next_providerID())
        self.failUnlessEqual(idpLogoutContext.build_response_msg(), 0)
        soapResponseMsg = idpLogoutContext.msg_body
        self.failUnless(soapResponseMsg)


suite1 = unittest.makeSuite(LoginTestCase, 'test')

allTests = unittest.TestSuite((suite1,))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity=2).run(allTests).wasSuccessful())

