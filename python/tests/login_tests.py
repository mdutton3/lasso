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
    def generateIdentityProviderDump(self):
        server = lasso.Server.new(
            "../../examples/data/idp-metadata.xml",
            "../../examples/data/idp-public-key.pem",
            "../../examples/data/idp-private-key.pem",
            "../../examples/data/idp-crt.pem",
            lasso.signatureMethodRsaSha1)
        server.add_provider(
            "../../examples/data/sp-metadata.xml",
            "../../examples/data/sp-public-key.pem",
            "../../examples/data/ca-crt.pem")
        serverDump = server.dump()
        server.destroy()
        return serverDump

    def generateServiceProviderDump(self):
        server = lasso.Server.new(
            "../../examples/data/sp-metadata.xml",
            "../../examples/data/sp-public-key.pem",
            "../../examples/data/sp-private-key.pem",
            "../../examples/data/sp-crt.pem",
            lasso.signatureMethodRsaSha1)
        server.add_provider(
            "../../examples/data/idp-metadata.xml",
            "../../examples/data/idp-public-key.pem",
            "../../examples/data/ca-crt.pem")
        serverDump = server.dump()
        server.destroy()
        return serverDump

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test01_generateServersDumps(self):
        """Generate identity and service provider dumps"""
        identityProviderDump = self.generateIdentityProviderDump()
        self.failUnless(identityProviderDump)
        serviceProviderDump = self.generateServiceProviderDump()
        self.failUnless(serviceProviderDump)

    def test02_serviceProviderLogin(self):
        """Service provider initiated login"""

        # Service provider login using HTTP redirect.
        spDump = self.generateServiceProviderDump()
        self.failUnless(spDump)
        sp = lasso.Server.new_from_dump(spDump)
        spLogin = lasso.Login.new(sp)
        self.failUnlessEqual(spLogin.init_authn_request(
            "https://identity-provider:1998/liberty-alliance/metadata"), 0)
        self.failUnlessEqual(spLogin.request_type, lasso.messageTypeAuthnRequest)
        spLogin.request.set_isPassive(False)
        spLogin.request.set_nameIDPolicy(lasso.libNameIDPolicyTypeFederated)
        spLogin.request.set_consent(lasso.libConsentObtained)
        relayState = "fake"
        spLogin.request.set_relayState(relayState)
        self.failUnlessEqual(spLogin.build_authn_request_msg(), 0)
        authnRequestUrl = spLogin.msg_url
        authnRequestQuery = authnRequestUrl.split("?", 1)[1]
        method = lasso.httpMethodRedirect

        # Identity provider singleSignOn, for a user having no federation.
        idpDump = self.generateIdentityProviderDump()
        self.failUnless(idpDump)
        idp = lasso.Server.new_from_dump(idpDump)
        idpLogin = lasso.Login.new(idp)
        self.failUnlessEqual(
            idpLogin.init_from_authn_request_msg(authnRequestQuery, method), 0)
        self.failUnless(idpLogin.must_authenticate())

        userAuthenticated = True
        authenticationMethod = lasso.samlAuthenticationMethodPassword
        self.failUnlessEqual(idpLogin.protocolProfile, lasso.loginProtocolProfileBrwsArt)
        self.failUnlessEqual(idpLogin.build_artifact_msg(
            userAuthenticated, authenticationMethod, "FIXME: reauthenticateOnOrAfter",
            lasso.httpMethodRedirect), 0)
        idpIdentityDump = idpLogin.get_identity().dump()
        self.failUnless(idpIdentityDump)
        idpSessionDump = idpLogin.get_session().dump()
        self.failUnless(idpSessionDump)
        responseUrl = idpLogin.msg_url
        responseQuery = responseUrl.split("?", 1)[1]
        soapResponseMsg = idpLogin.response_dump
        artifact = idpLogin.assertionArtifact
        nameIdentifier = idpLogin.nameIdentifier
        method = lasso.httpMethodRedirect

        # Service provider assertion consumer.
        spDump = self.generateServiceProviderDump()
        self.failUnless(spDump)
        sp = lasso.Server.new_from_dump(spDump)
        spLogin = lasso.Login.new(sp)
        self.failUnlessEqual(spLogin.init_request(responseQuery, method), 0)
        self.failUnlessEqual(spLogin.build_request_msg(), 0)
        soapEndpoint = spLogin.msg_url
        soapRequestMsg = spLogin.msg_body

        # Identity provider SOAP endpoint.
        requestType = lasso.get_request_type_from_soap_msg(soapRequestMsg)
        self.failUnlessEqual(requestType, lasso.requestTypeLogin)

        # Service provider assertion consumer (step 2: process SOAP response).
        self.failUnlessEqual(spLogin.process_response_msg(soapResponseMsg), 0)
        self.failUnlessEqual(spLogin.nameIdentifier, nameIdentifier)
        # The user doesn't have any federation yet.
        self.failUnlessEqual(spLogin.accept_sso(), 0)
        spIdentity = spLogin.get_identity()
        self.failUnless(spIdentity)
        spIdentityDump = spIdentity.dump()
        self.failUnless(spIdentityDump)
        spSession = spLogin.get_session()
        self.failUnless(spSession)
        spSessionDump = spSession.dump()
        self.failUnless(spSessionDump)
        authenticationMethod = spSession.get_authentication_method()
        self.failUnlessEqual(authenticationMethod, lasso.samlAuthenticationMethodPassword)

        # Service provider logout.
        spDump = self.generateServiceProviderDump()
        self.failUnless(spDump)
        sp = lasso.Server.new_from_dump(spDump)
        self.failUnless(sp)
        spLogout = lasso.Logout.new(sp, lasso.providerTypeSp)
        self.failUnless(spIdentityDump)
        spLogout.set_identity_from_dump(spIdentityDump)
        self.failUnless(spSessionDump)
        spLogout.set_session_from_dump(spSessionDump)
        self.failUnlessEqual(spLogout.init_request(), 0)
        self.failUnlessEqual(spLogout.build_request_msg(), 0)
        soapEndpoint = spLogout.msg_url
        soapRequestMsg = spLogout.msg_body

        # Identity provider SOAP endpoint.
        requestType = lasso.get_request_type_from_soap_msg(soapRequestMsg)
        self.failUnlessEqual(requestType, lasso.requestTypeLogout)
        idpDump = self.generateIdentityProviderDump()
        self.failUnless(idpDump)
        idp = lasso.Server.new_from_dump(idpDump)
        self.failUnless(idp)
        idpLogout = lasso.Logout.new(idp, lasso.providerTypeIdp)
        self.failUnlessEqual(
            idpLogout.process_request_msg(soapRequestMsg, lasso.httpMethodSoap), 0)
        self.failUnlessEqual(idpLogout.nameIdentifier, nameIdentifier)
        self.failUnless(idpIdentityDump)
        self.failUnlessEqual(idpLogout.set_identity_from_dump(idpIdentityDump), 0)
        self.failUnless(idpSessionDump)
        self.failUnlessEqual(idpLogout.set_session_from_dump(idpSessionDump), 0)
        self.failUnlessEqual(idpLogout.validate_request(), 0)
        idpIdentity = idpLogout.get_identity()
        self.failUnless(idpIdentity)
        idpIdentityDump = idpIdentity.dump()
        self.failUnless(idpIdentityDump)
        # There is no other service provider from which the user must be logged out.
        self.failUnlessEqual(idpLogout.get_next_providerID(), None)
        self.failUnlessEqual(idpLogout.build_response_msg(), 0)
        soapResponseMsg = idpLogout.msg_body

        # Service provider logout (step 2: process SOAP response).
        self.failUnlessEqual(
            spLogout.process_response_msg(soapResponseMsg, lasso.httpMethodSoap), 0)
        spIdentityDump = spLogout.get_identity().dump()
        self.failUnless(spIdentityDump)

    def test03(self):
        """Identity provider single sign-on when identity and session already exist."""
        idpDump = self.generateIdentityProviderDump()
        self.failUnless(idpDump)
        idp = lasso.Server.new_from_dump(idpDump)
        idpLogin = lasso.Login.new(idp)
        idpIdentityDump = """\
<LassoIdentity><LassoFederations><LassoFederation RemoteProviderID="https://service-provider:2003/liberty-alliance/metadata"><LassoLocalNameIdentifier><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">NjMxMEMzRTlEMDA4NTNEMEZGNDI1MEM0QzY4NUNBNzY=</saml:NameIdentifier></LassoLocalNameIdentifier></LassoFederation></LassoFederations></LassoIdentity>
""".strip()
        self.failUnlessEqual(idpLogin.set_identity_from_dump(idpIdentityDump), 0)
        idpSessionDump = """
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
""".strip()
        # " <-- Trick for Emacs Python mode.
        self.failUnlessEqual(idpLogin.set_session_from_dump(idpSessionDump), 0)
        authnRequestQuery = """NameIDPolicy=federated&IsPassive=false&ProviderID=https%3A%2F%2Fservice-provider%3A2003%2Fliberty-alliance%2Fmetadata&consent=urn%3Aliberty%3Aconsent%3Aobtained&IssueInstance=2004-08-02T20%3A33%3A58Z&MinorVersion=2&MajorVersion=1&RequestID=ODVGNkUyMzY5N0MzOTY4QzZGOUYyNzEwRTJGMUNCQTI%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=fnSL5Mgp%2BV%2FtdUuYQJmFKvFY8eEco6sypmejvP4sD0v5ApywV94mUo6BxE29o1KW%0AGFXiMG7puhTwRSlKDo1vlh5iHNqVfjKcbx2XhfoDfplqLir102dyHxB5GedEQvqw%0AbTFtFrB6SnHi5facrYHCn7b58CxAWv9XW4DIfcVCOSma2OOBCm%2FzzCSiZpOtbRk9%0AveQzace41tDW0XLlbRdWpvwsma0yaYSkqYvTV3hmvgkWS5x9lzcm97oME4ywzwbU%0AJAyG8BkqMFoG7FPjwzR8qh7%2FWi%2BCzxxqfczxSGkUZUmsQdxyxazjhDpt1X8i5fan%0AnaF1vWF3GmS6G4t7mrkItA%3D%3D"""
        method = lasso.httpMethodRedirect
        self.failUnlessEqual(
            idpLogin.init_from_authn_request_msg(authnRequestQuery, method), 0)
        self.failIf(idpLogin.must_authenticate())
        userAuthenticated = True
        authenticationMethod = lasso.samlAuthenticationMethodPassword
        self.failUnlessEqual(idpLogin.protocolProfile, lasso.loginProtocolProfileBrwsArt)
        idpLogin.build_artifact_msg(
            userAuthenticated, authenticationMethod, "FIXME: reauthenticateOnOrAfter",
            lasso.httpMethodRedirect)
        self.failUnless(idpLogin.msg_url)
        self.failUnless(idpLogin.assertionArtifact)
        self.failUnless(idpLogin.response_dump)
        self.failUnless(idpLogin.nameIdentifier)

    def test04(self):
        """Identity provider logout."""
        idpDump = self.generateIdentityProviderDump()
        self.failUnless(idpDump)
        idp = lasso.Server.new_from_dump(idpDump)

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
""".strip()
        # " <-- Trick for Emacs Python mode.
        requestType = lasso.get_request_type_from_soap_msg(soapRequestMessage)
        self.failUnlessEqual(requestType, lasso.requestTypeLogout)
        idpLogout = lasso.Logout.new(idp, lasso.providerTypeIdp)
        self.failUnless(idpLogout)
        self.failUnlessEqual(
            idpLogout.process_request_msg(soapRequestMessage, lasso.httpMethodSoap), 0)
        self.failUnless(idpLogout.nameIdentifier)
        idpIdentityDump = """\
<LassoIdentity><LassoFederations><LassoFederation RemoteProviderID="https://service-provider:2003/liberty-alliance/metadata"><LassoLocalNameIdentifier><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">QkM3M0M4MTYxREQzNEYwNEI4M0I4MUVERDUyQUUyMjA=</saml:NameIdentifier></LassoLocalNameIdentifier></LassoFederation></LassoFederations></LassoIdentity>
""".strip()
        self.failUnlessEqual(idpLogout.set_identity_from_dump(idpIdentityDump), 0)
        self.failUnlessEqual(idpLogout.get_identity().dump(), idpIdentityDump)
        idpSessionDump = """
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
""".strip()
        # " <-- Trick for Emacs Python mode.
        self.failUnlessEqual(idpLogout.set_session_from_dump(idpSessionDump), 0)
        self.failUnlessEqual(idpLogout.get_session().dump(), idpSessionDump)
        self.failUnlessEqual(idpLogout.validate_request(), 0)
        self.failIf(idpLogout.is_identity_dirty())
        self.failUnless(idpLogout.is_session_dirty())
        idpSessionDump = idpLogout.get_session().dump()
        self.failUnless(idpSessionDump)
        self.failIf(idpLogout.get_next_providerID())
        self.failUnlessEqual(idpLogout.build_response_msg(), 0)
        soapResponseMsg = idpLogout.msg_body
        self.failUnless(soapResponseMsg)

    def test05(self):
        """Service provider logout."""
        spDump = self.generateServiceProviderDump()
        self.failUnless(spDump)
        sp = lasso.Server.new_from_dump(spDump)

        spLogout = lasso.Logout.new(sp, lasso.providerTypeSp)

        spIdentityDump = """\
<LassoIdentity><LassoFederations><LassoFederation RemoteProviderID="https://identity-provider:1998/liberty-alliance/metadata"><LassoRemoteNameIdentifier><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">RTE5REZDN0UyMEJEQzA0MDQxRjM3NThCQkFCNERCODQ=</saml:NameIdentifier></LassoRemoteNameIdentifier><LassoLocalNameIdentifier><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">RTE5REZDN0UyMEJEQzA0MDQxRjM3NThCQkFCNERCODQ=</saml:NameIdentifier></LassoLocalNameIdentifier></LassoFederation></LassoFederations></LassoIdentity>
""".strip()
        spLogout.set_identity_from_dump(spIdentityDump)

        spSessionDump = """\
<LassoSession><LassoAssertions><LassoAssertion RemoteProviderID="https://identity-provider:1998/liberty-alliance/metadata"><lib:Assertion xmlns:lib="urn:liberty:iff:2003-08" AssertionID="QzQ3NkVCMEIzNTY0RDNBOUVEQkNDN0RCQjA1MjlFRTA=" MajorVersion="1" MinorVersion="2" IssueInstance="2004-08-04T00:03:08Z" Issuer="https://identity-provider:1998/liberty-alliance/metadata" InResponseTo="M0M3Q0RBREE4QjQ1OTAwOTk2QTlFN0RFRUU0NTNGNUM="><lib:AuthenticationStatement xmlns:lib="urn:liberty:iff:2003-08" AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="2004-08-04T00:03:08Z" ReauthenticateOnOrAfter="FIXME: reauthenticateOnOrAfter"><lib:Subject xmlns:lib="urn:liberty:iff:2003-08"><saml:NameIdentifier xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">RTE5REZDN0UyMEJEQzA0MDQxRjM3NThCQkFCNERCODQ=</saml:NameIdentifier><lib:IDPProvidedNameIdentifier xmlns:lib="urn:liberty:iff:2003-08" NameQualifier="https://identity-provider:1998/liberty-alliance/metadata" Format="urn:liberty:iff:nameid:federated">RTE5REZDN0UyMEJEQzA0MDQxRjM3NThCQkFCNERCODQ=</lib:IDPProvidedNameIdentifier><saml:SubjectConfirmation xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"><saml:SubjectConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:SubjectConfirmationMethod></saml:SubjectConfirmation></lib:Subject></lib:AuthenticationStatement><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<Reference>
<Transforms>
<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
</Transforms>
<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<DigestValue>8BSywvR2YB/euz8CCEhElQRSiZA=</DigestValue>
</Reference>
</SignedInfo>
<SignatureValue>Vg0BM0Z15mFsRxEOhy9oCfXuK/NgQPrgJc2Kf3tE9g/uTnNFGq0YNB5KSlonJLUr
0cZ8D18XlTJrZp22vPCUO44hvL5DDWGTctqJbl+TV3D8qzFlfe8XOPBy3cUSXcYo
E4qR44SnA9iZeRH0t4c3+8lY+BeXoqcglBrpE86B5Ftfb7wvLY0m8fdzPSJneSqq
Z41uh4Wtegq4bqIkUev0nrY1wKHJjkfpKNmcirGTNm0gm8c/Ki9UCgI9g4cknj+F
/UR8LQH/H8u2YSp3w5wiWfcmEfjfoVqa8YoiwWAoRgkKRVwER6iXYdqJ9vF0GFN/
Bm7OmEnDwF3bc/fruca4Pg==</SignatureValue>
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
""".strip()
        # " <-- Trick for Emacs Python mode.
        spLogout.set_session_from_dump(spSessionDump)

        self.failUnlessEqual(spLogout.init_request(), 0)
        self.failUnlessEqual(spLogout.build_request_msg(), 0)
        self.failUnless(spLogout.msg_url)
        self.failUnless(spLogout.msg_body)
        self.failUnless(spLogout.nameIdentifier)

        soapResponseMessage = """\
<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"><soap-env:Body xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"><lib:LogoutResponse xmlns:lib="urn:liberty:iff:2003-08" ResponseID="NjcyNDYxQ0FCRTQwMUE0NjE4MzlFQjFDOTI2MTc3NjE=" MajorVersion="1" MinorVersion="2" IssueInstance="2004-08-04T00:03:20Z" InResponseTo="MzNCOTRBMjRCMDExN0MxODc1MUI5NjMwQjlCMTg1NzM=" Recipient="https://service-provider:2003/liberty-alliance/metadata"><lib:ProviderID>https://identity-provider:1998/liberty-alliance/metadata</lib:ProviderID><samlp:Status xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"><samlp:StatusCode xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" Value="Samlp:Success"/></samlp:Status></lib:LogoutResponse></soap-env:Body></soap-env:Envelope>
""".strip()
        self.failUnlessEqual(
            spLogout.process_response_msg(soapResponseMessage, lasso.httpMethodSoap), 0)
        self.failIf(spLogout.is_identity_dirty())
        self.failUnless(spLogout.is_session_dirty())
        spSessionDump = spLogout.get_session().dump()
        # self.failIf(spSessionDump)


suite1 = unittest.makeSuite(LoginTestCase, 'test')

allTests = unittest.TestSuite((suite1,))

if __name__ == '__main__':
    sys.exit(not unittest.TextTestRunner(verbosity=2).run(allTests).wasSuccessful())

