/*
 * $Id: LoginTest.java 3307 2007-06-13 13:17:51Z dlaniel $
 *
 * Java unit tests for Lasso library
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: See AUTHORS file in top-level directory.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

// To run it:
// $ export LD_LIBRARY_PATH=../
// $ javac -classpath /usr/share/java/junit.jar:../lasso.jar:. LoginTest.java
// $ java -classpath /usr/share/java/junit.jar:../lasso.jar:. LoginTest
// or for gcj:
// $ export LD_LIBRARY_PATH=../
// $ gcj -C -classpath /usr/share/java/junit.jar:../lasso.jar:. LoginTest.java
// $ gij -classpath /usr/share/java/junit.jar:../lasso.jar:. LoginTest


import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import com.entrouvert.lasso.*;
import java.util.*;

public class LoginTest extends TestCase {
    public String generateIdentityProviderDump() {
        String srcdir = System.getProperty("srcdir") + "/";
        Server server = new Server(
            srcdir + "../../tests/data/idp1-la/metadata.xml",
            srcdir + "../../tests/data/idp1-la/private-key-raw.pem",
            null,
            srcdir + "../../tests/data/idp1-la/certificate.pem");
        server.addProvider(
            LassoConstants.PROVIDER_ROLE_SP,
            srcdir + "../../tests/data/sp1-la/metadata.xml",
            srcdir + "../../tests/data/sp1-la/public-key.pem",
            srcdir + "../../tests/data/ca1-la/certificate.pem");
        String serverDump = server.dump();
        return serverDump;
    }

    public String generateServiceProviderDump() {
        String srcdir = System.getProperty("srcdir") + "/";
        Server server = new Server(
            srcdir + "../../tests/data/sp1-la/metadata.xml",
            srcdir + "../../tests/data/sp1-la/private-key-raw.pem",
            null,
            srcdir + "../../tests/data/sp1-la/certificate.pem");
        server.addProvider(
            LassoConstants.PROVIDER_ROLE_IDP,
            srcdir + "../../tests/data/idp1-la/metadata.xml",
            srcdir + "../../tests/data/idp1-la/public-key.pem",
            srcdir + "../../tests/data/ca1-la/certificate.pem");
        String serverDump = server.dump();
        return serverDump;
    }

    public void test01_generateServersDumps() {
        String identityProviderDump = generateIdentityProviderDump();
        assertNotNull(identityProviderDump);
        String serviceProviderDump = generateServiceProviderDump();
        assertNotNull(serviceProviderDump);
    }

    public void test02_serviceProviderLogin() {
        boolean userAuthenticated, userConsentObtained;
        int method, requestType;
        LibAuthnRequest authnRequest;
        Identity idpIdentity, spIdentity;
        Login idpLogin, spLogin;
        Logout idpLogout, spLogout;
        SamlAssertion assertion;
        Server idp, sp;
        Session spSession;
        String artifact, authenticationMethod, authnRequestQuery, authnRequestUrl, idpDump,
            idpIdentityDump, idpRemoteProviderId, idpSessionDump, nameIdentifier, relayState,
            responseQuery, responseUrl, soapEndpoint, soapResponseMsg, soapRequestMsg,
            spDump, spIdentityDump, spSessionDump;

        // Service provider login using HTTP redirect.
        spDump = generateServiceProviderDump();
        assertNotNull(spDump);
        sp = Server.newFromDump(spDump);
        spLogin = new Login(sp);
        spLogin.initAuthnRequest("https://idp1/metadata", LassoConstants.HTTP_METHOD_REDIRECT);
        authnRequest = (LibAuthnRequest) spLogin.getRequest();
        authnRequest.setIsPassive(false);
        authnRequest.setNameIdPolicy(LassoConstants.LIB_NAMEID_POLICY_TYPE_FEDERATED);
        authnRequest.setConsent(LassoConstants.LIB_CONSENT_OBTAINED);
        relayState = "fake";
        authnRequest.setRelayState(relayState);
        spLogin.buildAuthnRequestMsg();
        authnRequestUrl = spLogin.getMsgUrl();
        authnRequestQuery = authnRequestUrl.substring(authnRequestUrl.indexOf("?") + 1);

        // Identity provider singleSignOn, for a user having no federation.
        idpDump = generateIdentityProviderDump();
        assertNotNull(idpDump);
        idp = Server.newFromDump(idpDump);
        idpLogin = new Login(idp);
        idpLogin.processAuthnRequestMsg(authnRequestQuery);
        assertTrue(idpLogin.mustAuthenticate());
        assertFalse(idpLogin.mustAskForConsent());

        userAuthenticated = true;
        userConsentObtained = false;
        idpLogin.validateRequestMsg(userAuthenticated, userConsentObtained);
        authenticationMethod = LassoConstants.SAML_AUTHENTICATION_METHOD_PASSWORD;
        idpLogin.buildAssertion(
                authenticationMethod,
                null, // authenticationInstant
                null, // reauthenticateOnOrAfter
                null, // notBefore
                null);// notOnOrAfter
        assertEquals(LassoConstants.LOGIN_PROTOCOL_PROFILE_BRWS_ART, idpLogin.getProtocolProfile());
        idpLogin.buildArtifactMsg(LassoConstants.HTTP_METHOD_REDIRECT);
        idpIdentityDump = idpLogin.getIdentity().dump();
        assertNotNull(idpIdentityDump);
        idpSessionDump = idpLogin.getSession().dump();
        assertNotNull(idpSessionDump);
        responseUrl = idpLogin.getMsgUrl();
        responseQuery = responseUrl.substring(responseUrl.indexOf("?") + 1);
        idpRemoteProviderId = idpLogin.getRemoteProviderId();
        nameIdentifier = ((SamlNameIdentifier)idpLogin.getNameIdentifier()).getContent();
        artifact = idpLogin.getAssertionArtifact();
        assertNotNull(artifact);
        method = LassoConstants.HTTP_METHOD_REDIRECT;

        // Service provider assertion consumer.
        spDump = generateServiceProviderDump();
        assertNotNull(spDump);
        sp = Server.newFromDump(spDump);
        soapEndpoint = spLogin.getMsgUrl();
        spLogin = new Login(sp);
        spLogin.initRequest(responseQuery, method);
        spLogin.buildRequestMsg();
        soapEndpoint = spLogin.getMsgUrl();
        assertNotNull(soapEndpoint);
        soapRequestMsg = spLogin.getMsgBody();
        assertNotNull(soapRequestMsg);

        // Identity provider SOAP endpoint.
        requestType = LassoJNI.lasso_get_request_type_from_soap_msg(soapRequestMsg);
        assertEquals(LassoConstants.REQUEST_TYPE_LOGIN, requestType);
        idpDump = generateIdentityProviderDump();
        assertNotNull(idpDump);
        idp = Server.newFromDump(idpDump);
        idpLogin = new Login(idp);
        idpLogin.processRequestMsg(soapRequestMsg);
        assertEquals(artifact, idpLogin.getAssertionArtifact());
        assertNotNull(idpSessionDump);
        idpLogin.setSessionFromDump(idpSessionDump);
        idpLogin.buildResponseMsg(idpRemoteProviderId);
        soapResponseMsg = idpLogin.getMsgBody();
        assertNotNull(soapResponseMsg);

        // Service provider assertion consumer (step 2: process SOAP response).
        spLogin.processResponseMsg(soapResponseMsg);
        assertEquals(nameIdentifier, ((SamlNameIdentifier)spLogin.getNameIdentifier()).getContent());
        // The user doesn't have any federation yet.
        spLogin.acceptSso();
        spIdentity = spLogin.getIdentity();
        assertNotNull(spIdentity);
        spIdentityDump = spIdentity.dump();
        assertNotNull(spIdentityDump);
        spSession = spLogin.getSession();
        assertNotNull(spSession);
        spSessionDump = spSession.dump();
        assertNotNull(spSessionDump);
        assertion = (SamlAssertion) spSession.getAssertions("https://idp1/metadata").get(0);
        authenticationMethod = assertion.getAuthenticationStatement().getAuthenticationMethod();
        assertEquals(LassoConstants.SAML_AUTHENTICATION_METHOD_PASSWORD, authenticationMethod);

        // Service provider logout.
        spDump = generateServiceProviderDump();
        assertNotNull(spDump);
        sp = Server.newFromDump(spDump);
        assertNotNull(sp);
        spLogout = new Logout(sp);
        assertNotNull(spIdentityDump);
        spLogout.setIdentityFromDump(spIdentityDump);
        assertNotNull(spSessionDump);
        spLogout.setSessionFromDump(spSessionDump);
        spLogout.initRequest(null, LassoConstants.HTTP_METHOD_ANY);
        spLogout.buildRequestMsg();
        soapEndpoint = spLogout.getMsgUrl();
        soapRequestMsg = spLogout.getMsgBody();

        // Identity provider SOAP endpoint.
        requestType = LassoJNI.lasso_get_request_type_from_soap_msg(soapRequestMsg);
        assertEquals(LassoConstants.REQUEST_TYPE_LOGOUT, requestType);
        idpDump = generateIdentityProviderDump();
        assertNotNull(idpDump);
        idp = Server.newFromDump(idpDump);
        assertNotNull(idp);
        idpLogout = new Logout(idp);
	assertEquals(0, idpLogout.processRequestMsg(soapRequestMsg));
        assertEquals(nameIdentifier, ((SamlNameIdentifier)idpLogout.getNameIdentifier()).getContent());
        assertNotNull(idpIdentityDump);
        idpLogout.setIdentityFromDump(idpIdentityDump);
        assertNotNull(idpSessionDump);
        idpLogout.setSessionFromDump(idpSessionDump);
        idpLogout.validateRequest();
        idpIdentity = idpLogout.getIdentity();
        assertNotNull(idpIdentity);
        idpIdentityDump = idpIdentity.dump();
        assertNotNull(idpIdentityDump);
        // There is no other service provider from which the user must be logged out.
        assertEquals(null, idpLogout.getNextProviderId());
        idpLogout.buildResponseMsg();
        soapResponseMsg = idpLogout.getMsgBody();

        // Service provider logout (step 2: process SOAP response).
        spLogout.processResponseMsg(soapResponseMsg);
        spIdentityDump = spLogout.getIdentity().dump();
        assertNotNull(spIdentityDump);
    }
    public void test03_getProviders() {
        String identityProviderDump = generateIdentityProviderDump();
        Server server = Server.newFromDump(identityProviderDump);
        Map providers = server.getProviders();
	assertNotNull(providers);
    }

    public static Test suite() { 
        return new TestSuite(LoginTest.class); 
    }

    public static void main(String args[]) { 
        junit.textui.TestRunner.run(suite());
        System.gc();
    }
}

