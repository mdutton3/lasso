/*
 * $Id$
 *
 * Java unit tests for Lasso library
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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


public class LoginTest extends TestCase {
    public String generateIdentityProviderDump() {
	Server server = new Server(
            "../../tests/data/idp1-la/metadata.xml",
            "../../tests/data/idp1-la/private-key-raw.pem",
	    null,
            "../../tests/data/idp1-la/certificate.pem");
        server.addProvider(
            lasso.PROVIDER_ROLE_SP,
            "../../tests/data/sp1-la/metadata.xml",
            "../../tests/data/sp1-la/public-key.pem",
            "../../tests/data/ca1-la/certificate.pem");
	String serverDump = server.dump();
        return serverDump;
    }

    public String generateServiceProviderDump() {
	Server server = new Server(
            "../../tests/data/sp1-la/metadata.xml",
            "../../tests/data/sp1-la/private-key-raw.pem",
	    null,
            "../../tests/data/sp1-la/certificate.pem");
        server.addProvider(
            lasso.PROVIDER_ROLE_IDP,
            "../../tests/data/idp1-la/metadata.xml",
            "../../tests/data/idp1-la/public-key.pem",
            "../../tests/data/ca1-la/certificate.pem");
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
	Session idpSession, spSession;
	String artifact, authenticationMethod, authnRequestQuery, authnRequestUrl, idpDump,
	    idpIdentityDump, idpRemoteProviderId, idpSessionDump, nameIdentifier, relayState,
	    responseQuery, responseUrl, soapEndpoint, soapResponseMsg, soapRequestMsg,
	    spDump, spIdentityDump, spSessionDump;

	// Service provider login using HTTP redirect.
        spDump = generateServiceProviderDump();
	assertNotNull(spDump);
        sp = Server.newFromDump(spDump);
        spLogin = new Login(sp);
        spLogin.initAuthnRequest("https://idp1/metadata", lasso.HTTP_METHOD_REDIRECT);
	authnRequest = (LibAuthnRequest) spLogin.getRequest();
        authnRequest.setIsPassive(false);
        authnRequest.setNameIdPolicy(lasso.LIB_NAMEID_POLICY_TYPE_FEDERATED);
        authnRequest.setConsent(lasso.LIB_CONSENT_OBTAINED);
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
        authenticationMethod = lasso.SAML_AUTHENTICATION_METHOD_PASSWORD;
        idpLogin.buildAssertion(
                authenticationMethod,
                null, // authenticationInstant
                null, // reauthenticateOnOrAfter
                null, // notBefore
                null);// notOnOrAfter
        assertEquals(lasso.LOGIN_PROTOCOL_PROFILE_BRWS_ART, idpLogin.getProtocolProfile());
        idpLogin.buildArtifactMsg(lasso.HTTP_METHOD_REDIRECT);
	idpIdentityDump = idpLogin.getIdentity().dump();
        assertNotNull(idpIdentityDump);
	idpSessionDump = idpLogin.getSession().dump();
        assertNotNull(idpSessionDump);
        responseUrl = idpLogin.getMsgUrl();
        responseQuery = responseUrl.substring(responseUrl.indexOf("?") + 1);
	idpRemoteProviderId = idpLogin.getRemoteProviderId();
	nameIdentifier = idpLogin.getNameIdentifier().getContent();
	artifact = idpLogin.getAssertionArtifact();
        assertNotNull(artifact);
        method = lasso.HTTP_METHOD_REDIRECT;

        // Service provider assertion consumer.
        spDump = generateServiceProviderDump();
	assertNotNull(spDump);
        sp = Server.newFromDump(spDump);
        spLogin = new Login(sp);
        spLogin.initRequest(responseQuery, method);
        spLogin.buildRequestMsg();
        soapEndpoint = spLogin.getMsgUrl();
	soapRequestMsg = spLogin.getMsgBody();

        // Identity provider SOAP endpoint.
        requestType = lasso.getRequestTypeFromSoapMsg(soapRequestMsg);
        assertEquals(lasso.REQUEST_TYPE_LOGIN, requestType);
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
        assertEquals(nameIdentifier, spLogin.getNameIdentifier().getContent());
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
	assertion = (SamlAssertion) spSession.getAssertions("https://idp1/metadata").getItem(0);
	authenticationMethod = assertion.getAuthenticationStatement().getAuthenticationMethod();
        assertEquals(lasso.SAML_AUTHENTICATION_METHOD_PASSWORD, authenticationMethod);

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
        spLogout.initRequest(null, lasso.HTTP_METHOD_ANY);
        spLogout.buildRequestMsg();
        soapEndpoint = spLogout.getMsgUrl();
        soapRequestMsg = spLogout.getMsgBody();

	// Identity provider SOAP endpoint.
	requestType = lasso.getRequestTypeFromSoapMsg(soapRequestMsg);
        assertEquals(lasso.REQUEST_TYPE_LOGOUT, requestType);
        idpDump = generateIdentityProviderDump();
        assertNotNull(idpDump);
        idp = Server.newFromDump(idpDump);
        assertNotNull(idp);
        idpLogout = new Logout(idp);
	idpLogout.processRequestMsg(soapRequestMsg);
        assertEquals(nameIdentifier, idpLogout.getNameIdentifier().getContent());
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

    public static Test suite() { 
	return new TestSuite(LoginTest.class); 
    }

    public static void main(String args[]) { 
        System.out.println(System.mapLibraryName("jlasso"));
        lasso.init();
	junit.textui.TestRunner.run(suite());
	lasso.shutdown();
    }
}
