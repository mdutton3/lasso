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
    public String generateIdentityProviderContextDump() {
	LassoServer serverContext = new LassoServer(
            "../../tests/data/idp1-la/metadata.xml'",
	    NULL, //"../../tests/data/idp1-la/public-key.pem",
            "../../tests/data/idp1-la/private-key-raw.pem",
            "../../tests/data/idp1-la/certificate.pem",
	    Lasso.SIGNATURE_METHOD_RSA_SHA1);
        serverContext.addProvider(
            "../../tests/data/sp1-la/metadata.xml",
            "../../tests/data/sp1-la/public-key.pem",
            "../../tests/data/ca1-la/certificate.pem");
	String serverContextDump = serverContext.dump();
        return serverContextDump;
    }

    public String generateServiceProviderContextDump() {
	LassoServer serverContext = new LassoServer(
            "../../tests/data/sp1-la/metadata.xml'",
	    NULL, //"../../tests/data/sp1-la/public-key.pem",
            "../../tests/data/sp1-la/private-key-raw.pem",
            "../../tests/data/sp1-la/certificate.pem",
	    Lasso.SIGNATURE_METHOD_RSA_SHA1);
        serverContext.addProvider(
            "../../tests/data/idp1-la/metadata.xml",
            "../../tests/data/idp1-la/public-key.pem",
            "../../tests/data/ca1-la/certificate.pem");
        String serverContextDump = serverContext.dump();
        return serverContextDump;
    }

    public void test01_generateServersContextDumps() {
        String identityProviderContextDump = generateIdentityProviderContextDump();
        assertNotNull(identityProviderContextDump);
        String serviceProviderContextDump = generateServiceProviderContextDump();
        assertNotNull(serviceProviderContextDump);
    }

    public void test02_serviceProviderLogin() {
	boolean userAuthenticated;
	int method, requestType;
	LassoAuthnRequest authnRequest;
	LassoIdentity idpIdentityContext, spIdentityContext;
	LassoLogin idpLoginContext, spLoginContext;
	LassoLogout idpLogoutContext, spLogoutContext;
	LassoResponse response;
	LassoServer idpContext, spContext;
	LassoSession idpSessionContext, spSessionContext;
	String artifact, authenticationMethod, authnRequestQuery, authnRequestUrl, idpContextDump,
	    idpIdentityContextDump, idpSessionContextDump, nameIdentifier, relayState,
	    responseQuery, responseUrl, soapEndpoint, soapResponseMsg, soapRequestMsg,
	    spContextDump, spIdentityContextDump, spSessionContextDump;

	// Service provider login using HTTP redirect.
        spContextDump = generateServiceProviderContextDump();
	assertNotNull(spContextDump);
        spContext = new LassoServer(spContextDump);
        spLoginContext = new LassoLogin(spContext);
        assertEquals(0, spLoginContext.initAuthnRequest(
            "https://identity-provider:1998/liberty-alliance/metadata"));
        assertEquals(Lasso.MESSAGE_TYPE_AUTHN_REQUEST, spLoginContext.getRequestType());
	authnRequest = (LassoAuthnRequest) spLoginContext.getRequest();
        authnRequest.setPassive(false);
        authnRequest.setNameIdPolicy(Lasso.LIB_NAMEID_POLICY_TYPE_FEDERATED);
        authnRequest.setConsent(Lasso.LIB_CONSENT_OBTAINED);
	relayState = "fake";
        authnRequest.setRelayState(relayState);
        assertEquals(0, spLoginContext.buildAuthnRequestMsg());
        authnRequestUrl = spLoginContext.getMsgUrl();
        authnRequestQuery = authnRequestUrl.substring(authnRequestUrl.indexOf("?") + 1);
        method = Lasso.HTTP_METHOD_REDIRECT;

	// Identity provider singleSignOn, for a user having no federation.
        idpContextDump = generateIdentityProviderContextDump();
        assertNotNull(idpContextDump);
        idpContext = new LassoServer(idpContextDump);
        idpLoginContext = new LassoLogin(idpContext);
        assertEquals(0, idpLoginContext.initFromAuthnRequestMsg(authnRequestQuery, method));
        assertTrue(idpLoginContext.mustAuthenticate());

        userAuthenticated = true;
        authenticationMethod = Lasso.SAML_AUTHENTICATION_METHOD_PASSWORD;
        assertEquals(Lasso.LOGIN_PROTOCOL_PROFILE_BRWS_ART, idpLoginContext.getProtocolProfile());
        assertEquals(0, idpLoginContext.buildArtifactMsg(
            userAuthenticated, authenticationMethod, "FIXME: reauthenticateOnOrAfter",
            Lasso.HTTP_METHOD_REDIRECT));
	idpIdentityContextDump = idpLoginContext.getIdentity().dump();
        assertNotNull(idpIdentityContextDump);
	idpSessionContextDump = idpLoginContext.getSession().dump();
        assertNotNull(idpSessionContextDump);
        responseUrl = idpLoginContext.getMsgUrl();
        responseQuery = responseUrl.substring(responseUrl.indexOf("?") + 1);
        soapResponseMsg = idpLoginContext.getResponseDump();
        artifact = idpLoginContext.getAssertionArtifact();
	nameIdentifier = idpLoginContext.getNameIdentifier();
        method = Lasso.HTTP_METHOD_REDIRECT;

        // Service provider assertion consumer.
        spContextDump = generateServiceProviderContextDump();
	assertNotNull(spContextDump);
        spContext = new LassoServer(spContextDump);
        spLoginContext = new LassoLogin(spContext);
        assertEquals(0, spLoginContext.initRequest(responseQuery, method));
        assertEquals(0, spLoginContext.buildRequestMsg());
        soapEndpoint = spLoginContext.getMsgUrl();
	soapRequestMsg = spLoginContext.getMsgBody();

        // Identity provider SOAP endpoint.
        requestType = Lasso.getRequestTypeFromSoapMsg(soapRequestMsg);
        assertEquals(Lasso.REQUEST_TYPE_LOGIN, requestType);

	// Service provider assertion consumer (step 2: process SOAP response).
        assertEquals(0, spLoginContext.processResponseMsg(soapResponseMsg));
        assertEquals(nameIdentifier, spLoginContext.getNameIdentifier());
	// The user doesn't have any federation yet.
        assertEquals(0, spLoginContext.acceptSso());
        spIdentityContext = spLoginContext.getIdentity();
        assertNotNull(spIdentityContext);
        spIdentityContextDump = spIdentityContext.dump();
        assertNotNull(spIdentityContextDump);
        spSessionContext = spLoginContext.getSession();
        assertNotNull(spSessionContext);
        spSessionContextDump = spSessionContext.dump();
        assertNotNull(spSessionContextDump);
	authenticationMethod = spSessionContext.getAuthenticationMethod(null);
        assertEquals(Lasso.SAML_AUTHENTICATION_METHOD_PASSWORD, authenticationMethod);

        // Service provider logout.
        spContextDump = generateServiceProviderContextDump();
        assertNotNull(spContextDump);
        spContext = new LassoServer(spContextDump);
        assertNotNull(spContext);
        spLogoutContext = new LassoLogout(spContext, Lasso.providerTypeSp);
        assertNotNull(spIdentityContextDump);
	spLogoutContext.setIdentityFromDump(spIdentityContextDump);
        assertNotNull(spSessionContextDump);
	spLogoutContext.setSessionFromDump(spSessionContextDump);
        assertEquals(0, spLogoutContext.initRequest(null));
        assertEquals(0, spLogoutContext.buildRequestMsg());
        soapEndpoint = spLogoutContext.getMsgUrl();
        soapRequestMsg = spLogoutContext.getMsgBody();

	// Identity provider SOAP endpoint.
	requestType = Lasso.getRequestTypeFromSoapMsg(soapRequestMsg);
        assertEquals(Lasso.REQUEST_TYPE_LOGOUT, requestType);
        idpContextDump = generateIdentityProviderContextDump();
        assertNotNull(idpContextDump);
        idpContext = new LassoServer(idpContextDump);
        assertNotNull(idpContext);
        idpLogoutContext = new LassoLogout(idpContext, Lasso.providerTypeIdp);
	assertEquals(0, idpLogoutContext.loadRequestMsg(soapRequestMsg, Lasso.HTTP_METHOD_SOAP));
        assertEquals(nameIdentifier, idpLogoutContext.getNameIdentifier());
        assertNotNull(idpIdentityContextDump);
        assertEquals(0, idpLogoutContext.setIdentityFromDump(idpIdentityContextDump));
        assertNotNull(idpSessionContextDump);
        assertEquals(0, idpLogoutContext.setSessionFromDump(idpSessionContextDump));
	assertEquals(0, idpLogoutContext.processRequest());
        idpIdentityContext = idpLogoutContext.getIdentity();
        assertNotNull(idpIdentityContext);
        idpIdentityContextDump = idpIdentityContext.dump();
        assertNotNull(idpIdentityContextDump);
	// There is no other service provider from which the user must be logged out.
        assertEquals(null, idpLogoutContext.getNextProviderId());
        assertEquals(0, idpLogoutContext.buildResponseMsg());
        soapResponseMsg = idpLogoutContext.getMsgBody();

	// Service provider logout (step 2: process SOAP response).
        assertEquals(0, spLogoutContext.processResponseMsg(soapResponseMsg, Lasso.HTTP_METHOD_SOAP));
        spIdentityContextDump = spLogoutContext.getIdentity().dump();
        assertNotNull(spIdentityContextDump);
    }

    public static Test suite() { 
	return new TestSuite(LoginTest.class); 
    }

    public static void main(String args[]) { 
        System.out.println(System.mapLibraryName("jlasso"));
        Lasso.init();
	junit.textui.TestRunner.run(suite());
	Lasso.shutdown();
    }
}
