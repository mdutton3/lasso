/*
 * JLasso -- Java bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: Benjamin Poussin <poussin@codelutin.com>
 *          Emmanuel Raviart <eraviart@entrouvert.com>
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
// $ export LD_LIBRARY_PATH=../target/
// $ javac -classpath /usr/share/java/junit.jar:../target/lasso.jar:. LoginTest.java
// $ java -classpath /usr/share/java/junit.jar:../target/lasso.jar:. LoginTest
// or for gcj:
// $ export LD_LIBRARY_PATH=../target/
// $ gcj -C -classpath /usr/share/java/junit.jar:../target/lasso.jar:. LoginTest.java
// $ gij -classpath /usr/share/java/junit.jar:../target/lasso.jar:. LoginTest

import junit.framework.TestCase;
import junit.framework.Test;
import junit.framework.TestSuite;

import com.entrouvert.lasso.*;


public class LoginTest extends TestCase {
    public String generateIdentityProviderContextDump() {
	LassoServer serverContext = new LassoServer(
            "../../examples/data/idp-metadata.xml",
            "../../examples/data/idp-public-key.pem",
            "../../examples/data/idp-private-key.pem",
            "../../examples/data/idp-crt.pem",
           Lasso.signatureMethodRsaSha1);
        serverContext.addProvider(
            "../../examples/data/sp-metadata.xml",
            "../../examples/data/sp-public-key.pem",
            "../../examples/data/ca-crt.pem");
	String serverContextDump = serverContext.dump();
        return serverContextDump;
    }

    public String generateServiceProviderContextDump() {
        LassoServer serverContext = new LassoServer(
            "../../examples/data/sp-metadata.xml",
            "../../examples/data/sp-public-key.pem",
            "../../examples/data/sp-private-key.pem",
            "../../examples/data/sp-crt.pem",
            Lasso.signatureMethodRsaSha1);
        serverContext.addProvider(
            "../../examples/data/idp-metadata.xml",
            "../../examples/data/idp-public-key.pem",
            "../../examples/data/ca-crt.pem");
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
	// Service provider login using HTTP redirect.
        String spContextDump = generateServiceProviderContextDump();
	assertNotNull(spContextDump);
        LassoServer spContext = new LassoServer(spContextDump);
        LassoLogin spLoginContext = new LassoLogin(spContext, null);
        assertEquals(spLoginContext.initAuthnRequest(
	    "https://identity-provider:1998/liberty-alliance/metadata"), 0);
	LassoAuthnRequest authnRequest = (LassoAuthnRequest) spLoginContext.getRequest();
        authnRequest.setPassive(false);
        authnRequest.setNameIdPolicy(Lasso.libNameIdPolicyTypeFederated);
        authnRequest.setConsent(Lasso.libConsentObtained);
        authnRequest.setRelayState("fake");
        assertEquals(spLoginContext.buildAuthnRequestMsg(), 0);
        String authnRequestUrl = spLoginContext.getMsgUrl();
        String authnRequestMsg = authnRequestUrl.substring(authnRequestUrl.indexOf("?") + 1);
        int method = Lasso.httpMethodRedirect;

	// Identity provider singleSignOn, for a user having no federation.
        String idpContextDump = generateIdentityProviderContextDump();
        assertNotNull(idpContextDump);
        LassoServer idpContext = new LassoServer(idpContextDump);
        LassoLogin idpLoginContext = new LassoLogin(idpContext, null);
        assertEquals(idpLoginContext.initFromAuthnRequestMsg(authnRequestMsg, method), 0);
        assertTrue(idpLoginContext.mustAuthenticate());
    }

    public static Test suite() { 
	return new TestSuite(LoginTest.class); 
    }

    public static void main(String args[]) { 
	Lasso.init();
	junit.textui.TestRunner.run(suite());
	Lasso.shutdown();
    }
}
