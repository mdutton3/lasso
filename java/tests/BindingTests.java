/*
 * $Id$
 *
 * Java unit tests for Lasso library
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: See AUTHORS file.
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
// $ javac -classpath /usr/share/java/junit.jar:../lasso.jar:. BindingTests.java
// $ java -classpath /usr/share/java/junit.jar:../lasso.jar:. BindingTests
// or for gcj:
// $ export LD_LIBRARY_PATH=../
// $ gcj -C -classpath /usr/share/java/junit.jar:../lasso.jar:. BindingTests.java
// $ gij -classpath /usr/share/java/junit.jar:../lasso.jar:. BindingTests


import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import com.entrouvert.lasso.*;


public class BindingTests extends TestCase {
    public static void main(String args[]) { 
	junit.textui.TestRunner.run(suite());
    }

    public static Test suite() { 
	return new TestSuite(BindingTests.class); 
    }

    public void test01() {
	// Create and delete nodes.

	LibAuthnRequest authnRequest = new LibAuthnRequest();
	authnRequest = null;
    }

    public void test02() {
	// Get & set simple attributes of nodes.

	LibAuthnRequest authnRequest = new LibAuthnRequest();

	// Test a string attribute.
	assertNull(authnRequest.getConsent());
	authnRequest.setConsent(lasso.libConsentObtained);
	assertEquals(authnRequest.getConsent(), lasso.libConsentObtained);
	authnRequest.setConsent(null);
	assertNull(authnRequest.getConsent());

	// Test a renamed string attribute.
	assertNull(authnRequest.getRelayState());
	authnRequest.setRelayState("Hello World!");
	assertEquals(authnRequest.getRelayState(), "Hello World!");
	authnRequest.setRelayState(null);
	assertNull(authnRequest.getRelayState());

	// Test an integer attribute.
	assertEquals(authnRequest.getMajorVersion(), 0);
	authnRequest.setMajorVersion(314);
	assertEquals(authnRequest.getMajorVersion(), 314);

	authnRequest = null;
    }

    public void test03() {
	// Get & set attributes of nodes of type string list.

	LibAuthnRequest authnRequest = new LibAuthnRequest();

	assertNull(authnRequest.getRespondWith());

	StringList respondWith = new StringList();
	assertEquals(respondWith.length(), 0);
	respondWith.append("first string");
	assertEquals(respondWith.length(), 1);
	assertEquals(respondWith.getItem(0), "first string");
	assertEquals(respondWith.getItem(0), "first string");
	respondWith.append("second string");
	assertEquals(respondWith.length(), 2);
	assertEquals(respondWith.getItem(0), "first string");
	assertEquals(respondWith.getItem(1), "second string");
	respondWith.append("third string");
	assertEquals(respondWith.length(), 3);
	assertEquals(respondWith.getItem(0), "first string");
	assertEquals(respondWith.getItem(1), "second string");
	assertEquals(respondWith.getItem(2), "third string");
	authnRequest.setRespondWith(respondWith);
	assertEquals(authnRequest.getRespondWith().getItem(0), "first string");
	assertEquals(authnRequest.getRespondWith().getItem(1), "second string");
	assertEquals(authnRequest.getRespondWith().getItem(2), "third string");
	assertEquals(respondWith.getItem(0), "first string");
	assertEquals(respondWith.getItem(1), "second string");
	assertEquals(respondWith.getItem(2), "third string");
	respondWith = null;
	assertEquals(authnRequest.getRespondWith().getItem(0), "first string");
	assertEquals(authnRequest.getRespondWith().getItem(1), "second string");
	assertEquals(authnRequest.getRespondWith().getItem(2), "third string");
	respondWith = authnRequest.getRespondWith();
	assertEquals(respondWith.getItem(0), "first string");
	assertEquals(respondWith.getItem(1), "second string");
	assertEquals(respondWith.getItem(2), "third string");
	respondWith = null;
	assertEquals(authnRequest.getRespondWith().getItem(0), "first string");
	assertEquals(authnRequest.getRespondWith().getItem(1), "second string");
	assertEquals(authnRequest.getRespondWith().getItem(2), "third string");
	authnRequest.setRespondWith(null);
	assertNull(authnRequest.getRespondWith());

	authnRequest = null;
    }

    public void test04() {
        // Get & set attributes of nodes of type node list.

        SamlpResponse response = new SamlpResponse();

        assertNull(response.getAssertion());

        NodeList assertions = new NodeList();
        assertEquals(assertions.length(), 0);
        SamlAssertion assertion1 = new SamlAssertion();
        assertion1.setAssertionId("assertion 1");
        assertions.append(assertion1);
        assertEquals(assertions.length(), 1);
        assertEquals(((SamlAssertion) assertions.getItem(0)).getAssertionId(), "assertion 1");
        assertEquals(((SamlAssertion) assertions.getItem(0)).getAssertionId(), "assertion 1");
        SamlAssertion assertion2 = new SamlAssertion();
        assertion2.setAssertionId("assertion 2");
        assertions.append(assertion2);
        assertEquals(assertions.length(), 2);
        assertEquals(((SamlAssertion) assertions.getItem(0)).getAssertionId(), "assertion 1");
        assertEquals(((SamlAssertion) assertions.getItem(1)).getAssertionId(), "assertion 2");
        SamlAssertion assertion3 = new SamlAssertion();
        assertion3.setAssertionId("assertion 3");
        assertions.append(assertion3);
        assertEquals(assertions.length(), 3);
        assertEquals(((SamlAssertion) assertions.getItem(0)).getAssertionId(), "assertion 1");
        assertEquals(((SamlAssertion) assertions.getItem(1)).getAssertionId(), "assertion 2");
        assertEquals(((SamlAssertion) assertions.getItem(2)).getAssertionId(), "assertion 3");
        response.setAssertion(assertions);
        assertEquals(((SamlAssertion) response.getAssertion().getItem(0)).getAssertionId(),
		     "assertion 1");
        assertEquals(((SamlAssertion) response.getAssertion().getItem(1)).getAssertionId(),
		     "assertion 2");
        assertEquals(((SamlAssertion) response.getAssertion().getItem(2)).getAssertionId(),
		     "assertion 3");
        assertEquals(((SamlAssertion) assertions.getItem(0)).getAssertionId(), "assertion 1");
        assertEquals(((SamlAssertion) assertions.getItem(1)).getAssertionId(), "assertion 2");
        assertEquals(((SamlAssertion) assertions.getItem(2)).getAssertionId(), "assertion 3");
        assertions = null;;
        assertEquals(((SamlAssertion) response.getAssertion().getItem(0)).getAssertionId(),
		     "assertion 1");
        assertEquals(((SamlAssertion) response.getAssertion().getItem(1)).getAssertionId(),
		     "assertion 2");
        assertEquals(((SamlAssertion) response.getAssertion().getItem(2)).getAssertionId(),
		     "assertion 3");
        assertions = response.getAssertion();
        assertEquals(((SamlAssertion) assertions.getItem(0)).getAssertionId(), "assertion 1");
        assertEquals(((SamlAssertion) assertions.getItem(1)).getAssertionId(), "assertion 2");
        assertEquals(((SamlAssertion) assertions.getItem(2)).getAssertionId(), "assertion 3");
        assertions = null;
        assertEquals(((SamlAssertion) response.getAssertion().getItem(0)).getAssertionId(),
		     "assertion 1");
        assertEquals(((SamlAssertion) response.getAssertion().getItem(1)).getAssertionId(),
		     "assertion 2");
        assertEquals(((SamlAssertion) response.getAssertion().getItem(2)).getAssertionId(),
		     "assertion 3");
        response.setAssertion(null);
        assertNull(response.getAssertion());

	response = null;
    }

    public void test05() {
	// Get & set attributes of nodes of type XML list.

	LibAuthnRequest authnRequest = new LibAuthnRequest();

	assertNull(authnRequest.getExtension());

        String actionString1 = "<lib:Extension xmlns:lib=\"urn:liberty:iff:2003-08\">\n"
	    + "  <action>do 1</action>\n"
	    + "</lib:Extension>";
        String actionString2 = "<lib:Extension xmlns:lib=\"urn:liberty:iff:2003-08\">\n"
	    + "  <action>do 2</action>\n"
	    + "</lib:Extension>";
        String actionString3 = "<lib:Extension xmlns:lib=\"urn:liberty:iff:2003-08\">\n"
	    + "  <action>do 3</action>\n"
	    + "</lib:Extension>";
	StringList extension = new StringList();
	assertEquals(extension.length(), 0);
	extension.append(actionString1);
	assertEquals(extension.length(), 1);
	assertEquals(extension.getItem(0), actionString1);
	assertEquals(extension.getItem(0), actionString1);
	extension.append(actionString2);
	assertEquals(extension.length(), 2);
	assertEquals(extension.getItem(0), actionString1);
	assertEquals(extension.getItem(1), actionString2);
	extension.append(actionString3);
	assertEquals(extension.length(), 3);
	assertEquals(extension.getItem(0), actionString1);
	assertEquals(extension.getItem(1), actionString2);
	assertEquals(extension.getItem(2), actionString3);
	authnRequest.setExtension(extension);
	assertEquals(authnRequest.getExtension().getItem(0), actionString1);
	assertEquals(authnRequest.getExtension().getItem(1), actionString2);
	assertEquals(authnRequest.getExtension().getItem(2), actionString3);
	assertEquals(extension.getItem(0), actionString1);
	assertEquals(extension.getItem(1), actionString2);
	assertEquals(extension.getItem(2), actionString3);
	extension = null;
	assertEquals(authnRequest.getExtension().getItem(0), actionString1);
	assertEquals(authnRequest.getExtension().getItem(1), actionString2);
	assertEquals(authnRequest.getExtension().getItem(2), actionString3);
	extension = authnRequest.getExtension();
	assertEquals(extension.getItem(0), actionString1);
	assertEquals(extension.getItem(1), actionString2);
	assertEquals(extension.getItem(2), actionString3);
	extension = null;
	assertEquals(authnRequest.getExtension().getItem(0), actionString1);
	assertEquals(authnRequest.getExtension().getItem(1), actionString2);
	assertEquals(authnRequest.getExtension().getItem(2), actionString3);
	authnRequest.setExtension(null);
	assertNull(authnRequest.getExtension());

	authnRequest = null;
    }

    public void test06() {
        // Get & set attributes of nodes of type node.

        Login login = new Login(new Server(null, null, null, null));

        assertNull(login.getRequest());
        login.setRequest((SamlpRequestAbstract) new LibAuthnRequest());
        ((LibAuthnRequest) login.getRequest()).setConsent(lasso.libConsentObtained);
        assertEquals(((LibAuthnRequest) login.getRequest()).getConsent(),
		     lasso.libConsentObtained);
        login.setRequest(null);
        assertNull(login.getRequest());

        login = null;
    }
}
