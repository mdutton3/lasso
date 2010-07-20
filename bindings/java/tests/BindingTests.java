/*
 * $Id: BindingTests.java 3238 2007-05-30 17:24:50Z dlaniel $
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import com.entrouvert.lasso.*;
import java.util.*;


public class BindingTests extends TestCase {
    public static void main(String args[]) { 
	junit.textui.TestRunner.run(suite());
        System.gc();
    }

    public static Test suite() { 
	return new TestSuite(BindingTests.class); 
    }

    public void test01() {
	// Create and delete nodes.

	LibAuthnRequest authnRequest = new LibAuthnRequest();
        assertNotNull(authnRequest);
	authnRequest = null;
    }

    public void test02() {
	// Get & set simple attributes of nodes.

	LibAuthnRequest authnRequest = new LibAuthnRequest();

	// Test a string attribute.
	assertNull(authnRequest.getConsent());
	authnRequest.setConsent(LassoConstants.LIB_CONSENT_OBTAINED);
	assertEquals(authnRequest.getConsent(), LassoConstants.LIB_CONSENT_OBTAINED);
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

	assertTrue(authnRequest.getRespondWith().isEmpty());

	List respondWith = new ArrayList();
	assertEquals(respondWith.size(), 0);
	respondWith.add("first string");
	assertEquals(respondWith.size(), 1);
	assertEquals(respondWith.get(0), "first string");
	assertEquals(respondWith.get(0), "first string");
	respondWith.add("second string");
	assertEquals(respondWith.size(), 2);
	assertEquals(respondWith.get(0), "first string");
	assertEquals(respondWith.get(1), "second string");
	respondWith.add("third string");
	assertEquals(respondWith.size(), 3);
	assertEquals(respondWith.get(0), "first string");
	assertEquals(respondWith.get(1), "second string");
	assertEquals(respondWith.get(2), "third string");
	authnRequest.setRespondWith(respondWith);
	assertEquals(authnRequest.getRespondWith().get(0), "first string");
	assertEquals(authnRequest.getRespondWith().get(1), "second string");
	assertEquals(authnRequest.getRespondWith().get(2), "third string");
	assertEquals(respondWith.get(0), "first string");
	assertEquals(respondWith.get(1), "second string");
	assertEquals(respondWith.get(2), "third string");
	respondWith = null;
	assertEquals(authnRequest.getRespondWith().get(0), "first string");
	assertEquals(authnRequest.getRespondWith().get(1), "second string");
	assertEquals(authnRequest.getRespondWith().get(2), "third string");
	respondWith = authnRequest.getRespondWith();
	assertEquals(respondWith.get(0), "first string");
	assertEquals(respondWith.get(1), "second string");
	assertEquals(respondWith.get(2), "third string");
	respondWith = null;
	assertEquals(authnRequest.getRespondWith().get(0), "first string");
	assertEquals(authnRequest.getRespondWith().get(1), "second string");
	assertEquals(authnRequest.getRespondWith().get(2), "third string");
        authnRequest.removeFromRespondWith("second string");
	assertEquals(authnRequest.getRespondWith().get(0), "first string");
	assertEquals(authnRequest.getRespondWith().get(1), "third string");
        authnRequest.addToRespondWith("second string");
	assertEquals(authnRequest.getRespondWith().get(0), "first string");
	assertEquals(authnRequest.getRespondWith().get(1), "third string");
	assertEquals(authnRequest.getRespondWith().get(2), "second string");
	authnRequest.setRespondWith(null);
	assertTrue(authnRequest.getRespondWith().isEmpty());

	authnRequest = null;
    }

    public void test04() {
        // Get & set attributes of nodes of type node list.

        SamlpResponse response = new SamlpResponse();

        assertTrue(response.getAssertion().isEmpty());

        List assertions = new ArrayList();
        assertEquals(assertions.size(), 0);
        SamlAssertion assertion1 = new SamlAssertion();
        assertion1.setAssertionId("assertion 1");
        assertions.add(assertion1);
        assertEquals(assertions.size(), 1);
        assertEquals(((SamlAssertion) assertions.get(0)).getAssertionId(), "assertion 1");
        assertEquals(((SamlAssertion) assertions.get(0)).getAssertionId(), "assertion 1");
        SamlAssertion assertion2 = new SamlAssertion();
        assertion2.setAssertionId("assertion 2");
        assertions.add(assertion2);
        assertEquals(assertions.size(), 2);
        assertEquals(((SamlAssertion) assertions.get(0)).getAssertionId(), "assertion 1");
        assertEquals(((SamlAssertion) assertions.get(1)).getAssertionId(), "assertion 2");
        SamlAssertion assertion3 = new SamlAssertion();
        assertion3.setAssertionId("assertion 3");
        assertions.add(assertion3);
        assertEquals(assertions.size(), 3);
        assertEquals(((SamlAssertion) assertions.get(0)).getAssertionId(), "assertion 1");
        assertEquals(((SamlAssertion) assertions.get(1)).getAssertionId(), "assertion 2");
        assertEquals(((SamlAssertion) assertions.get(2)).getAssertionId(), "assertion 3");
        response.setAssertion(assertions);
        assertEquals(((SamlAssertion) response.getAssertion().get(0)).getAssertionId(), "assertion 1");
        assertEquals(((SamlAssertion) response.getAssertion().get(1)).getAssertionId(), "assertion 2");
        assertEquals(((SamlAssertion) response.getAssertion().get(2)).getAssertionId(), "assertion 3");
        assertEquals(((SamlAssertion) assertions.get(0)).getAssertionId(), "assertion 1");
        assertEquals(((SamlAssertion) assertions.get(1)).getAssertionId(), "assertion 2");
        assertEquals(((SamlAssertion) assertions.get(2)).getAssertionId(), "assertion 3");
        assertions = null;;
        assertEquals(((SamlAssertion) response.getAssertion().get(0)).getAssertionId(), "assertion 1");
        assertEquals(((SamlAssertion) response.getAssertion().get(1)).getAssertionId(), "assertion 2");
        assertEquals(((SamlAssertion) response.getAssertion().get(2)).getAssertionId(), "assertion 3");
        assertions = response.getAssertion();
        assertEquals(((SamlAssertion) assertions.get(0)).getAssertionId(), "assertion 1");
        assertEquals(((SamlAssertion) assertions.get(1)).getAssertionId(), "assertion 2");
        assertEquals(((SamlAssertion) assertions.get(2)).getAssertionId(), "assertion 3");
        assertions = null;
        assertEquals(((SamlAssertion) response.getAssertion().get(0)).getAssertionId(), "assertion 1");
        assertEquals(((SamlAssertion) response.getAssertion().get(1)).getAssertionId(), "assertion 2");
        assertEquals(((SamlAssertion) response.getAssertion().get(2)).getAssertionId(), "assertion 3");
        response.setAssertion(null);
        assertTrue(response.getAssertion().isEmpty());

	response = null;
    }

    public void test05() {
	// Get & set attributes of nodes of type XML list.

	LibAuthnRequest authnRequest = new LibAuthnRequest();

	assertTrue(authnRequest.getExtension().isEmpty());

        String actionString1 = "<lib:Extension xmlns:lib=\"urn:liberty:iff:2003-08\">\n" + "  <action>do 1</action>\n" + "</lib:Extension>";
        String actionString2 = "<lib:Extension xmlns:lib=\"urn:liberty:iff:2003-08\">\n" + "  <action>do 2</action>\n" + "</lib:Extension>";
        String actionString3 = "<lib:Extension xmlns:lib=\"urn:liberty:iff:2003-08\">\n" + "  <action>do 3</action>\n" + "</lib:Extension>";
	List extension = new ArrayList();
	assertEquals(extension.size(), 0);
	extension.add(actionString1);
	assertEquals(extension.size(), 1);
	assertEquals(extension.get(0), actionString1);
	assertEquals(extension.get(0), actionString1);
	extension.add(actionString2);
	assertEquals(extension.size(), 2);
	assertEquals(extension.get(0), actionString1);
	assertEquals(extension.get(1), actionString2);
	extension.add(actionString3);
	assertEquals(extension.size(), 3);
	assertEquals(extension.get(0), actionString1);
	assertEquals(extension.get(1), actionString2);
	assertEquals(extension.get(2), actionString3);
	authnRequest.setExtension(extension);
	assertEquals(authnRequest.getExtension().get(0), actionString1);
	assertEquals(authnRequest.getExtension().get(1), actionString2);
	assertEquals(authnRequest.getExtension().get(2), actionString3);
	assertEquals(extension.get(0), actionString1);
	assertEquals(extension.get(1), actionString2);
	assertEquals(extension.get(2), actionString3);
	extension = null;
	assertEquals(authnRequest.getExtension().get(0), actionString1);
	assertEquals(authnRequest.getExtension().get(1), actionString2);
	assertEquals(authnRequest.getExtension().get(2), actionString3);
	extension = authnRequest.getExtension();
	assertEquals(extension.get(0), actionString1);
	assertEquals(extension.get(1), actionString2);
	assertEquals(extension.get(2), actionString3);
	extension = null;
	assertEquals(authnRequest.getExtension().get(0), actionString1);
	assertEquals(authnRequest.getExtension().get(1), actionString2);
	assertEquals(authnRequest.getExtension().get(2), actionString3);
	authnRequest.setExtension(null);
	assertTrue(authnRequest.getExtension().isEmpty());

	authnRequest = null;
    }

    public void test06() {
        // Get & set attributes of nodes of type node.

        Login login = new Login(new Server(null, null, null, null));

        assertNull(login.getRequest());
        login.setRequest((SamlpRequestAbstract) new LibAuthnRequest());
        ((LibAuthnRequest) login.getRequest()).setConsent(LassoConstants.LIB_CONSENT_OBTAINED);
        assertEquals(((LibAuthnRequest) login.getRequest()).getConsent(), LassoConstants.LIB_CONSENT_OBTAINED);
        login.setRequest(null);
        assertNull(login.getRequest());

        login = null;
    }
}
