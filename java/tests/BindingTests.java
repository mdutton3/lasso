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
}
