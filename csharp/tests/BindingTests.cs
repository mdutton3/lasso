/*
 * $Id$
 *
 * C# unit tests for Lasso library
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

/* 
 * To run it, install Lasso then compile with:
 * export PKG_CONFIG_PATH=../
 * ln -s ../lasso.dll
 * ln -s ../lasso.dll.config
 * mcs -g -nologo -pkg:lasso-sharp -out:BindingTests.exe BindingTests.cs
 */

using System;

public class BindingTests {
	static void assertEquals(int i1, int i2) {
		if (i1 != i2)
			Console.WriteLine("Assertion failed: %d != %d", i1, i2);
	}

	static void assertEquals(String s1, String s2) {
		if (s1 != s2)
			Console.WriteLine("Assertion failed: %s != %s", s1, s2);
	}

	static void assertNull(Object o) {
		if (o != null)
			Console.WriteLine("Assertion failed: %s is not null", o);
	}

	static void assertNull(String s) {
		if (s != null)
			Console.WriteLine("Assertion failed: %s is not null", s);
	}

	static void Main() {
		lasso.lasso.init();
		test01();
		test02();
		test03();
		test04();
		test05();
		test06();
		lasso.lasso.shutdown();
	}

	static void test01() {
		Console.Write("Create and delete nodes.");

		lasso.LibAuthnRequest authnRequest = new lasso.LibAuthnRequest();
		authnRequest = null;

		Console.WriteLine(".. OK");
	}

	static void test02() {
		Console.Write("Get & set simple attributes of nodes.");

		lasso.LibAuthnRequest authnRequest = new lasso.LibAuthnRequest();

		// Test a string attribute.
		assertNull(authnRequest.consent);
		authnRequest.consent = lasso.lasso.libConsentObtained;
		assertEquals(authnRequest.consent, lasso.lasso.libConsentObtained);
		authnRequest.consent = null;
		assertNull(authnRequest.consent);

		// Test a renamed string attribute.
		assertNull(authnRequest.relayState);
		authnRequest.relayState = "Hello World!";
		assertEquals(authnRequest.relayState, "Hello World!");
		authnRequest.relayState = null;
		assertNull(authnRequest.relayState);

		// Test an integer attribute.
		assertEquals(authnRequest.majorVersion, 0);
		authnRequest.majorVersion = 314;
		assertEquals(authnRequest.majorVersion, 314);

		authnRequest = null;

		Console.WriteLine(".. OK");
	}

	static void test03() {
		Console.Write("Get & set attributes of nodes of type string list.");

		lasso.LibAuthnRequest authnRequest = new lasso.LibAuthnRequest();

		assertNull(authnRequest.respondWith);

		lasso.StringList respondWith = new lasso.StringList();
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
		authnRequest.respondWith = respondWith;
		assertEquals(authnRequest.respondWith.getItem(0), "first string");
		assertEquals(authnRequest.respondWith.getItem(1), "second string");
		assertEquals(authnRequest.respondWith.getItem(2), "third string");
		assertEquals(respondWith.getItem(0), "first string");
		assertEquals(respondWith.getItem(1), "second string");
		assertEquals(respondWith.getItem(2), "third string");
		respondWith = null;
		assertEquals(authnRequest.respondWith.getItem(0), "first string");
		assertEquals(authnRequest.respondWith.getItem(1), "second string");
		assertEquals(authnRequest.respondWith.getItem(2), "third string");
		respondWith = authnRequest.respondWith;
		assertEquals(respondWith.getItem(0), "first string");
		assertEquals(respondWith.getItem(1), "second string");
		assertEquals(respondWith.getItem(2), "third string");
		respondWith = null;
		assertEquals(authnRequest.respondWith.getItem(0), "first string");
		assertEquals(authnRequest.respondWith.getItem(1), "second string");
		assertEquals(authnRequest.respondWith.getItem(2), "third string");
		authnRequest.respondWith = null;
		assertNull(authnRequest.respondWith);
	
		authnRequest = null;

		Console.WriteLine(".. OK");
	}

	static void test04() {
		Console.Write("Get & set attributes of nodes of type node list.");

	        lasso.SamlpResponse response = new lasso.SamlpResponse();

	        assertNull(response.assertion);
	        lasso.NodeList assertions = new lasso.NodeList();
	        assertEquals(assertions.length(), 0);
	        lasso.SamlAssertion assertion1 = new lasso.SamlAssertion();
	        assertion1.assertionId = "assertion 1";
	        assertions.append(assertion1);
	        assertEquals(assertions.length(), 1);
	        assertEquals(((lasso.SamlAssertion) assertions.getItem(0)).assertionId,
				"assertion 1");
	        assertEquals(((lasso.SamlAssertion) assertions.getItem(0)).assertionId,
				"assertion 1");
	        lasso.SamlAssertion assertion2 = new lasso.SamlAssertion();
	        assertion2.assertionId = "assertion 2";
	        assertions.append(assertion2);
	        assertEquals(assertions.length(), 2);
	        assertEquals(((lasso.SamlAssertion) assertions.getItem(0)).assertionId,
				"assertion 1");
	        assertEquals(((lasso.SamlAssertion) assertions.getItem(1)).assertionId,
				"assertion 2");
	        lasso.SamlAssertion assertion3 = new lasso.SamlAssertion();
	        assertion3.assertionId = "assertion 3";
	        assertions.append(assertion3);
	        assertEquals(assertions.length(), 3);
	        assertEquals(((lasso.SamlAssertion) assertions.getItem(0)).assertionId,
				"assertion 1");
	        assertEquals(((lasso.SamlAssertion) assertions.getItem(1)).assertionId,
				"assertion 2");
	        assertEquals(((lasso.SamlAssertion) assertions.getItem(2)).assertionId,
				"assertion 3");
	        response.assertion = assertions;
	        assertEquals(((lasso.SamlAssertion) response.assertion.getItem(0)).assertionId,
				"assertion 1");
	        assertEquals(((lasso.SamlAssertion) response.assertion.getItem(1)).assertionId,
				"assertion 2");
	        assertEquals(((lasso.SamlAssertion) response.assertion.getItem(2)).assertionId,
				"assertion 3");
	        assertEquals(((lasso.SamlAssertion) assertions.getItem(0)).assertionId,
				"assertion 1");
	        assertEquals(((lasso.SamlAssertion) assertions.getItem(1)).assertionId,
				"assertion 2");
	        assertEquals(((lasso.SamlAssertion) assertions.getItem(2)).assertionId,
				"assertion 3");
	        assertions = null;;
	        assertEquals(((lasso.SamlAssertion) response.assertion.getItem(0)).assertionId,
				"assertion 1");
	        assertEquals(((lasso.SamlAssertion) response.assertion.getItem(1)).assertionId,
				"assertion 2");
	        assertEquals(((lasso.SamlAssertion) response.assertion.getItem(2)).assertionId,
				"assertion 3");
	        assertions = response.assertion;
	        assertEquals(((lasso.SamlAssertion) assertions.getItem(0)).assertionId,
				"assertion 1");
	        assertEquals(((lasso.SamlAssertion) assertions.getItem(1)).assertionId,
				"assertion 2");
	        assertEquals(((lasso.SamlAssertion) assertions.getItem(2)).assertionId,
				"assertion 3");
	        assertions = null;
	        assertEquals(((lasso.SamlAssertion) response.assertion.getItem(0)).assertionId,
				"assertion 1");
	        assertEquals(((lasso.SamlAssertion) response.assertion.getItem(1)).assertionId,
				"assertion 2");
	        assertEquals(((lasso.SamlAssertion) response.assertion.getItem(2)).assertionId,
				"assertion 3");
	        response.assertion = null;
	        assertNull(response.assertion);

		response = null;

		Console.WriteLine(".. OK");
	}

	static void test05() {
		Console.Write("Get & set attributes of nodes of type XML list.");

		lasso.LibAuthnRequest authnRequest = new lasso.LibAuthnRequest();

		assertNull(authnRequest.extension);

	        String actionString1 = "<lib:Extension xmlns:lib=\"urn:liberty:iff:2003-08\">\n"
			+ "  <action>do 1</action>\n"
			+ "</lib:Extension>";
	        String actionString2 = "<lib:Extension xmlns:lib=\"urn:liberty:iff:2003-08\">\n"
			+ "  <action>do 2</action>\n"
			+ "</lib:Extension>";
	        String actionString3 = "<lib:Extension xmlns:lib=\"urn:liberty:iff:2003-08\">\n"
			+ "  <action>do 3</action>\n"
			+ "</lib:Extension>";
		lasso.StringList extension = new lasso.StringList();
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
		authnRequest.extension = extension;
		assertEquals(authnRequest.extension.getItem(0), actionString1);
		assertEquals(authnRequest.extension.getItem(1), actionString2);
		assertEquals(authnRequest.extension.getItem(2), actionString3);
		assertEquals(extension.getItem(0), actionString1);
		assertEquals(extension.getItem(1), actionString2);
		assertEquals(extension.getItem(2), actionString3);
		extension = null;
		assertEquals(authnRequest.extension.getItem(0), actionString1);
		assertEquals(authnRequest.extension.getItem(1), actionString2);
		assertEquals(authnRequest.extension.getItem(2), actionString3);
		extension = authnRequest.extension;
		assertEquals(extension.getItem(0), actionString1);
		assertEquals(extension.getItem(1), actionString2);
		assertEquals(extension.getItem(2), actionString3);
		extension = null;
		assertEquals(authnRequest.extension.getItem(0), actionString1);
		assertEquals(authnRequest.extension.getItem(1), actionString2);
		assertEquals(authnRequest.extension.getItem(2), actionString3);
		authnRequest.extension = null;
		assertNull(authnRequest.extension);

		authnRequest = null;

		Console.WriteLine(".. OK");
	}

	static void test06() {
		Console.Write("Get & set attributes of nodes of type node.");

	        lasso.Login login = new lasso.Login(new lasso.Server(null, null, null, null));

	        assertNull(login.request);
	        login.request = (lasso.SamlpRequestAbstract) new lasso.LibAuthnRequest();
	        ((lasso.LibAuthnRequest) login.request).consent = lasso.lasso.libConsentObtained;
	        assertEquals(((lasso.LibAuthnRequest) login.request).consent,
			 lasso.lasso.libConsentObtained);
	        login.request = null;
	        assertNull(login.request);
	
	        login = null;

		Console.WriteLine(".. OK");
	}
}
