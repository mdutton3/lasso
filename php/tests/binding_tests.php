#! /usr/bin/env php
<?php
# $Id$
#
# PHP unit tests for Lasso library
#
 * Copyright (C) 2004-2007 Entr'ouvert
# http://lasso.entrouvert.org
#
# Authors: See AUTHORS file in top-level directory.
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


$ret = @dl('lasso.' . PHP_SHLIB_SUFFIX);
if ($ret == FALSE) {
    print "lasso not found\n";
    exit(1);
}

function test01()
{
        print "Create and delete nodes.";

        $authnRequest = new LassoLibAuthnRequest();
	$authnRequest = NULL;

	print ".. OK\n";
}

function test02()
{
        print "Get & set simple attributes of nodes.";

        $authnRequest = new LassoLibAuthnRequest();

        # Test a string attribute.
        assert($authnRequest->consent == NULL);
        $authnRequest->consent = LassoLibConsentObtained;
        assert($authnRequest->consent == LassoLibConsentObtained);
	$authnRequest->consent = NULL;
	assert($authnRequest->consent == NULL);

        # Test a renamed string attribute. But renaming doesn't work with current SWIG PHP binding.
        assert($authnRequest->RelayState == NULL);
        $authnRequest->RelayState = 'Hello World!';
        assert($authnRequest->RelayState == 'Hello World!');
	$authnRequest->RelayState = NULL;
	assert($authnRequest->RelayState == NULL);

        # Test an integer attribute.
        assert($authnRequest->majorVersion == 0);
        $authnRequest->majorVersion = 314;
	assert($authnRequest->majorVersion == 314);

	$authnRequest = NULL;

	print ".. OK\n";
}

function test03()
{
 	print "Get & set attributes of nodes of type string list.";

        $authnRequest = new LassoLibAuthnRequest();

        assert($authnRequest->respondWith == NULL);

        $respondWith = new LassoStringList();
        assert($respondWith->length() == 0);
        $respondWith->append('first string');
        assert($respondWith->length() == 1);
        assert($respondWith->getItem(0) == 'first string');
        assert($respondWith->getItem(0) == 'first string');
        $respondWith->append('second string');
        assert($respondWith->length() == 2);
        assert($respondWith->getItem(0) == 'first string');
        assert($respondWith->getItem(1) == 'second string');
        $respondWith->append('third string');
        assert($respondWith->length() == 3);
        assert($respondWith->getItem(0) == 'first string');
        assert($respondWith->getItem(1) == 'second string');
        assert($respondWith->getItem(2) == 'third string');
        $authnRequest->RespondWith = $respondWith;
	# $authnRequest->RespondWith->getItem(0) doesnt work. It raises:
	# Fatal error: Class 'lassolibauthnrequest' does not support overloaded method calls
	$authnRequestRespondWith = $authnRequest->RespondWith;
        assert($authnRequestRespondWith->getItem(0) == 'first string');
        assert($authnRequestRespondWith->getItem(1) == 'second string');
        assert($authnRequestRespondWith->getItem(2) == 'third string');
        assert($respondWith->getItem(0) == 'first string');
        assert($respondWith->getItem(1) == 'second string');
        assert($respondWith->getItem(2) == 'third string');
        $respondWith = NULL;
        assert($authnRequestRespondWith->getItem(0) == 'first string');
        assert($authnRequestRespondWith->getItem(1) == 'second string');
        assert($authnRequestRespondWith->getItem(2) == 'third string');
        $respondWith = $authnRequest->RespondWith;
        assert($respondWith->getItem(0) == 'first string');
        assert($respondWith->getItem(1) == 'second string');
        assert($respondWith->getItem(2) == 'third string');
        $respondWith = NULL;
        assert($authnRequestRespondWith->getItem(0) == 'first string');
        assert($authnRequestRespondWith->getItem(1) == 'second string');
        assert($authnRequestRespondWith->getItem(2) == 'third string');
	$authnRequestRespondWith = NULL;
        $authnRequest->RespondWith = NULL;
	print_r($authnRequest->RespondWith);
        assert($authnRequest->RespondWith == NULL);

	$authnRequest = NULL;

	print ".. OK\n";
}

function test04()
{
 	print "Get & set attributes of nodes of type node list.";

        $response = new LassoSamlpResponse();

	assert($response->assertion == NULL);

        $assertions = new LassoNodeList();
        assert($assertions->length() == 0);
        $assertion1 = new LassoSamlAssertion();
        $assertion1->AssertionID = 'assertion 1';
        $assertions->append($assertion1);
        assert($assertions->length() == 1);
	$assertionsItem0 = $assertions->getItem(0);
        assert($assertionsItem0->AssertionID == 'assertion 1');
	$assertionsItem0 = $assertions->getItem(0);
        assert($assertionsItem0->AssertionID == 'assertion 1');
        $assertion2 = new LassoSamlAssertion();
        $assertion2->AssertionID = 'assertion 2';
        $assertions->append($assertion2);
        assert($assertions->length() == 2);
	$assertionsItem0 = $assertions->getItem(0);
        assert($assertionsItem0->AssertionID == 'assertion 1');
	$assertionsItem1 = $assertions->getItem(1);
        assert($assertionsItem1->AssertionID == 'assertion 2');
        $assertion3 = new LassoSamlAssertion();
        $assertion3->AssertionID = 'assertion 3';
        $assertions->append($assertion3);
        assert($assertions->length() == 3);
	$assertionsItem0 = $assertions->getItem(0);
        assert($assertionsItem0->AssertionID == 'assertion 1');
	$assertionsItem1 = $assertions->getItem(1);
        assert($assertionsItem1->AssertionID == 'assertion 2');
	$assertionsItem2 = $assertions->getItem(2);
        assert($assertionsItem2->AssertionID == 'assertion 3');
        $response->assertion = $assertions;
	$responseAssertion = $response->assertion;
	$responseAssertionItem0 = $responseAssertion->getItem(0);
        assert($responseAssertionItem0->AssertionID == 'assertion 1');
	$responseAssertion = $response->assertion;
	$responseAssertionItem1 = $responseAssertion->getItem(1);
        assert($responseAssertionItem1->AssertionID == 'assertion 2');
	$responseAssertion = $response->assertion;
	$responseAssertionItem2 = $responseAssertion->getItem(2);
        assert($responseAssertionItem2->AssertionID == 'assertion 3');
	$assertionsItem0 = $assertions->getItem(0);
        assert($assertionsItem0->AssertionID == 'assertion 1');
	$assertionsItem1 = $assertions->getItem(1);
        assert($assertionsItem1->AssertionID == 'assertion 2');
	$assertionsItem2 = $assertions->getItem(2);
        assert($assertionsItem2->AssertionID == 'assertion 3');
        $assertions = NULL;
	$responseAssertion = $response->assertion;
	$responseAssertionItem0 = $responseAssertion->getItem(0);
        assert($responseAssertionItem0->AssertionID == 'assertion 1');
	$responseAssertion = $response->assertion;
	$responseAssertionItem1 = $responseAssertion->getItem(1);
        assert($responseAssertionItem1->AssertionID == 'assertion 2');
	$responseAssertion = $response->assertion;
	$responseAssertionItem2 = $responseAssertion->getItem(2);
        assert($responseAssertionItem2->AssertionID == 'assertion 3');
        $assertions = $response->assertion;
	$assertionsItem0 = $assertions->getItem(0);
        assert($assertionsItem0->AssertionID == 'assertion 1');
	$assertionsItem1 = $assertions->getItem(1);
        assert($assertionsItem1->AssertionID == 'assertion 2');
	$assertionsItem2 = $assertions->getItem(2);
        assert($assertionsItem2->AssertionID == 'assertion 3');
        $assertions = NULL;
	$responseAssertion = $response->assertion;
	$responseAssertionItem0 = $responseAssertion->getItem(0);
        assert($responseAssertionItem0->AssertionID == 'assertion 1');
	$responseAssertion = $response->assertion;
	$responseAssertionItem1 = $responseAssertion->getItem(1);
        assert($responseAssertionItem1->AssertionID == 'assertion 2');
	$responseAssertion = $response->assertion;
	$responseAssertionItem2 = $responseAssertion->getItem(2);
        assert($responseAssertionItem2->AssertionID == 'assertion 3');
        $response->assertion = NULL;
        assert($response->assertion == NULL);

	$response = NULL;

	print ".. OK\n";
}

function test05()
{
 	print "Get & set attributes of nodes of type XML list.";

        $authnRequest = new LassoLibAuthnRequest();

        assert($authnRequest->extension == NULL);

        $actionString1 = '<lib:Extension xmlns:lib="urn:liberty:iff:2003-08">
  <action>do 1</action>
</lib:Extension>';
        $actionString2 = '<lib:Extension xmlns:lib="urn:liberty:iff:2003-08">
  <action>do 2</action>
</lib:Extension>';
        $actionString3 = '<lib:Extension xmlns:lib="urn:liberty:iff:2003-08">
  <action>do 3</action>
</lib:Extension>';
        $extension = new LassoStringList();
        assert($extension->length() == 0);
        $extension->append($actionString1);
        assert($extension->length() == 1);
        assert($extension->getItem(0) == $actionString1);
        assert($extension->getItem(0) == $actionString1);
        $extension->append($actionString2);
        assert($extension->length() == 2);
        assert($extension->getItem(0) == $actionString1);
        assert($extension->getItem(1) == $actionString2);
        $extension->append($actionString3);
        assert($extension->length() == 3);
        assert($extension->getItem(0) == $actionString1);
        assert($extension->getItem(1) == $actionString2);
        assert($extension->getItem(2) == $actionString3);
        $authnRequest->extension = $extension;
	# $authnRequest->extension->getItem(0) doesnt work. It raises:
	# Fatal error: Class 'lassolibauthnrequest' does not support overloaded method calls
	$authnRequestExtension = $authnRequest->extension;
        assert($authnRequestExtension->getItem(0) == $actionString1);
        assert($authnRequestExtension->getItem(1) == $actionString2);
        assert($authnRequestExtension->getItem(2) == $actionString3);
        assert($extension->getItem(0) == $actionString1);
        assert($extension->getItem(1) == $actionString2);
        assert($extension->getItem(2) == $actionString3);
        $extension = NULL;
        assert($authnRequestExtension->getItem(0) == $actionString1);
        assert($authnRequestExtension->getItem(1) == $actionString2);
        assert($authnRequestExtension->getItem(2) == $actionString3);
        $extension = $authnRequest->extension;
        assert($extension->getItem(0) == $actionString1);
        assert($extension->getItem(1) == $actionString2);
        assert($extension->getItem(2) == $actionString3);
        $extension = NULL;
        assert($authnRequestExtension->getItem(0) == $actionString1);
        assert($authnRequestExtension->getItem(1) == $actionString2);
        assert($authnRequestExtension->getItem(2) == $actionString3);
	$authnRequestExtension = NULL;
        $authnRequest->extension = NULL;
	print_r($authnRequest->Extension);
        assert($authnRequest->extension == NULL);

	$authnRequest = NULL;

	print ".. OK\n";
}

function test06()
{
 	print "Get & set attributes of nodes of type node.";

	$login = new LassoLogin(new LassoServer());

        assert($login->request == NULL);
        $login->request = new LassoLibAuthnRequest();
	$loginRequest = $login->request;
        $loginRequest->consent = LassoLibConsentObtained;
        assert($loginRequest->consent == LassoLibConsentObtained);
	$loginRequest = $login->request;
        assert($loginRequest->consent == LassoLibConsentObtained);
        $login->request = NULL;
        assert($login->request == NULL);

        $login = NULL;

	print ".. OK\n";
}

lasso_init();
test01();
test02();
test03();
test04();
test05();
test06();
lasso_shutdown();

?>
