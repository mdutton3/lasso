#! /usr/bin/php
<?php

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
        assert($respondWith->getitem(0) == 'first string');
        assert($respondWith->getitem(0) == 'first string');
        $respondWith->append('second string');
        assert($respondWith->length() == 2);
        assert($respondWith->getitem(0) == 'first string');
        assert($respondWith->getitem(1) == 'second string');
        $respondWith->append('third string');
        assert($respondWith->length() == 3);
        assert($respondWith->getitem(0) == 'first string');
        assert($respondWith->getitem(1) == 'second string');
        assert($respondWith->getitem(2) == 'third string');
        $authnRequest->RespondWith = $respondWith;
	# $authnRequest->RespondWith->getitem(0) doesnt work. It raises:
	# Fatal error: Class 'lassolibauthnrequest' does not support overloaded method calls
	$authnRequestRespondWith = $authnRequest->RespondWith;
        assert($authnRequestRespondWith->getitem(0) == 'first string');
        assert($authnRequestRespondWith->getitem(1) == 'second string');
        assert($authnRequestRespondWith->getitem(2) == 'third string');
        assert($respondWith->getitem(0) == 'first string');
        assert($respondWith->getitem(1) == 'second string');
        assert($respondWith->getitem(2) == 'third string');
        $respondWith = NULL;
        assert($authnRequestRespondWith->getitem(0) == 'first string');
        assert($authnRequestRespondWith->getitem(1) == 'second string');
        assert($authnRequestRespondWith->getitem(2) == 'third string');
        $respondWith = $authnRequest->RespondWith;
        assert($respondWith->getitem(0) == 'first string');
        assert($respondWith->getitem(1) == 'second string');
        assert($respondWith->getitem(2) == 'third string');
        $respondWith = NULL;
        assert($authnRequestRespondWith->getitem(0) == 'first string');
        assert($authnRequestRespondWith->getitem(1) == 'second string');
        assert($authnRequestRespondWith->getitem(2) == 'third string');
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
	$assertionsItem0 = $assertions->getitem(0);
        assert($assertionsItem0->AssertionID == 'assertion 1');
	$assertionsItem0 = $assertions->getitem(0);
        assert($assertionsItem0->AssertionID == 'assertion 1');
        $assertion2 = new LassoSamlAssertion();
        $assertion2->AssertionID = 'assertion 2';
        $assertions->append($assertion2);
        assert($assertions->length() == 2);
	$assertionsItem0 = $assertions->getitem(0);
        assert($assertionsItem0->AssertionID == 'assertion 1');
	$assertionsItem1 = $assertions->getitem(1);
        assert($assertionsItem1->AssertionID == 'assertion 2');
        $assertion3 = new LassoSamlAssertion();
        $assertion3->AssertionID = 'assertion 3';
        $assertions->append($assertion3);
        assert($assertions->length() == 3);
	$assertionsItem0 = $assertions->getitem(0);
        assert($assertionsItem0->AssertionID == 'assertion 1');
	$assertionsItem1 = $assertions->getitem(1);
        assert($assertionsItem1->AssertionID == 'assertion 2');
	$assertionsItem2 = $assertions->getitem(2);
        assert($assertionsItem2->AssertionID == 'assertion 3');
        $response->assertion = $assertions;
	$responseAssertion = $response->assertion;
	$responseAssertionItem0 = $responseAssertion->getitem(0);
        assert($responseAssertionItem0->AssertionID == 'assertion 1');
	$responseAssertion = $response->assertion;
	$responseAssertionItem1 = $responseAssertion->getitem(1);
        assert($responseAssertionItem1->AssertionID == 'assertion 2');
	$responseAssertion = $response->assertion;
	$responseAssertionItem2 = $responseAssertion->getitem(2);
        assert($responseAssertionItem2->AssertionID == 'assertion 3');
	$assertionsItem0 = $assertions->getitem(0);
        assert($assertionsItem0->AssertionID == 'assertion 1');
	$assertionsItem1 = $assertions->getitem(1);
        assert($assertionsItem1->AssertionID == 'assertion 2');
	$assertionsItem2 = $assertions->getitem(2);
        assert($assertionsItem2->AssertionID == 'assertion 3');
        $assertions = NULL;
	$responseAssertion = $response->assertion;
	$responseAssertionItem0 = $responseAssertion->getitem(0);
        assert($responseAssertionItem0->AssertionID == 'assertion 1');
	$responseAssertion = $response->assertion;
	$responseAssertionItem1 = $responseAssertion->getitem(1);
        assert($responseAssertionItem1->AssertionID == 'assertion 2');
	$responseAssertion = $response->assertion;
	$responseAssertionItem2 = $responseAssertion->getitem(2);
        assert($responseAssertionItem2->AssertionID == 'assertion 3');
        $assertions = $response->assertion;
	$assertionsItem0 = $assertions->getitem(0);
        assert($assertionsItem0->AssertionID == 'assertion 1');
	$assertionsItem1 = $assertions->getitem(1);
        assert($assertionsItem1->AssertionID == 'assertion 2');
	$assertionsItem2 = $assertions->getitem(2);
        assert($assertionsItem2->AssertionID == 'assertion 3');
        $assertions = NULL;
	$responseAssertion = $response->assertion;
	$responseAssertionItem0 = $responseAssertion->getitem(0);
        assert($responseAssertionItem0->AssertionID == 'assertion 1');
	$responseAssertion = $response->assertion;
	$responseAssertionItem1 = $responseAssertion->getitem(1);
        assert($responseAssertionItem1->AssertionID == 'assertion 2');
	$responseAssertion = $response->assertion;
	$responseAssertionItem2 = $responseAssertion->getitem(2);
        assert($responseAssertionItem2->AssertionID == 'assertion 3');
        $response->assertion = NULL;
        assert($response->assertion == NULL);

	$response = NULL;

	print ".. OK\n";
}

lasso_init();
test01();
test02();
test03();
test04();
lasso_shutdown();

?>
