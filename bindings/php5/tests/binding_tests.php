#!/usr/bin/php
<?php
# Lasso - A free implementation of the Liberty Alliance specifications.
# 
# Copyright (C) 2004-2007 Entr'ouvert
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
# along with this program; if not, see <http://www.gnu.org/licenses/>.

require("../lasso.php");

define("DATA_DIR", getenv("SRCDIR") . "../../../tests/data/");

function test01() {
    echo "Get an xmlNode* from a Lasso function... ";

    $organisation_string = '<Organization xmlns="urn:liberty:metadata:2003-08">
  <OrganizationName>Name of the organization</OrganizationName>
 </Organization>';

    $server = new LassoServer(
        DATA_DIR . "sp1-la/metadata.xml",
        DATA_DIR . "sp1-la/private-key-raw.pem",
        NULL,
        DATA_DIR . "sp1-la/certificate.pem");
    assert(!is_null($server->organization));
    assert($server->organization == $organisation_string);

    echo "OK.\n";
}

function test02() {
    echo "Get and set a list of strings... ";

    $requestAuthnContext = new LassoLibRequestAuthnContext();
    $requestAuthnContext->authnContextClassRef = array(LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_PASSWORD);
    assert(! is_null($requestAuthnContext->authnContextClassRef));
    assert(sizeof($requestAuthnContext->authnContextClassRef) == 1);
    assert($requestAuthnContext->authnContextClassRef[0] == LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_PASSWORD);

    echo "OK.\n";
}

function test03() {
    echo "Get and set a list of xmlNode*... ";

    $server = new LassoServer(
        DATA_DIR . "sp1-la/metadata.xml",
        DATA_DIR . "sp1-la/private-key-raw.pem",
        NULL,
        DATA_DIR . "sp1-la/certificate.pem");
    $server->addProvider(
        LASSO_PROVIDER_ROLE_IDP,
        DATA_DIR . "idp1-la/metadata.xml",
        DATA_DIR . "idp1-la/public-key.pem",
        DATA_DIR . "idp1-la/certificate.pem");
    $login = new LassoLogin($server);
    $login->initAuthnRequest();
    $requestAuthnContext = new LassoLibRequestAuthnContext();
    $extension1 = '<lib:Extension xmlns:lib="urn:liberty:iff:2003-08">
    <action>do</action>
</lib:Extension>';
	$extension2 = '<lib:Extension xmlns:lib="urn:liberty:iff:2003-08">
    <action2>do action 2</action2><action3>do action 3</action3>
</lib:Extension>';
    $extensionList = array($extension1, $extension2);
    $login->request->extension = $extensionList;
    assert($login->request->extension == $extensionList);
    assert($login->request->extension[0] == $extension1);
    assert($login->request->extension[1] == $extension2);

    echo "OK.\n";
}

function test04() {
    echo "Get and set a list of Lasso objects... ";

    $response = new LassoSamlpResponse();
    assert(!$response->assertion);

    $assertions = array();
    $assertion1 = new LassoSamlAssertion();
    $assertion1->assertionId = "assertion 1";
    $assertions[] = $assertion1;
    assert($assertions[0]->assertionId == "assertion 1");
    $assertion2 = new LassoSamlAssertion();
    $assertion2->assertionId = "assertion 2";
    $assertions[] = $assertion2;
    $response->assertion = $assertions;
    assert($response->assertion[0]->assertionId == "assertion 1");
    assert($response->assertion[1]->assertionId == "assertion 2");
    unset($assertions);
    assert($response->assertion[0]->assertionId == "assertion 1");
    assert($response->assertion[1]->assertionId == "assertion 2");
    $assertions = $response->assertion;
    assert($assertions[0]->assertionId == "assertion 1");
    assert($assertions[1]->assertionId == "assertion 2");

    echo "OK.\n";
}

function test05() {
    echo "Get and set a hashtable of objects... ";

    $server = new LassoServer(
        DATA_DIR . "sp1-la/metadata.xml",
        DATA_DIR . "sp1-la/private-key-raw.pem",
        NULL,
        DATA_DIR . "sp1-la/certificate.pem");
    $server->addProvider(
        LASSO_PROVIDER_ROLE_IDP,
        DATA_DIR . "idp1-la/metadata.xml",
        DATA_DIR . "idp1-la/public-key.pem",
        DATA_DIR . "idp1-la/certificate.pem");
    assert(!is_null($server->providers));
    assert($server->providers["https://idp1/metadata"]->providerId == "https://idp1/metadata");
    assert($server->providers["https://idp1/metadata"]->providerId == "https://idp1/metadata");
    $tmp_providers = $server->providers;
    $server->providers = NULL;
    assert(!$server->providers);
    $server->providers = $tmp_providers;
    $provider = $server->providers["https://idp1/metadata"];
    assert($server->providers["https://idp1/metadata"]->providerId == "https://idp1/metadata");

    echo "OK.\n";
}

function test06() {
    echo "Get and set SAML 2.0 assertion attribute values... ";

    $attribute1_name = "first attribute";
    $attribute1_string = "first string";
    $attribute2_name = "second attribute";
    $attribute2_string = "second string";
    $attribute3_string = "third string";

    $expected_assertion_dump = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" SignType="0" SignMethod="0" EncryptionActivated="false" EncryptionSymKeyType="0"><saml:AttributeStatement><saml:Attribute Name="first attribute"><saml:AttributeValue><XXX>first string</XXX></saml:AttributeValue></saml:Attribute><saml:Attribute Name="second attribute"><saml:AttributeValue><XXX>second string</XXX></saml:AttributeValue><saml:AttributeValue><XXX>third string</XXX></saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>';

    $text_node1 = new LassoMiscTextNode();
    $text_node1->content = $attribute1_string;
    $any1 = array();
    $any1[] = $text_node1;
    $attribute_value1 = new LassoSaml2AttributeValue();
    $attribute_value1->any = $any1;
    $attribute_values1 = array();
    $attribute_values1[] = $attribute_value1;
    $attribute1 = new LassoSaml2Attribute();
    $attribute1->name = $attribute1_name;
    $attribute1->attributeValue = $attribute_values1;

    $text_node2 = new LassoMiscTextNode();
    $text_node2->content = $attribute2_string;
    $any2 = array();
    $any2[] = $text_node2;
    $attribute_value2 = new LassoSaml2AttributeValue();
    $attribute_value2->any = $any2;

    $text_node3 = new LassoMiscTextNode();
    $text_node3->content = $attribute3_string;
    $any3 = array();
    $any3[] = $text_node3;
    $attribute_value3 = new LassoSaml2AttributeValue();
    $attribute_value3->any = $any3;

    $attribute_values2 = array();
    $attribute_values2[] = $attribute_value2;
    $attribute_values2[] = $attribute_value3;

    $attribute2 = new LassoSaml2Attribute();
    $attribute2->name = $attribute2_name;
    $attribute2->attributeValue = $attribute_values2;

    $attributes = array();
    $attributes[] = $attribute1;
    $attributes[] = $attribute2;

    $attributeStatement = new LassoSaml2AttributeStatement();
    $attributeStatement->attribute = $attributes;
    $attributeStatements = array();
    $attributeStatements[] = $attributeStatement;

    $assertion = new LassoSaml2Assertion();
    $assertion->attributeStatement = $attributeStatements;

    assert($assertion->dump() == $expected_assertion_dump);

    echo "OK.\n";
}

lasso_init();
test01();
test02();
test03();
test04();
//test05();
test06();
lasso_shutdown();

