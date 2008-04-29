#! /usr/bin/env php
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

require("../lasso.php");

define("DATA_DIR", "../../../tests/data/");

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
    echo "Get and set a list of xmlNode*...";

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
    echo "Get and set a list of Lasso objects...";

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


lasso_init();
test01();
test02();
test03();
test04();
//test05();
lasso_shutdown();

