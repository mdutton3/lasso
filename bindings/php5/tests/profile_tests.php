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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

require("../lasso.php");

define(DATA_DIR, getenv('SRCDIR') . '../../../tests/data/');

function test01() {
    echo "Server construction, dump & newFromDump... ";

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

    $dump = $server->dump();
    assert(! is_null($dump));
    assert($dump != "");
    $server2 = LassoServer::newFromDump($dump);
    $dump2 = $server2->dump();
    assert($dump == $dump2);

    echo "OK.\n";
}

function test02() {
    echo "Server construction with no optional argument, dump & newFromDump... ";

    $server = new LassoServer(DATA_DIR . "sp1-la/metadata.xml");
    $server->addProvider(
        LASSO_PROVIDER_ROLE_IDP,
        DATA_DIR . "idp1-la/metadata.xml",
        DATA_DIR . "idp1-la/public-key.pem",
        DATA_DIR . "idp1-la/certificate.pem");

    $dump = $server->dump();
    $server2 = LassoServer::newFromDump($dump);
    $dump2 = $server2->dump();
    assert($dump == $dump2);

    echo "OK.\n";
}

function test03() {
    echo "SP login; testing access to authentication request... ";

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
    $result = $login->initAuthnRequest();
    assert(! is_null($login->request));
    assert(get_class($login->request) == "LassoLibAuthnRequestNoInit");
    $dump = $login->request->dump();
    $login->request->protocolProfile = LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART;
    assert($login->request->protocolProfile == LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART);
    $dump2 = $login->request->dump();
    assert($dump != $dump2);

    echo "OK.\n";
}

function test04() {
    echo "SP login; testing processing of an empty Response... ";

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
    try {
        $login->processResponseMsg("");
    }
    catch (LassoProfileInvalidMsgError $error) {
    }

    echo "OK.\n";
}

function test05() {
    echo "Conversion of a lib:AuthnRequest with an AuthnContext into a query and back... ";

    $spServer = new LassoServer(
        DATA_DIR . "sp1-la/metadata.xml",
        DATA_DIR . "sp1-la/private-key-raw.pem",
        NULL,
        DATA_DIR . "sp1-la/certificate.pem");
    $spServer->addProvider(
        LASSO_PROVIDER_ROLE_IDP,
        DATA_DIR . "idp1-la/metadata.xml",
        DATA_DIR . "idp1-la/public-key.pem",
        DATA_DIR . "idp1-la/certificate.pem");

    $spLogin = new LassoLogin($spServer);
    $spLogin->initAuthnRequest();
    $requestAuthnContext = new LassoLibRequestAuthnContext();
    $requestAuthnContext->authnContextClassRef = array(LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_PASSWORD);
    assert($requestAuthnContext->authnContextClassRef[0] == LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_PASSWORD);
    $spLogin->request->requestAuthnContext = $requestAuthnContext;
    assert(! is_null($spLogin->request->requestAuthnContext));
    $spLogin->request->protocolProfile = LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART;
    assert($spLogin->request->protocolProfile == LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART);
    $spLogin->buildAuthnRequestMsg();
    assert(! is_null($spLogin->msgUrl));
    assert($spLogin->msgUrl != "");

    $idpServer = new LassoServer(
        DATA_DIR . "idp1-la/metadata.xml",
        DATA_DIR . "idp1-la/private-key-raw.pem",
        NULL,
        DATA_DIR . "idp1-la/certificate.pem");
    $idpServer->addProvider(
        LASSO_PROVIDER_ROLE_IDP,
        DATA_DIR . "sp1-la/metadata.xml",
        DATA_DIR . "sp1-la/public-key.pem",
        DATA_DIR . "sp1-la/certificate.pem");

    $idpLogin = new LassoLogin($idpServer);
    list($urlBase, $authnRequestQuery) = split("\?", $spLogin->msgUrl, 2);
    assert($authnRequestQuery != "");
    $idpLogin->processAuthnRequestMsg($authnRequestQuery);
    assert(! is_null($idpLogin->request));
    assert(! is_null($idpLogin->request->requestAuthnContext));
    assert($idpLogin->request->requestAuthnContext != "");
    assert(sizeof($idpLogin->request->requestAuthnContext->authnContextClassRef) == 1);
    assert($idpLogin->request->requestAuthnContext->authnContextClassRef[0] ==
        LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_PASSWORD);

    echo "OK.\n";
}

function test06() {
    echo "SP logout without session and identity; testing initRequest... ";

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

    $logout = new LassoLogout($server);
    try {
        $logout->initRequest();
        echo "logout.initRequest without having set identity before should fail\n";
        assert(False);
    }
    catch (LassoProfileSessionNotFoundError $error) {
    }

    echo "OK.\n";
}

function test07() {
    echo "IDP logout without session and identity; testing logout.getNextProviderId... ";

    $server = new LassoServer(
        DATA_DIR . "idp1-la/metadata.xml",
        DATA_DIR . "idp1-la/private-key-raw.pem",
        NULL,
        DATA_DIR . "idp1-la/certificate.pem");
    $server->addProvider(
        LASSO_PROVIDER_ROLE_IDP,
        DATA_DIR . "sp1-la/metadata.xml",
        DATA_DIR . "sp1-la/public-key.pem",
        DATA_DIR . "sp1-la/certificate.pem");

    $logout = new LassoLogout($server);
    assert(is_null($logout->next_providerID));

    echo "OK.\n";
}

test01();
test02();
test03();
test04();
test05();
test06();
test07();
