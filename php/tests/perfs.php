#! /usr/bin/env php
<?php
#
# $Id$
#
# PHP performance tests for Lasso library
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

function create_authnresponse($query)
{

    $server = new LassoServer(
                    "../../tests/data/idp1-la/metadata.xml",
                    "../../tests/data/idp1-la/private-key-raw.pem",
                    NULL,
                    "../../tests/data/idp1-la/certificate.pem");

    $server->addProvider(LASSO_PROVIDER_ROLE_SP,
                    "../../tests/data/sp1-la/metadata.xml",
                    "../../tests/data/sp1-la/public-key.pem",
                    "../../tests/data/ca1-la/certificate.pem");

    $login = new LassoLogin($server);

    $login->processAuthnRequestMsg(substr(strstr($query, "?"),1));
    $login->validateRequestMsg(1, 1);
    $login->buildAssertion(LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD,
                    "later", "reauthnonorafter", "notbefore", "notonorafter");
    $login->buildAuthnResponseMsg();

    return $login->msgBody;
}

lasso_init();

$server = new LassoServer(
                "../../tests/data/sp1-la/metadata.xml",
                "../../tests/data/sp1-la/private-key-raw.pem",
                NULL,
                "../../tests/data/sp1-la/certificate.pem");

$server->addProvider(LASSO_PROVIDER_ROLE_IDP,
                "../../tests/data/idp1-la/metadata.xml",
                "../../tests/data/idp1-la/public-key.pem",
                "../../tests/data/ca1-la/certificate.pem");

$login = new LassoLogin($server);

printf("Generating 50 AuthnRequest...\n");
for ($i=0; $i < 50; $i++) {
    $login->initAuthnRequest("https://idp1/metadata", LASSO_HTTP_METHOD_REDIRECT);

    $request = $login->request;
    $request->ForceAuthn = true;
    $request->IsPassive = false;
    $request->NameIDPolicy = LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED;
    $request->ProtocolProfile = LASSO_LIB_PROTOCOL_PROFILE_BRWS_POST;
    $login->buildAuthnRequestMsg();
}

$query = $login->msgUrl;
$authn_response_msg = create_authnresponse($query);

printf("Processing 50 AuthnResponse...\n");
for ($i=0; $i < 50; $i++) {
    $login->processAuthnResponseMsg($authn_response_msg);
    $login->acceptSso();
}

?>
