#! /usr/bin/php
<?php

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
    printf("%s\n", $login->msgUrl);
}

$query = $login->msgUrl;
print $query;
$authn_response_msg = create_authnresponse($query);

printf("Processing 50 AuthnResponse...\n");
for ($i=0; $i < 50; $i++) {
    $login->processAuthnResponseMsg($authn_response_msg);
    $login->acceptSso();
}

?>
