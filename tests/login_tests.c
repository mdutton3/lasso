/*
 * Lasso library C unit tests
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Author: Emmanuel Raviart <eraviart@entrouvert.com>
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

#include <stdlib.h>
#include <string.h>

#include <check.h>

#include <lasso/lasso.h>


static char*
generateIdentityProviderContextDump()
{
	LassoServer *serverContext;
	
	serverContext = lasso_server_new(
			"../tests/data/idp1-la/metadata.xml",
			NULL, /* "../tests/data/idp1-la/public-key.pem" is no more used */
			"../tests/data/idp1-la/private-key-raw.pem",
			"../tests/data/idp1-la/certificate.pem",
			lassoSignatureMethodRsaSha1);
	lasso_server_add_provider(
			serverContext,
			"../tests/data/sp1-la/metadata.xml",
			"../tests/data/sp1-la/public-key.pem",
			"../tests/data/ca1-la/certificate.pem");
	return lasso_server_dump(serverContext);
}

static char*
generateServiceProviderContextDump()
{
	LassoServer *serverContext;
	
	serverContext = lasso_server_new(
			"../tests/data/sp1-la/metadata.xml",
			NULL, /* "../tests/data/sp1-la/public-key.pem" is no more used */
			"../tests/data/sp1-la/private-key-raw.pem",
			"../tests/data/sp1-la/certificate.pem",
			lassoSignatureMethodRsaSha1);
	lasso_server_add_provider(
			serverContext,
			"../tests/data/idp1-la/metadata.xml",
			"../tests/data/idp1-la/public-key.pem",
			"../tests/data/ca1-la/certificate.pem");
	return lasso_server_dump(serverContext);
}


START_TEST(test01_generateServersContextDumps)
{
	char *identityProviderContextDump;
	char *serviceProviderContextDump; 

	identityProviderContextDump = generateIdentityProviderContextDump();
	fail_unless(identityProviderContextDump != NULL,
			"generateIdentityProviderContextDump should not return NULL");
	serviceProviderContextDump = generateServiceProviderContextDump();
	fail_unless(serviceProviderContextDump != NULL,
			"generateServiceProviderContextDump should not return NULL");
}
END_TEST

START_TEST(test02_serviceProviderLogin)
{
	char *serviceProviderContextDump, *identityProviderContextDump;
	LassoServer *spContext, *idpContext;
	LassoLogin *spLoginContext, *idpLoginContext;
	LassoLogout *spLogoutContext, *idpLogoutContext;
	LassoLibAuthnRequest *request;
	int rc;
	char *relayState;
	char *authnRequestUrl, *authnRequestQuery;
	char *responseUrl, *responseQuery;
	char *idpIdentityContextDump;
	char *soapResponseMsg;
	char *spIdentityContextDump, *spIdentityContextDumpTemp;
	int requestType;

	serviceProviderContextDump = generateServiceProviderContextDump();
	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new(spContext);
	fail_unless(spLoginContext != NULL,
			"lasso_login_new() shouldn't have returned NULL");
	rc = lasso_login_init_authn_request(spLoginContext);
	fail_unless(rc == 0, "lasso_login_init_authn_request failed");
	fail_unless(LASSO_PROFILE(spLoginContext)->request_type == \
			lassoMessageTypeAuthnRequest, "request_type should be AuthnRequest");
	request = LASSO_LIB_AUTHN_REQUEST(
			LASSO_PROFILE(spLoginContext)->request);
	lasso_lib_authn_request_set_isPassive(request, 0);
	lasso_lib_authn_request_set_nameIDPolicy(request, lassoLibNameIDPolicyTypeFederated);
	lasso_lib_authn_request_set_consent(request, lassoLibConsentObtained);
	relayState = "fake";
	lasso_lib_authn_request_set_relayState(request, "fake");
	rc = lasso_login_build_authn_request_msg(spLoginContext, "https://idp1/metadata");
	fail_unless(rc == 0, "lasso_login_build_authn_request_msg failed");
	authnRequestUrl = LASSO_PROFILE(spLoginContext)->msg_url;
	fail_unless(authnRequestUrl != NULL,
			"authnRequestUrl shouldn't be NULL");
	authnRequestQuery = strchr(authnRequestUrl, '?')+1;
	fail_unless(strlen(authnRequestQuery) > 0,
			"authnRequestRequest shouldn't be an empty string");

        /* Identity provider singleSignOn, for a user having no federation. */
	identityProviderContextDump = generateIdentityProviderContextDump();
	idpContext = lasso_server_new_from_dump(identityProviderContextDump);
	idpLoginContext = lasso_login_new(idpContext);
	fail_unless(idpLoginContext != NULL,
			"lasso_login_new() shouldn't have returned NULL");
	rc = lasso_login_init_from_authn_request_msg(idpLoginContext,
			authnRequestQuery, lassoHttpMethodRedirect);
	fail_unless(rc == 0, "lasso_login_init_from_authn_request_msg failed");
	fail_unless(lasso_login_must_authenticate(idpLoginContext),
			"lasso_login_must_authenticate() should be TRUE");
	fail_unless(idpLoginContext->protocolProfile == lassoLoginProtocolProfileBrwsArt,
			"protocoleProfile should be ProfileBrwsArt");
	rc = lasso_login_build_artifact_msg(idpLoginContext,
			1,
			lassoSamlAuthenticationMethodPassword,
			"FIXME: reauthenticateOnOrAfter",
			lassoHttpMethodRedirect);
	fail_unless(rc == 0, "lasso_login_build_artifact_msg failed");

	idpIdentityContextDump = lasso_identity_dump(LASSO_PROFILE(idpLoginContext)->identity);
	fail_unless(idpIdentityContextDump != NULL,
		    "lasso_identity_dump shouldn't return NULL");
	responseUrl = LASSO_PROFILE(idpLoginContext)->msg_url;
	fail_unless(responseUrl != NULL, "responseUrl shouldn't be NULL");
	responseQuery = strchr(responseUrl, '?')+1;
	fail_unless(strlen(responseQuery) > 0,
			"responseQuery shouldn't be an empty string");
	soapResponseMsg = idpLoginContext->response_dump;

        /* Service provider assertion consumer */
	lasso_server_destroy(spContext);
	lasso_login_destroy(spLoginContext);

	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new(spContext);
	rc = lasso_login_init_request(spLoginContext,
			responseQuery,
			lassoHttpMethodRedirect);
	fail_unless(rc == 0, "lasso_login_init_request failed");
	rc = lasso_login_build_request_msg(spLoginContext);
	fail_unless(rc == 0, "lasso_login_build_request_msg failed");

	/* Identity provider SOAP endpoint */
	requestType = lasso_profile_get_request_type_from_soap_msg(
			LASSO_PROFILE(spLoginContext)->msg_body);
	fail_unless(requestType == lassoRequestTypeLogin,
			"requestType should be lassoRequestTypeLogin");
	
        /* Service provider assertion consumer (step 2: process SOAP response) */
	rc = lasso_login_process_response_msg(spLoginContext, soapResponseMsg);
	fail_unless(rc == 0, "lasso_login_process_request_msg failed");
	fail_unless(strcmp(LASSO_PROFILE(spLoginContext)->nameIdentifier,
        	LASSO_PROFILE(idpLoginContext)->nameIdentifier) == 0,
		"nameIdentifiers should be identical");
	rc = lasso_login_accept_sso(spLoginContext);
	fail_unless(rc == 0, "lasso_login_accept_sso failed");
	fail_unless(LASSO_PROFILE(spLoginContext)->identity != NULL,
			"spLoginContext has no identity");
	spIdentityContextDump = lasso_identity_dump(LASSO_PROFILE(spLoginContext)->identity);
	fail_unless(spIdentityContextDump != NULL, "lasso_identity_dump failed");

	/* Service provider logout */
	lasso_server_destroy(spContext);
	lasso_login_destroy(spLoginContext);

	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLogoutContext = lasso_logout_new(spContext, lassoProviderTypeSp);
	lasso_profile_set_identity_from_dump(LASSO_PROFILE(spLogoutContext),
						 spIdentityContextDump);
	fail_unless(spLogoutContext != NULL, "spLogoutContext should not be NULL");
	spIdentityContextDump = lasso_identity_dump(LASSO_PROFILE(spLogoutContext)->identity);
	fail_unless(spIdentityContextDump != NULL, "spIdentityContextDump should not be NULL");
	rc = lasso_logout_init_request(spLogoutContext, NULL);
	fail_unless(rc == 0, "lasso_logout_init_request failed");
	rc = lasso_logout_build_request_msg(spLogoutContext);
	fail_unless(rc == 0, "lasso_logout_build_request_msg failed");
	spIdentityContextDump = lasso_identity_dump(LASSO_PROFILE(spLogoutContext)->identity);

	/* Identity provider SOAP endpoint */
	lasso_server_destroy(idpContext);

	spIdentityContextDumpTemp = lasso_identity_dump(LASSO_PROFILE(spLogoutContext)->identity);
	fail_unless(spIdentityContextDumpTemp != NULL,
			"spIdentityContextDumpTemp should not be NULL");
	fail_unless(strcmp(spIdentityContextDumpTemp, spIdentityContextDump) == 0,
			"spIdentityContextDumpTemp should not have diverted from spIdentityContextDump");

	requestType = lasso_profile_get_request_type_from_soap_msg(
			LASSO_PROFILE(spLogoutContext)->msg_body);

	idpContext = lasso_server_new_from_dump(identityProviderContextDump);
	idpLogoutContext = lasso_logout_new(idpContext, lassoProviderTypeIdp);
	fail_unless(idpLogoutContext != NULL, "lasso_logout_new failed");
	rc = lasso_logout_process_request_msg(
			idpLogoutContext,
			LASSO_PROFILE(spLogoutContext)->msg_body,
			lassoHttpMethodSoap);
	fail_unless(rc == 0, "lasso_logout_process_request_msg failed");
	rc = lasso_profile_set_identity_from_dump(LASSO_PROFILE(idpLogoutContext),
						  idpIdentityContextDump);
	fail_unless(rc == 0, "lasso_profile_set_identity_from_dump failed");
	rc = lasso_logout_validate_request(idpLogoutContext);
	fail_unless(rc == 0, "lasso_logout_process_request failed");
	fail_unless(lasso_logout_get_next_providerID(idpLogoutContext) == NULL,
			"lasso_logout_get_next_providerID failed");
	rc = lasso_logout_build_response_msg(idpLogoutContext);
	fail_unless(rc == 0, "lasso_logout_build_response_msg failed");
	soapResponseMsg = LASSO_PROFILE(idpLogoutContext)->msg_body;

	/* Service provider logout (step 2: process SOAP response) */
	rc = lasso_logout_process_response_msg(spLogoutContext,
			soapResponseMsg, lassoHttpMethodSoap);
	fail_unless(rc == 0, "lasso_logout_process_response_msg failed");
	spIdentityContextDump = lasso_identity_dump(LASSO_PROFILE(spLogoutContext)->identity);
	fail_unless(spIdentityContextDump != NULL, "lasso_identity_dump failed");

}
END_TEST

Suite*
login_suite()
{
	Suite *s = suite_create("Login");
	TCase *tc_generate = tcase_create("Generate Server Contexts");
	TCase *tc_spLogin = tcase_create("Login initiated by service provider");
	suite_add_tcase(s, tc_generate);
	suite_add_tcase(s, tc_spLogin);
	tcase_add_test(tc_generate, test01_generateServersContextDumps);
	tcase_add_test(tc_spLogin, test02_serviceProviderLogin);
	return s;
}

