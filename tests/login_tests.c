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


char*
generateIdentityProviderContextDump()
{
	LassoServer *serverContext;
	
	serverContext = lasso_server_new(
			"../examples/data/idp-metadata.xml",
			"../examples/data/idp-public-key.pem",
			"../examples/data/idp-private-key.pem",
			"../examples/data/idp-crt.pem",
			lassoSignatureMethodRsaSha1);
	lasso_server_add_provider(
			serverContext,
			"../examples/data/sp-metadata.xml",
			"../examples/data/sp-public-key.pem",
			"../examples/data/ca-crt.pem");
	return lasso_server_dump(serverContext);
}

char*
generateServiceProviderContextDump()
{
	LassoServer *serverContext;
	
	serverContext = lasso_server_new(
			"../examples/data/sp-metadata.xml",
			"../examples/data/sp-public-key.pem",
			"../examples/data/sp-private-key.pem",
			"../examples/data/sp-crt.pem",
			lassoSignatureMethodRsaSha1);
	lasso_server_add_provider(
			serverContext,
			"../examples/data/idp-metadata.xml",
			"../examples/data/idp-public-key.pem",
			"../examples/data/ca-crt.pem");
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
	LassoUser *spUserContext;
	LassoLibAuthnRequest *request;
	int rc;
	char *relayState;
	char *authnRequestUrl, *authnRequestQuery;
	char *responseUrl, *responseQuery;
	char *idpUserContextDump;
	char *soapResponseMsg;
	char *spUserContextDump;
	int requestType;

	serviceProviderContextDump = generateServiceProviderContextDump();
	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new(spContext, NULL);
	fail_unless(spLoginContext != NULL,
			"lasso_login_new() shouldn't have returned NULL");
	rc = lasso_login_init_authn_request(spLoginContext,
			"https://identity-provider:1998/liberty-alliance/metadata");
	fail_unless(rc == 0, "lasso_login_init_authn_request failed");
	fail_unless(LASSO_PROFILE_CONTEXT(spLoginContext)->request_type == \
			lassoMessageTypeAuthnRequest, "request_type should be AuthnRequest");
	request = LASSO_LIB_AUTHN_REQUEST(
			LASSO_PROFILE_CONTEXT(spLoginContext)->request);
	lasso_lib_authn_request_set_isPassive(request, 0);
	lasso_lib_authn_request_set_nameIDPolicy(request, lassoLibNameIDPolicyTypeFederated);
	lasso_lib_authn_request_set_consent(request, lassoLibConsentObtained);
	relayState = "fake";
	lasso_lib_authn_request_set_relayState(request, "fake");
	rc = lasso_login_build_authn_request_msg(spLoginContext);
	fail_unless(rc == 0, "lasso_login_build_authn_request_msg failed");
	authnRequestUrl = LASSO_PROFILE_CONTEXT(spLoginContext)->msg_url;
	fail_unless(authnRequestUrl != NULL,
			"authnRequestUrl shouldn't be NULL");
	authnRequestQuery = strchr(authnRequestUrl, '?')+1;
	fail_unless(strlen(authnRequestQuery) > 0,
			"authnRequestRequest shouldn't be an empty string");

        /* Identity provider singleSignOn, for a user having no federation. */
	identityProviderContextDump = generateIdentityProviderContextDump();
	idpContext = lasso_server_new_from_dump(identityProviderContextDump);
	idpLoginContext = lasso_login_new(idpContext, NULL);
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

	idpUserContextDump = lasso_user_dump(LASSO_PROFILE_CONTEXT(idpLoginContext)->user);
	fail_unless(idpUserContextDump != NULL,
			"lasso_user_dump shouldn't return NULL");
	responseUrl = LASSO_PROFILE_CONTEXT(idpLoginContext)->msg_url;
	fail_unless(responseUrl != NULL, "responseUrl shouldn't be NULL");
	responseQuery = strchr(responseUrl, '?')+1;
	fail_unless(strlen(responseQuery) > 0,
			"responseQuery shouldn't be an empty string");
	soapResponseMsg = idpLoginContext->response_dump;

        /* Service provider assertion consumer */
	lasso_server_destroy(spContext);
	lasso_login_destroy(spLoginContext);

	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new(spContext, NULL);
	rc = lasso_login_init_request(spLoginContext,
			responseQuery,
			lassoHttpMethodRedirect);
	fail_unless(rc == 0, "lasso_login_init_request failed");
	rc = lasso_login_build_request_msg(spLoginContext);
	fail_unless(rc == 0, "lasso_login_build_request_msg failed");

	/* Identity provider SOAP endpoint */
	requestType = lasso_profile_context_get_request_type_from_soap_msg(
			LASSO_PROFILE_CONTEXT(spLoginContext)->msg_body);
	fail_unless(requestType == lassoRequestTypeLogin,
			"requestType should be lassoRequestTypeLogin");
	
        /* Service provider assertion consumer (step 2: process SOAP response) */
	rc = lasso_login_process_response_msg(spLoginContext, soapResponseMsg);
	fail_unless(rc == 0, "lasso_login_process_request_msg failed");
	fail_unless(strcmp(LASSO_PROFILE_CONTEXT(spLoginContext)->nameIdentifier,
        	LASSO_PROFILE_CONTEXT(idpLoginContext)->nameIdentifier) == 0,
		"nameIdentifiers should be identical");
	rc = lasso_login_create_user(spLoginContext, NULL);
	fail_unless(rc == 0, "lasso_login_create_user failed");
	fail_unless(LASSO_PROFILE_CONTEXT(spLoginContext)->user != NULL,
			"spLoginContext has no user");
	spUserContextDump = lasso_user_dump(LASSO_PROFILE_CONTEXT(spLoginContext)->user);
	fail_unless(spUserContextDump != NULL, "lasso_user_dump failed");

	/* Service provider logout */
	lasso_server_destroy(spContext);
	lasso_login_destroy(spLoginContext);

	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spUserContext = lasso_user_new_from_dump(spUserContextDump);
	fail_unless(spUserContext != NULL, "spUserContext should not be NULL");
	spLogoutContext = lasso_logout_new(lassoProviderTypeSp,
			spContext, spUserContext);
	fail_unless(spLogoutContext != NULL, "spLogoutContext should not be NULL");
	rc = lasso_logout_init_request(spLogoutContext, NULL);
	fail_unless(rc == 0, "lasso_logout_init_request failed");
	rc = lasso_logout_build_request_msg(spLogoutContext);
	fail_unless(rc == 0, "lasso_logout_build_request_msg failed");

	/* Identity provider SOAP endpoint */
	lasso_server_destroy(idpContext);
	requestType = lasso_profile_context_get_request_type_from_soap_msg(
			LASSO_PROFILE_CONTEXT(spLogoutContext)->msg_body);
	idpContext = lasso_server_new_from_dump(identityProviderContextDump);
	idpLogoutContext = lasso_logout_new(lassoProviderTypeIdp, idpContext, NULL);
	fail_unless(idpLogoutContext != NULL, "lasso_logout_new failed");
	rc = lasso_logout_load_request_msg(
			idpLogoutContext,
			LASSO_PROFILE_CONTEXT(spLogoutContext)->msg_body,
			lassoHttpMethodSoap);
	fail_unless(rc == 0, "lasso_logout_load_request_msg failed");
	rc = lasso_logout_load_user_dump(idpLogoutContext, idpUserContextDump);
	fail_unless(rc == 0, "lasso_logout_load_user_dump failed");
	rc = lasso_logout_process_request(idpLogoutContext);
	fail_unless(rc == 0, "lasso_logout_process_request failed");
	fail_unless(lasso_logout_get_next_providerID(idpLogoutContext) == NULL,
			"lasso_logout_get_next_providerID failed");
	lasso_logout_build_response_msg(idpLogoutContext);
	soapResponseMsg = LASSO_PROFILE_CONTEXT(idpLogoutContext)->msg_body;

	/* Service provider logout (step 2: process SOAP response) */
	rc = lasso_logout_process_response_msg(spLogoutContext,
			soapResponseMsg, lassoHttpMethodSoap);
	fail_unless(rc == 0, "lasso_logout_process_response_msg failed");
	spUserContextDump = lasso_user_dump(LASSO_PROFILE_CONTEXT(spLogoutContext)->user);
	fail_unless(spUserContextDump != NULL, "lasso_user_dump failed");

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

int
main(int argc, char *argv[])
{
	int rc;
	Suite *s;
	SRunner *sr;
	int i;
	int dont_fork = 0;

	for (i=1; i<argc; i++) {
		if (strcmp(argv[i], "--dontfork") == 0) {
			dont_fork = 1;
		}
	}

	lasso_init();
	
	s = login_suite();
	sr = srunner_create(s);
	if (dont_fork) {
		srunner_set_fork_status(sr, CK_NOFORK);
	}
	srunner_set_xml(sr, "out.xml");
	srunner_run_all (sr, CK_VERBOSE);
	rc = srunner_ntests_failed(sr);
	
	srunner_free(sr);
	/*suite_free(s);*/

	/*lasso_destroy();*/

	return (rc == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

