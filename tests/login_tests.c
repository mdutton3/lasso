/*
 * Lasso library C unit tests
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: See AUTHORS file in top-level directory.
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

#include <../lasso/lasso.h>
#include <glib.h>
#include "../lasso/utils.h"
#include "../lasso/backward_comp.h"
#include "./tests.h"
#include "../bindings/ghashtable.h"


static char*
generateIdentityProviderContextDump()
{
	LassoServer *serverContext;
	char *ret;

	serverContext = lasso_server_new(
			TESTSDATADIR "/idp1-la/metadata.xml",
			TESTSDATADIR "/idp1-la/private-key-raw.pem",
			NULL, /* Secret key to unlock private key */
			TESTSDATADIR "/idp1-la/certificate.pem");
	check_not_null(serverContext);
	check_good_rc(lasso_server_add_provider(
			serverContext,
			LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp1-la/metadata.xml",
			TESTSDATADIR "/sp1-la/public-key.pem",
			TESTSDATADIR "/ca1-la/certificate.pem"));
	ret = lasso_server_dump(serverContext);
	check_not_null(ret);
	g_object_unref(serverContext);

	return ret;
}

static char*
generateServiceProviderContextDump()
{
	LassoServer *serverContext;
	char *ret;

	serverContext = lasso_server_new(
			TESTSDATADIR "/sp1-la/metadata.xml",
			TESTSDATADIR "/sp1-la/private-key-raw.pem",
			NULL, /* Secret key to unlock private key */
			TESTSDATADIR "/sp1-la/certificate.pem");
	check_not_null(serverContext);
	check_good_rc(lasso_server_add_provider(
			serverContext,
			LASSO_PROVIDER_ROLE_IDP,
			TESTSDATADIR "/idp1-la/metadata.xml",
			TESTSDATADIR "/idp1-la/public-key.pem",
			TESTSDATADIR "/ca1-la/certificate.pem"));

	ret = lasso_server_dump(serverContext);
	check_not_null(ret);
	g_object_unref(serverContext);
	return ret;
}

static char*
generateIdentityProviderContextDumpMemory()
{
	LassoServer *serverContext;
	char *metadata;
	char *private_key;
	char *certificate;
	guint len;
	char *ret;

	g_file_get_contents(TESTSDATADIR "/idp1-la/metadata.xml", &metadata, &len, NULL);
	g_file_get_contents(TESTSDATADIR "/idp1-la/private-key-raw.pem", &private_key, &len, NULL);
	g_file_get_contents(TESTSDATADIR "/idp1-la/certificate.pem", &certificate, &len, NULL);

	serverContext = lasso_server_new_from_buffers(
			metadata,
			private_key,
			NULL, /* Secret key to unlock private key */
			certificate);
	lasso_server_add_provider(
			serverContext,
			LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp1-la/metadata.xml",
			TESTSDATADIR "/sp1-la/public-key.pem",
			TESTSDATADIR "/ca1-la/certificate.pem");
	g_free(metadata);
	g_free(private_key);
	g_free(certificate);
	ret = lasso_server_dump(serverContext);
	g_object_unref(serverContext);
	return ret;
}


START_TEST(test01_generateServersContextDumps)
{
	char *identityProviderContextDump;
	char *serviceProviderContextDump;

	identityProviderContextDump = generateIdentityProviderContextDump();
	fail_unless(identityProviderContextDump != NULL,
			"generateIdentityProviderContextDump should not return NULL");
	g_free(identityProviderContextDump);
	serviceProviderContextDump = generateServiceProviderContextDump();
	fail_unless(serviceProviderContextDump != NULL,
			"generateServiceProviderContextDump should not return NULL");
	g_free(serviceProviderContextDump);
}
END_TEST

START_TEST(test02_serviceProviderLogin)
{
	char *serviceProviderContextDump, *identityProviderContextDump;
	LassoServer *spContext, *idpContext;
	LassoLogin *spLoginContext, *idpLoginContext;
	LassoLibAuthnRequest *request;
	int rc = 0;
	char *relayState;
	char *authnRequestUrl, *authnRequestQuery;
	char *responseUrl, *responseQuery;
	char *idpIdentityContextDump, *idpSessionContextDump;
	char *serviceProviderId, *soapRequestMsg, *soapResponseMsg;
	char *spIdentityContextDump;
	char *spSessionDump;
	char *spLoginDump;
	int requestType;
	char *found;

	serviceProviderContextDump = generateServiceProviderContextDump();
	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new(spContext);
	fail_unless(spLoginContext != NULL,
			"lasso_login_new() shouldn't have returned NULL");
	rc = lasso_login_init_authn_request(spLoginContext, "https://idp1/metadata",
			LASSO_HTTP_METHOD_REDIRECT);
	fail_unless(rc == 0, "lasso_login_init_authn_request failed");
	request = LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(spLoginContext)->request);
	fail_unless(LASSO_IS_LIB_AUTHN_REQUEST(request), "request should be authn_request");
	request->IsPassive = 0;
	request->NameIDPolicy = g_strdup(LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED);
	request->consent = g_strdup(LASSO_LIB_CONSENT_OBTAINED);
	relayState = "fake[]";
	request->RelayState = g_strdup(relayState);
	rc = lasso_login_build_authn_request_msg(spLoginContext);
	fail_unless(rc == 0, "lasso_login_build_authn_request_msg failed");
	authnRequestUrl = LASSO_PROFILE(spLoginContext)->msg_url;
	fail_unless(authnRequestUrl != NULL,
			"authnRequestUrl shouldn't be NULL");
	authnRequestQuery = strchr(authnRequestUrl, '?')+1;
	fail_unless(strlen(authnRequestQuery) > 0,
			"authnRequestQuery shouldn't be an empty string");
	spLoginDump = lasso_node_dump(LASSO_NODE(spLoginContext));
	fail_unless(strstr(authnRequestQuery, "RelayState") != NULL,
			"authnRequestQuery should contain a RelayState parameter");
	fail_unless(strstr(authnRequestQuery, "fake%5B%5D") != NULL,
			"authnRequestQuery RelayState parameter should be encoded");

	/* Identity provider singleSignOn, for a user having no federation. */
	identityProviderContextDump = generateIdentityProviderContextDump();
	idpContext = lasso_server_new_from_dump(identityProviderContextDump);
	idpLoginContext = lasso_login_new(idpContext);
	fail_unless(idpLoginContext != NULL,
			"lasso_login_new() shouldn't have returned NULL");
	rc = lasso_login_process_authn_request_msg(idpLoginContext, authnRequestQuery);
	fail_unless(rc == 0, "lasso_login_process_authn_request_msg failed");
	fail_unless(lasso_login_must_authenticate(idpLoginContext),
			"lasso_login_must_authenticate() should be TRUE");
	fail_unless(idpLoginContext->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART,
			"protocoleProfile should be ProfileBrwsArt");
	fail_unless(! lasso_login_must_ask_for_consent(idpLoginContext),
			"lasso_login_must_ask_for_consent() should be FALSE");
	fail_unless(idpLoginContext->parent.msg_relayState != NULL,
			"lasso_login_process_authn_request_msg should restore the RelayState parameter");
	fail_unless(lasso_strisequal(idpLoginContext->parent.msg_relayState,relayState),
			"lasso_login_process_authn_request_msg should restore the same RelayState thant sent in the request");
	rc = lasso_login_validate_request_msg(idpLoginContext,
			1, /* authentication_result */
		        0 /* is_consent_obtained */
			);

	rc = lasso_login_build_assertion(idpLoginContext,
			LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD,
			"FIXME: authenticationInstant",
			"FIXME: reauthenticateOnOrAfter",
			"FIXME: notBefore",
			"FIXME: notOnOrAfter");
	rc = lasso_login_build_artifact_msg(idpLoginContext, LASSO_HTTP_METHOD_REDIRECT);
	fail_unless(rc == 0, "lasso_login_build_artifact_msg failed");

	idpIdentityContextDump = lasso_identity_dump(LASSO_PROFILE(idpLoginContext)->identity);
	fail_unless(idpIdentityContextDump != NULL,
		    "lasso_identity_dump shouldn't return NULL");
	idpSessionContextDump = lasso_session_dump(LASSO_PROFILE(idpLoginContext)->session);
	fail_unless(idpSessionContextDump != NULL,
		    "lasso_session_dump shouldn't return NULL");
	responseUrl = LASSO_PROFILE(idpLoginContext)->msg_url;
	fail_unless(responseUrl != NULL, "responseUrl shouldn't be NULL");
	responseQuery = strchr(responseUrl, '?')+1;
	fail_unless(strlen(responseQuery) > 0,
			"responseQuery shouldn't be an empty string");
	fail_unless(strstr(responseQuery, "RelayState") != NULL,
			"responseQuery should contain a RelayState parameter");
	fail_unless(strstr(responseQuery, "fake%5B%5D") != NULL,
			"responseQuery RelayState parameter should be encoded");
	serviceProviderId = g_strdup(LASSO_PROFILE(idpLoginContext)->remote_providerID);
	fail_unless(serviceProviderId != NULL,
		    "lasso_profile_get_remote_providerID shouldn't return NULL");

	/* Service provider assertion consumer */
	lasso_server_destroy(spContext);
	lasso_login_destroy(spLoginContext);

	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new_from_dump(spContext, spLoginDump);
	rc = lasso_login_init_request(spLoginContext,
			responseQuery,
			LASSO_HTTP_METHOD_REDIRECT);
	fail_unless(spLoginContext->parent.msg_relayState != NULL,
			"lasso_login_init_request should restore the RelayState parameter");
	fail_unless(lasso_strisequal(spLoginContext->parent.msg_relayState,relayState),
			"lasso_login_init_request should restore the same RelayState thant sent in the request");
	fail_unless(rc == 0, "lasso_login_init_request failed");
	rc = lasso_login_build_request_msg(spLoginContext);
	fail_unless(rc == 0, "lasso_login_build_request_msg failed");
	soapRequestMsg = LASSO_PROFILE(spLoginContext)->msg_body;
	fail_unless(soapRequestMsg != NULL, "soapRequestMsg must not be NULL");

	/* Identity provider SOAP endpoint */
	lasso_server_destroy(idpContext);
	lasso_login_destroy(idpLoginContext);
	requestType = lasso_profile_get_request_type_from_soap_msg(soapRequestMsg);
	fail_unless(requestType == LASSO_REQUEST_TYPE_LOGIN,
			"requestType should be LASSO_REQUEST_TYPE_LOGIN");

	idpContext = lasso_server_new_from_dump(identityProviderContextDump);
	idpLoginContext = lasso_login_new(idpContext);
	rc = lasso_login_process_request_msg(idpLoginContext, soapRequestMsg);
	fail_unless(rc == 0, "lasso_login_process_request_msg failed");

	rc = lasso_profile_set_session_from_dump(LASSO_PROFILE(idpLoginContext),
						 idpSessionContextDump);
	fail_unless(rc == 0, "lasso_login_set_assertion_from_dump failed");
	rc = lasso_login_build_response_msg(idpLoginContext, serviceProviderId);
	fail_unless(rc == 0, "lasso_login_build_response_msg failed");
	soapResponseMsg =  LASSO_PROFILE(idpLoginContext)->msg_body;
	fail_unless(soapResponseMsg != NULL, "soapResponseMsg must not be NULL");

	/* Service provider assertion consumer (step 2: process SOAP response) */
	rc = lasso_login_process_response_msg(spLoginContext, soapResponseMsg);
	fail_unless(rc == 0, "lasso_login_process_response_msg failed");
	rc = lasso_login_accept_sso(spLoginContext);
	fail_unless(rc == 0, "lasso_login_accept_sso failed");
	fail_unless(LASSO_PROFILE(spLoginContext)->identity != NULL,
			"spLoginContext has no identity");
	spIdentityContextDump = lasso_identity_dump(LASSO_PROFILE(spLoginContext)->identity);
	fail_unless(spIdentityContextDump != NULL, "lasso_identity_dump failed");
	spSessionDump = lasso_session_dump(LASSO_PROFILE(spLoginContext)->session);

	/* Test InResponseTo checking */
	found = strstr(soapResponseMsg, "Assertion");
	fail_unless(found != NULL, "We must find an Assertion");
	found = strstr(found, "InResponseTo=\"");
	fail_unless(found != NULL, "We must find an InResponseTo attribute");
	found[sizeof("InResponseTo=\"")] = '?';
	lasso_set_flag("no-verify-signature");
	rc = lasso_login_process_response_msg(spLoginContext, soapResponseMsg);
	lasso_set_flag("verify-signature");
	fail_unless(rc != 0, "lasso_login_process_response_msg must fail");
	rc = lasso_login_accept_sso(spLoginContext);
	fail_unless(rc == 0, "lasso_login_accept_sso must fail");

	g_free(spLoginDump);
	g_free(serviceProviderId);
	g_free(serviceProviderContextDump);
	g_free(identityProviderContextDump);
	g_free(idpSessionContextDump);
	g_free(idpIdentityContextDump);
	g_free(spIdentityContextDump);
	g_free(spSessionDump);
	g_object_unref(spContext);
	g_object_unref(idpContext);
	g_object_unref(spLoginContext);
	g_object_unref(idpLoginContext);
}
END_TEST

START_TEST(test03_serviceProviderLogin)
{
	char *serviceProviderContextDump, *identityProviderContextDump;
	LassoServer *spContext, *idpContext;
	LassoLogin *spLoginContext, *idpLoginContext;
	LassoLibAuthnRequest *request;
	int rc = 0;
	char *relayState;
	char *authnRequestUrl, *authnRequestQuery;
	char *responseUrl, *responseQuery;
	char *idpIdentityContextDump, *idpSessionContextDump;
	char *serviceProviderId, *soapRequestMsg, *soapResponseMsg;
	char *spIdentityContextDump;
	char *spSessionDump;
	int requestType;

	serviceProviderContextDump = generateServiceProviderContextDump();
	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new(spContext);
	fail_unless(spLoginContext != NULL,
			"lasso_login_new() shouldn't have returned NULL");
	rc = lasso_login_init_authn_request(spLoginContext, "https://idp1/metadata",
			LASSO_HTTP_METHOD_REDIRECT);
	fail_unless(rc == 0, "lasso_login_init_authn_request failed");
	request = LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(spLoginContext)->request);
	fail_unless(LASSO_IS_LIB_AUTHN_REQUEST(request), "request should be authn_request");
	request->IsPassive = 0;
	request->NameIDPolicy = g_strdup(LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED);
	request->consent = g_strdup(LASSO_LIB_CONSENT_OBTAINED);
	relayState = "fake";
	request->RelayState = g_strdup(relayState);
	rc = lasso_login_build_authn_request_msg(spLoginContext);
	fail_unless(rc == 0, "lasso_login_build_authn_request_msg failed");
	authnRequestUrl = LASSO_PROFILE(spLoginContext)->msg_url;
	fail_unless(authnRequestUrl != NULL,
			"authnRequestUrl shouldn't be NULL");
	authnRequestQuery = strchr(authnRequestUrl, '?')+1;
	fail_unless(strlen(authnRequestQuery) > 0,
			"authnRequestRequest shouldn't be an empty string");

	/* Identity provider singleSignOn, for a user having no federation. */
	identityProviderContextDump = generateIdentityProviderContextDumpMemory();
	idpContext = lasso_server_new_from_dump(identityProviderContextDump);
	idpLoginContext = lasso_login_new(idpContext);
	fail_unless(idpLoginContext != NULL,
			"lasso_login_new() shouldn't have returned NULL");
	rc = lasso_login_process_authn_request_msg(idpLoginContext, authnRequestQuery);
	fail_unless(rc == 0, "lasso_login_process_authn_request_msg failed");
	fail_unless(lasso_login_must_authenticate(idpLoginContext),
			"lasso_login_must_authenticate() should be TRUE");
	fail_unless(idpLoginContext->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART,
			"protocoleProfile should be ProfileBrwsArt");
	fail_unless(! lasso_login_must_ask_for_consent(idpLoginContext),
			"lasso_login_must_ask_for_consent() should be FALSE");
	rc = lasso_login_validate_request_msg(idpLoginContext,
			1, /* authentication_result */
		        0 /* is_consent_obtained */
			);

	rc = lasso_login_build_assertion(idpLoginContext,
			LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD,
			"FIXME: authenticationInstant",
			"FIXME: reauthenticateOnOrAfter",
			"FIXME: notBefore",
			"FIXME: notOnOrAfter");
	rc = lasso_login_build_artifact_msg(idpLoginContext, LASSO_HTTP_METHOD_REDIRECT);
	fail_unless(rc == 0, "lasso_login_build_artifact_msg failed");

	idpIdentityContextDump = lasso_identity_dump(LASSO_PROFILE(idpLoginContext)->identity);
	fail_unless(idpIdentityContextDump != NULL,
		    "lasso_identity_dump shouldn't return NULL");
	idpSessionContextDump = lasso_session_dump(LASSO_PROFILE(idpLoginContext)->session);
	fail_unless(idpSessionContextDump != NULL,
		    "lasso_session_dump shouldn't return NULL");
	responseUrl = LASSO_PROFILE(idpLoginContext)->msg_url;
	fail_unless(responseUrl != NULL, "responseUrl shouldn't be NULL");
	responseQuery = strchr(responseUrl, '?')+1;
	fail_unless(strlen(responseQuery) > 0,
			"responseQuery shouldn't be an empty string");
	serviceProviderId = g_strdup(LASSO_PROFILE(idpLoginContext)->remote_providerID);
	fail_unless(serviceProviderId != NULL,
		    "lasso_profile_get_remote_providerID shouldn't return NULL");

	/* Service provider assertion consumer */
	lasso_server_destroy(spContext);
	lasso_login_destroy(spLoginContext);

	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new(spContext);
	rc = lasso_login_init_request(spLoginContext,
			responseQuery,
			LASSO_HTTP_METHOD_REDIRECT);
	fail_unless(rc == 0, "lasso_login_init_request failed");
	rc = lasso_login_build_request_msg(spLoginContext);
	fail_unless(rc == 0, "lasso_login_build_request_msg failed");
	soapRequestMsg = LASSO_PROFILE(spLoginContext)->msg_body;
	fail_unless(soapRequestMsg != NULL, "soapRequestMsg must not be NULL");

	/* Identity provider SOAP endpoint */
	lasso_server_destroy(idpContext);
	lasso_login_destroy(idpLoginContext);
	requestType = lasso_profile_get_request_type_from_soap_msg(soapRequestMsg);
	fail_unless(requestType == LASSO_REQUEST_TYPE_LOGIN,
			"requestType should be LASSO_REQUEST_TYPE_LOGIN");

	idpContext = lasso_server_new_from_dump(identityProviderContextDump);
	idpLoginContext = lasso_login_new(idpContext);
	rc = lasso_login_process_request_msg(idpLoginContext, soapRequestMsg);
	fail_unless(rc == 0, "lasso_login_process_request_msg failed");

	rc = lasso_profile_set_session_from_dump(LASSO_PROFILE(idpLoginContext),
						 idpSessionContextDump);
	fail_unless(rc == 0, "lasso_login_set_assertion_from_dump failed");
	rc = lasso_login_build_response_msg(idpLoginContext, serviceProviderId);
	fail_unless(rc == 0, "lasso_login_build_response_msg failed");
	soapResponseMsg =  LASSO_PROFILE(idpLoginContext)->msg_body;
	fail_unless(soapResponseMsg != NULL, "soapResponseMsg must not be NULL");

	/* Service provider assertion consumer (step 2: process SOAP response) */
	rc = lasso_login_process_response_msg(spLoginContext, soapResponseMsg);
	fail_unless(rc == 0, "lasso_login_process_response_msg failed");
	rc = lasso_login_accept_sso(spLoginContext);
	fail_unless(rc == 0, "lasso_login_accept_sso failed");
	fail_unless(LASSO_PROFILE(spLoginContext)->identity != NULL,
			"spLoginContext has no identity");
	spIdentityContextDump = lasso_identity_dump(LASSO_PROFILE(spLoginContext)->identity);
	fail_unless(spIdentityContextDump != NULL, "lasso_identity_dump failed");
	spSessionDump = lasso_session_dump(LASSO_PROFILE(spLoginContext)->session);

	g_free(serviceProviderId);
	g_free(serviceProviderContextDump);
	g_free(identityProviderContextDump);
	g_free(idpSessionContextDump);
	g_free(idpIdentityContextDump);
	g_free(spIdentityContextDump);
	g_free(spSessionDump);
	g_object_unref(spContext);
	g_object_unref(idpContext);
	g_object_unref(spLoginContext);
	g_object_unref(idpLoginContext);
}
END_TEST
Suite*
login_suite()
{
	Suite *s = suite_create("Login");
	TCase *tc_generate = tcase_create("Generate Server Contexts");
	TCase *tc_spLogin = tcase_create("Login initiated by service provider");
	TCase *tc_spLoginMemory = tcase_create("Login initiated by service provider without key loading");
	suite_add_tcase(s, tc_generate);
	suite_add_tcase(s, tc_spLogin);
	suite_add_tcase(s, tc_spLoginMemory);
	tcase_add_test(tc_generate, test01_generateServersContextDumps);
	tcase_add_test(tc_spLogin, test02_serviceProviderLogin);
	tcase_add_test(tc_spLoginMemory, test03_serviceProviderLogin);
	return s;
}

