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
#include <glib.h>

#include "../lasso/lasso.h"
#include "../lasso/xml/saml-2.0/samlp2_authn_request.h"
#include "../lasso/utils.h"
#include "../lasso/backward_comp.h"


static char*
generateIdentityProviderContextDump()
{
	LassoServer *serverContext;
	char *ret;

	serverContext = lasso_server_new(
			TESTSDATADIR "/idp5-saml2/metadata.xml",
			TESTSDATADIR "/idp5-saml2/private-key.pem",
			NULL, /* Secret key to unlock private key */
			NULL);
	lasso_server_add_provider(
			serverContext,
			LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp5-saml2/metadata.xml",
			NULL,
			NULL);
	ret = lasso_server_dump(serverContext);

	g_object_unref(serverContext);

	return ret;
}

static char*
generateServiceProviderContextDump()
{
	LassoServer *serverContext;
	char *ret;

	serverContext = lasso_server_new(
			TESTSDATADIR "/sp5-saml2/metadata.xml",
			TESTSDATADIR "/sp5-saml2/private-key.pem",
			NULL, /* Secret key to unlock private key */
			NULL);
	lasso_server_add_provider(
			serverContext,
			LASSO_PROVIDER_ROLE_IDP,
			TESTSDATADIR "/idp5-saml2/metadata.xml",
			NULL,
			NULL);

	ret = lasso_server_dump(serverContext);
	g_object_unref(serverContext);
	return ret;
}

static char*
generateIdentityProviderContextDumpMemory()
{
	LassoServer *serverContext = NULL;
	char *metadata = NULL;
	char *private_key = NULL;
	char *certificate = NULL;
	guint len;
	char *ret = NULL;

	g_file_get_contents(TESTSDATADIR "/idp5-saml2/metadata.xml", &metadata, &len, NULL);
	g_file_get_contents(TESTSDATADIR "/idp5-saml2/private-key.pem", &private_key, &len, NULL);
	g_file_get_contents(TESTSDATADIR "/idp5-saml2/certificate.pem", &certificate, &len, NULL);

	serverContext = lasso_server_new_from_buffers(
			metadata,
			private_key,
			NULL, /* Secret key to unlock private key */
			certificate);
	lasso_server_add_provider(
			serverContext,
			LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp5-saml2/metadata.xml",
			NULL,
			NULL);
	g_free(metadata);
	g_free(private_key);
	g_free(certificate);
	ret = lasso_server_dump(serverContext);
	g_object_unref(serverContext);
	return ret;
}


START_TEST(test01_saml2_generateServersContextDumps)
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

START_TEST(test02_saml2_serviceProviderLogin)
{
	char *serviceProviderContextDump = NULL, *identityProviderContextDump = NULL;
	LassoServer *spContext = NULL, *idpContext = NULL;
	LassoLogin *spLoginContext = NULL, *idpLoginContext = NULL;
	LassoSamlp2AuthnRequest *request = NULL;
	int rc;
	char *relayState = NULL;
	char *authnRequestUrl = NULL, *authnRequestQuery = NULL;
	char *responseUrl = NULL, *responseQuery = NULL;
	char *idpIdentityContextDump = NULL, *idpSessionContextDump = NULL;
	char *serviceProviderId = NULL, *soapRequestMsg = NULL, *soapResponseMsg = NULL;
	char *spIdentityContextDump = NULL;
	char *spSessionDump = NULL;
	char *spLoginDump = NULL, *idpLoginDump = NULL;
	char *found = NULL;

	serviceProviderContextDump = generateServiceProviderContextDump();
	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new(spContext);
	fail_unless(spLoginContext != NULL,
			"lasso_login_new() shouldn't have returned NULL");
	rc = lasso_login_init_authn_request(spLoginContext, "http://idp5/metadata",
			LASSO_HTTP_METHOD_REDIRECT);
	fail_unless(rc == 0, "lasso_login_init_authn_request failed");
	request = LASSO_SAMLP2_AUTHN_REQUEST(LASSO_PROFILE(spLoginContext)->request);
	fail_unless(LASSO_IS_SAMLP2_AUTHN_REQUEST(request), "request should be authn_request");
	request->IsPassive = 0;
	lasso_assign_string(request->NameIDPolicy->Format, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT);
	request->NameIDPolicy->AllowCreate = 1;
	relayState = "fake[]";
	lasso_assign_string(LASSO_PROFILE(spLoginContext)->msg_relayState, relayState);
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
	fail_unless(g_strcmp0(idpLoginContext->parent.msg_relayState, relayState) == 0,
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
	rc = lasso_login_build_artifact_msg(idpLoginContext, LASSO_HTTP_METHOD_ARTIFACT_GET);
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
	lasso_assign_string(serviceProviderId, LASSO_PROFILE(idpLoginContext)->remote_providerID);
	fail_unless(serviceProviderId != NULL,
		    "lasso_profile_get_remote_providerID shouldn't return NULL");

	/* Service provider assertion consumer */
	lasso_server_destroy(spContext);
	lasso_login_destroy(spLoginContext);

	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new_from_dump(spContext, spLoginDump);
	rc = lasso_login_init_request(spLoginContext,
			responseQuery,
			LASSO_HTTP_METHOD_ARTIFACT_GET);
	fail_unless(spLoginContext->parent.msg_relayState != NULL,
			"lasso_login_init_request should restore the RelayState parameter");
	fail_unless(g_strcmp0(spLoginContext->parent.msg_relayState, relayState) == 0,
			"lasso_login_init_request should restore the same RelayState thant sent in the request");
	fail_unless(rc == 0, "lasso_login_init_request failed");
	rc = lasso_login_build_request_msg(spLoginContext);
	fail_unless(rc == 0, "lasso_login_build_request_msg failed");
	soapRequestMsg = LASSO_PROFILE(spLoginContext)->msg_body;
	fail_unless(soapRequestMsg != NULL, "soapRequestMsg must not be NULL");

	/* Identity provider SOAP endpoint */
	lasso_server_destroy(idpContext);
	idpLoginDump = lasso_node_dump(LASSO_NODE(idpLoginContext));
	lasso_login_destroy(idpLoginContext);

	idpContext = lasso_server_new_from_dump(identityProviderContextDump);
	idpLoginContext = lasso_login_new_from_dump(idpContext, idpLoginDump);
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
	fail_unless(rc != 0, "lasso_login_accept_sso must fail");

	g_free(idpLoginDump);
	g_free(serviceProviderId);
	g_free(serviceProviderContextDump);
	g_free(identityProviderContextDump);
	g_free(idpSessionContextDump);
	g_free(idpIdentityContextDump);
	g_free(spIdentityContextDump);
	g_free(spSessionDump);
	g_free(spLoginDump);
	g_object_unref(spContext);
	g_object_unref(idpContext);
	g_object_unref(spLoginContext);
	g_object_unref(idpLoginContext);
}
END_TEST

START_TEST(test03_saml2_serviceProviderLogin)
{
	char *serviceProviderContextDump = NULL, *identityProviderContextDump = NULL;
	LassoServer *spContext = NULL, *idpContext = NULL;
	LassoLogin *spLoginContext = NULL, *idpLoginContext = NULL;
	LassoSamlp2AuthnRequest *request = NULL;
	char *relayState = NULL;
	char *authnRequestUrl = NULL, *authnRequestQuery = NULL;
	char *responseUrl = NULL, *responseQuery = NULL;
	char *idpIdentityContextDump = NULL, *idpSessionContextDump = NULL;
	char *serviceProviderId = NULL, *soapRequestMsg = NULL, *soapResponseMsg = NULL;
	char *spIdentityContextDump = NULL;
	char *spSessionDump = NULL;
	char *idpLoginDump = NULL;
	int rc;

	serviceProviderContextDump = generateServiceProviderContextDump();
	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new(spContext);
	fail_unless(spLoginContext != NULL,
			"lasso_login_new() shouldn't have returned NULL");
	rc = lasso_login_init_authn_request(spLoginContext, "http://idp5/metadata",
			LASSO_HTTP_METHOD_REDIRECT);
	fail_unless(rc == 0, "lasso_login_init_authn_request failed");
	request = LASSO_SAMLP2_AUTHN_REQUEST(LASSO_PROFILE(spLoginContext)->request);
	fail_unless(LASSO_IS_SAMLP2_AUTHN_REQUEST(request), "request should be authn_request");
	request->IsPassive = 0;
	lasso_assign_string(request->NameIDPolicy->Format, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT);
	request->NameIDPolicy->AllowCreate = 1;
	relayState = "fake";
	lasso_assign_string(LASSO_PROFILE(spLoginContext)->msg_relayState, relayState);
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
	rc = lasso_login_build_artifact_msg(idpLoginContext, LASSO_HTTP_METHOD_ARTIFACT_GET);
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
	lasso_assign_string(serviceProviderId, LASSO_PROFILE(idpLoginContext)->remote_providerID);
	fail_unless(serviceProviderId != NULL,
		    "lasso_profile_get_remote_providerID shouldn't return NULL");

	/* Service provider assertion consumer */
	lasso_server_destroy(spContext);
	lasso_login_destroy(spLoginContext);

	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new(spContext);
	rc = lasso_login_init_request(spLoginContext,
			responseQuery,
			LASSO_HTTP_METHOD_ARTIFACT_GET);
	fail_unless(rc == 0, "lasso_login_init_request failed");
	rc = lasso_login_build_request_msg(spLoginContext);
	fail_unless(rc == 0, "lasso_login_build_request_msg failed");
	soapRequestMsg = LASSO_PROFILE(spLoginContext)->msg_body;
	fail_unless(soapRequestMsg != NULL, "soapRequestMsg must not be NULL");

	/* Identity provider SOAP endpoint */
	lasso_server_destroy(idpContext);
	idpLoginDump = lasso_node_dump(LASSO_NODE(idpLoginContext));
	lasso_login_destroy(idpLoginContext);

	idpContext = lasso_server_new_from_dump(identityProviderContextDump);
	idpLoginContext = lasso_login_new_from_dump(idpContext, idpLoginDump);
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

	g_free(idpLoginDump);
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
login_saml2_suite()
{
	Suite *s = suite_create("Login");
	TCase *tc_generate = tcase_create("Generate Server Contexts");
	TCase *tc_spLogin = tcase_create("Login initiated by service provider");
	TCase *tc_spLoginMemory = tcase_create("Login initiated by service provider without key loading");
	suite_add_tcase(s, tc_generate);
	suite_add_tcase(s, tc_spLogin);
	suite_add_tcase(s, tc_spLoginMemory);
	tcase_add_test(tc_generate, test01_saml2_generateServersContextDumps);
	tcase_add_test(tc_spLogin, test02_saml2_serviceProviderLogin);
	tcase_add_test(tc_spLoginMemory, test03_saml2_serviceProviderLogin);
	return s;
}

