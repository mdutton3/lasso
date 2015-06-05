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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>

#include <check.h>
#include <glib.h>

#include "../lasso/lasso.h"
#include "../lasso/xml/saml-2.0/samlp2_authn_request.h"
#include "../lasso/utils.h"
#include "../lasso/backward_comp.h"
#include "../lasso/xml/saml-2.0/samlp2_logout_request.h"
#include "../bindings/ghashtable.h"
#include "tests.h"

static char*
generateIdentityProviderContextDump()
{
	LassoServer *serverContext;
	GList *providers;
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
	providers = g_hash_table_get_values(serverContext->providers);
	lasso_provider_set_encryption_mode(LASSO_PROVIDER(providers->data), LASSO_ENCRYPTION_MODE_ASSERTION | LASSO_ENCRYPTION_MODE_NAMEID);
	ret = lasso_server_dump(serverContext);

	g_object_unref(serverContext);
	g_list_free(providers);

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
	size_t len;
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
	LassoLogout *spLogoutContext = NULL, *idpLogoutContext = NULL;
	LassoSamlp2AuthnRequest *request = NULL;
	int rc = 0;
	char *relayState = NULL;
	char *authnRequestUrl = NULL, *authnRequestQuery = NULL;
	char *logoutRequestUrl = NULL, *logoutRequestQuery = NULL;
	char *logoutResponseUrl = NULL, *logoutResponseQuery = NULL;
	char *responseUrl = NULL, *responseQuery = NULL;
	char *idpIdentityContextDump = NULL, *idpSessionContextDump = NULL;
	char *serviceProviderId = NULL, *soapRequestMsg = NULL, *soapResponseMsg = NULL;
	char *spIdentityContextDump = NULL;
	char *spSessionDump = NULL;
	char *spLoginDump = NULL, *idpLoginDump = NULL;
	char *found = NULL;
	LassoSaml2Assertion *assertion;

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
	check_good_rc(lasso_login_process_authn_request_msg(idpLoginContext, authnRequestQuery));
	check_true(lasso_login_must_authenticate(idpLoginContext));
	check_equals(idpLoginContext->protocolProfile, LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART);
	check_false(lasso_login_must_ask_for_consent(idpLoginContext));
	check_not_null(idpLoginContext->parent.msg_relayState);
	check_equals(lasso_strisnotequal(idpLoginContext->parent.msg_relayState,relayState), 0);
	check_good_rc(lasso_login_validate_request_msg(idpLoginContext,
			1, /* authentication_result */
		        0 /* is_consent_obtained */
			));

	check_good_rc(lasso_login_build_assertion(idpLoginContext,
			LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD,
			"FIXME: authenticationInstant",
			"FIXME: reauthenticateOnOrAfter",
			"FIXME: notBefore",
			"FIXME: notOnOrAfter"));
	assertion = (LassoSaml2Assertion*)lasso_login_get_assertion(idpLoginContext);
	check_true(LASSO_IS_SAML2_ASSERTION(assertion));
	lasso_saml2_assertion_set_basic_conditions(LASSO_SAML2_ASSERTION(assertion), 60, 120, FALSE);
	lasso_release_gobject(assertion);
	check_good_rc(lasso_login_build_artifact_msg(idpLoginContext, LASSO_HTTP_METHOD_ARTIFACT_GET));

	idpIdentityContextDump = lasso_identity_dump(LASSO_PROFILE(idpLoginContext)->identity);
	check_not_null(idpIdentityContextDump);
	idpSessionContextDump = lasso_session_dump(LASSO_PROFILE(idpLoginContext)->session);
	check_not_null(idpSessionContextDump);
	responseUrl = LASSO_PROFILE(idpLoginContext)->msg_url;
	check_not_null(responseUrl);
	responseQuery = strchr(responseUrl, '?')+1;
	fail_unless(strlen(responseQuery) > 0,
			"responseQuery shouldn't be an empty string");
	check_not_null(strstr(responseQuery, "RelayState"));
	check_not_null(strstr(responseQuery, "fake%5B%5D"));
	lasso_assign_string(serviceProviderId, LASSO_PROFILE(idpLoginContext)->remote_providerID);
	check_not_null(serviceProviderId);

	/* Service provider assertion consumer */
	lasso_server_destroy(spContext);
	lasso_login_destroy(spLoginContext);

	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new_from_dump(spContext, spLoginDump);
	check_good_rc(lasso_login_init_request(spLoginContext,
			responseQuery,
			LASSO_HTTP_METHOD_ARTIFACT_GET));
	check_not_null(spLoginContext->parent.msg_relayState);
	check_equals(lasso_strisnotequal(spLoginContext->parent.msg_relayState,relayState), 0);
	check_good_rc(lasso_login_build_request_msg(spLoginContext));
	soapRequestMsg = LASSO_PROFILE(spLoginContext)->msg_body;
	check_not_null(soapRequestMsg);

	/* Identity provider SOAP endpoint */
	lasso_server_destroy(idpContext);
	idpLoginDump = lasso_node_dump(LASSO_NODE(idpLoginContext));
	lasso_login_destroy(idpLoginContext);

	idpContext = lasso_server_new_from_dump(identityProviderContextDump);
	idpLoginContext = lasso_login_new_from_dump(idpContext, idpLoginDump);
	check_good_rc(lasso_login_process_request_msg(idpLoginContext, soapRequestMsg));

	check_good_rc(lasso_profile_set_session_from_dump(LASSO_PROFILE(idpLoginContext),
						 idpSessionContextDump));
	check_good_rc(lasso_login_build_response_msg(idpLoginContext, serviceProviderId));
	soapResponseMsg =  LASSO_PROFILE(idpLoginContext)->msg_body;
	check_not_null(soapResponseMsg);

	/* Service provider assertion consumer (step 2: process SOAP response) */
	check_good_rc(lasso_login_process_response_msg(spLoginContext, soapResponseMsg));
	check_good_rc(lasso_login_accept_sso(spLoginContext));
	assertion = (LassoSaml2Assertion*)lasso_login_get_assertion(spLoginContext);
	check_true(LASSO_IS_SAML2_ASSERTION(assertion));
	check_equals(lasso_saml2_assertion_validate_conditions(assertion,
				spLoginContext->parent.server->parent.ProviderID),
			LASSO_SAML2_ASSERTION_VALID);
	check_equals(lasso_saml2_assertion_validate_conditions(assertion, "coin"), LASSO_SAML2_ASSERTION_INVALID);
	lasso_release_gobject(assertion);
	check_not_null(LASSO_PROFILE(spLoginContext)->identity);
	spIdentityContextDump = lasso_identity_dump(LASSO_PROFILE(spLoginContext)->identity);
	check_not_null(spIdentityContextDump);
	spSessionDump = lasso_session_dump(LASSO_PROFILE(spLoginContext)->session);

	/* Test InResponseTo checking */
	if (! strstr(soapResponseMsg, "EncryptedAssertion")) {
		found = strstr(soapResponseMsg, "Assertion");
		check_not_null(found);
		found = strstr(found, "InResponseTo=\"");
		check_not_null(found);
		found[sizeof("InResponseTo=\"")] = '?';
		lasso_set_flag("no-verify-signature");
		check_not_equals(lasso_login_process_response_msg(spLoginContext, soapResponseMsg), 0);
		lasso_set_flag("verify-signature");
		check_not_equals(lasso_login_accept_sso(spLoginContext), 0);
	}

	/* logout test */
	/* generate a logout request */
	check_not_null(idpLogoutContext = lasso_logout_new(idpContext));
	check_good_rc(lasso_profile_set_session_from_dump(&idpLogoutContext->parent, idpSessionContextDump));
	check_good_rc(lasso_logout_init_request(idpLogoutContext, NULL, LASSO_HTTP_METHOD_REDIRECT));
	check_good_rc(lasso_logout_build_request_msg(idpLogoutContext));
	check_not_null(idpLogoutContext->parent.msg_url);
	check_null(idpLogoutContext->parent.msg_body);
	check_null(idpLogoutContext->parent.msg_relayState);
	lasso_assign_string(logoutRequestUrl, idpLogoutContext->parent.msg_url);
	lasso_release_gobject(idpLogoutContext);
	logoutRequestQuery = strchr(logoutRequestUrl, '?');
	logoutRequestQuery += 1; /* keep only the query */
	check_not_null(logoutRequestQuery);

	/* process the logout request */
	check_not_null(spLogoutContext = lasso_logout_new(spContext));
	check_good_rc(lasso_profile_set_session_from_dump(&spLogoutContext->parent, spSessionDump));
	check_good_rc(lasso_logout_process_request_msg(spLogoutContext, logoutRequestQuery));
	check_good_rc(lasso_logout_validate_request(spLogoutContext));
	check_good_rc(lasso_logout_build_response_msg(spLogoutContext));
	check_not_null(spLogoutContext->parent.msg_url);
	check_null(spLogoutContext->parent.msg_body);
	check_null(spLogoutContext->parent.msg_relayState);
	lasso_assign_string(logoutResponseUrl, spLogoutContext->parent.msg_url);
	check_not_null(logoutResponseQuery = strchr(logoutResponseUrl, '?'));
	logoutResponseQuery += 1; /* keep only the query */
	lasso_release_gobject(spLogoutContext);

	/* process the response */
	check_not_null(idpLogoutContext = lasso_logout_new(idpContext));
	check_good_rc(lasso_profile_set_session_from_dump(&idpLogoutContext->parent, idpSessionContextDump));
	check_good_rc(lasso_logout_process_response_msg(idpLogoutContext, logoutResponseQuery));
	lasso_release_gobject(idpLogoutContext);
	lasso_release_string(logoutRequestUrl);
	lasso_release_string(logoutResponseUrl);

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
	int rc = 0;

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

START_TEST(test04_sso_then_slo_soap)
{
	char *serviceProviderContextDump = NULL, *identityProviderContextDump = NULL;
	LassoServer *spContext = NULL, *idpContext = NULL;
	LassoLogin *spLoginContext = NULL, *idpLoginContext = NULL;
	LassoLogout *spLogoutContext = NULL, *idpLogoutContext = NULL;
	LassoSamlp2AuthnRequest *request = NULL;
	int rc = 0;
	char *relayState = NULL;
	char *authnRequestUrl = NULL, *authnRequestQuery = NULL;
	char *logoutRequestSoapMessage = NULL;
	char *logoutResponseSoapMessage = NULL;
	char *responseUrl = NULL, *responseQuery = NULL;
	char *idpIdentityContextDump = NULL, *idpSessionContextDump = NULL;
	char *serviceProviderId = NULL, *soapRequestMsg = NULL, *soapResponseMsg = NULL;
	char *spIdentityContextDump = NULL;
	char *spSessionDump = NULL;
	char *spLoginDump = NULL, *idpLoginDump = NULL;
	char *found = NULL;
	LassoSaml2Assertion *assertion;

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
	check_good_rc(lasso_login_process_authn_request_msg(idpLoginContext, authnRequestQuery));
	check_true(lasso_login_must_authenticate(idpLoginContext));
	check_equals(idpLoginContext->protocolProfile, LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART);
	check_false(lasso_login_must_ask_for_consent(idpLoginContext));
	check_not_null(idpLoginContext->parent.msg_relayState);
	check_equals(lasso_strisnotequal(idpLoginContext->parent.msg_relayState,relayState), 0);
	check_good_rc(lasso_login_validate_request_msg(idpLoginContext,
			1, /* authentication_result */
		        0 /* is_consent_obtained */
			));

	check_good_rc(lasso_login_build_assertion(idpLoginContext,
			LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD,
			"FIXME: authenticationInstant",
			"FIXME: reauthenticateOnOrAfter",
			"FIXME: notBefore",
			"FIXME: notOnOrAfter"));
	assertion = (LassoSaml2Assertion*)lasso_login_get_assertion(idpLoginContext);
	check_true(LASSO_IS_SAML2_ASSERTION(assertion));
	lasso_saml2_assertion_set_basic_conditions(LASSO_SAML2_ASSERTION(assertion), 60, 120, FALSE);
	lasso_release_gobject(assertion);
	check_good_rc(lasso_login_build_artifact_msg(idpLoginContext, LASSO_HTTP_METHOD_ARTIFACT_GET));

	idpIdentityContextDump = lasso_identity_dump(LASSO_PROFILE(idpLoginContext)->identity);
	check_not_null(idpIdentityContextDump);
	idpSessionContextDump = lasso_session_dump(LASSO_PROFILE(idpLoginContext)->session);
	check_not_null(idpSessionContextDump);
	responseUrl = LASSO_PROFILE(idpLoginContext)->msg_url;
	check_not_null(responseUrl);
	responseQuery = strchr(responseUrl, '?')+1;
	fail_unless(strlen(responseQuery) > 0,
			"responseQuery shouldn't be an empty string");
	check_not_null(strstr(responseQuery, "RelayState"));
	check_not_null(strstr(responseQuery, "fake%5B%5D"));
	lasso_assign_string(serviceProviderId, LASSO_PROFILE(idpLoginContext)->remote_providerID);
	check_not_null(serviceProviderId);

	/* Service provider assertion consumer */
	lasso_server_destroy(spContext);
	lasso_login_destroy(spLoginContext);

	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new_from_dump(spContext, spLoginDump);
	check_good_rc(lasso_login_init_request(spLoginContext,
			responseQuery,
			LASSO_HTTP_METHOD_ARTIFACT_GET));
	check_not_null(spLoginContext->parent.msg_relayState);
	check_equals(lasso_strisnotequal(spLoginContext->parent.msg_relayState,relayState), 0);
	check_good_rc(lasso_login_build_request_msg(spLoginContext));
	soapRequestMsg = LASSO_PROFILE(spLoginContext)->msg_body;
	check_not_null(soapRequestMsg);

	/* Identity provider SOAP endpoint */
	lasso_server_destroy(idpContext);
	idpLoginDump = lasso_node_dump(LASSO_NODE(idpLoginContext));
	lasso_login_destroy(idpLoginContext);

	idpContext = lasso_server_new_from_dump(identityProviderContextDump);
	idpLoginContext = lasso_login_new_from_dump(idpContext, idpLoginDump);
	check_good_rc(lasso_login_process_request_msg(idpLoginContext, soapRequestMsg));

	check_good_rc(lasso_profile_set_session_from_dump(LASSO_PROFILE(idpLoginContext),
						 idpSessionContextDump));
	check_good_rc(lasso_login_build_response_msg(idpLoginContext, serviceProviderId));
	soapResponseMsg =  LASSO_PROFILE(idpLoginContext)->msg_body;
	check_not_null(soapResponseMsg);

	/* Service provider assertion consumer (step 2: process SOAP response) */
	check_good_rc(lasso_login_process_response_msg(spLoginContext, soapResponseMsg));
	check_good_rc(lasso_login_accept_sso(spLoginContext));
	assertion = (LassoSaml2Assertion*)lasso_login_get_assertion(spLoginContext);
	check_true(LASSO_IS_SAML2_ASSERTION(assertion));
	check_equals(lasso_saml2_assertion_validate_conditions(assertion,
				spLoginContext->parent.server->parent.ProviderID),
			LASSO_SAML2_ASSERTION_VALID);
	check_equals(lasso_saml2_assertion_validate_conditions(assertion, "coin"), LASSO_SAML2_ASSERTION_INVALID);
	lasso_release_gobject(assertion);
	check_not_null(LASSO_PROFILE(spLoginContext)->identity);
	spIdentityContextDump = lasso_identity_dump(LASSO_PROFILE(spLoginContext)->identity);
	check_not_null(spIdentityContextDump);
	spSessionDump = lasso_session_dump(LASSO_PROFILE(spLoginContext)->session);

	/* Test InResponseTo checking */
	if (! strstr(soapResponseMsg, "EncryptedAssertion")) {
		found = strstr(soapResponseMsg, "Assertion");
		check_not_null(found);
		found = strstr(found, "InResponseTo=\"");
		check_not_null(found);
		found[sizeof("InResponseTo=\"")] = '?';
		lasso_set_flag("no-verify-signature");
		check_not_equals(lasso_login_process_response_msg(spLoginContext, soapResponseMsg), 0);
		lasso_set_flag("verify-signature");
		check_not_equals(lasso_login_accept_sso(spLoginContext), 0);
	}

	/* logout test */
	/* generate a logout request */
	check_not_null(idpLogoutContext = lasso_logout_new(idpContext));
	check_good_rc(lasso_profile_set_session_from_dump(&idpLogoutContext->parent, idpSessionContextDump));
	check_good_rc(lasso_logout_init_request(idpLogoutContext, NULL, LASSO_HTTP_METHOD_SOAP));
	check_good_rc(lasso_logout_build_request_msg(idpLogoutContext));
	check_not_null(idpLogoutContext->parent.msg_url);
	check_not_null(idpLogoutContext->parent.msg_body);
	check_null(idpLogoutContext->parent.msg_relayState);
	lasso_assign_string(logoutRequestSoapMessage, idpLogoutContext->parent.msg_body);
	check_not_null(logoutRequestSoapMessage);

	/* process the logout request */
	check_not_null(spLogoutContext = lasso_logout_new(spContext));
	check_good_rc(lasso_profile_set_session_from_dump(&spLogoutContext->parent, spSessionDump));
	check_good_rc(lasso_logout_process_request_msg(spLogoutContext, logoutRequestSoapMessage));
	lasso_release(logoutRequestSoapMessage);
	check_good_rc(lasso_logout_validate_request(spLogoutContext));
	check_good_rc(lasso_logout_build_response_msg(spLogoutContext));
	check_not_null(spLogoutContext->parent.msg_body);
	check_null(spLogoutContext->parent.msg_url);
	check_null(spLogoutContext->parent.msg_relayState);
	lasso_assign_string(logoutResponseSoapMessage, spLogoutContext->parent.msg_body);
	lasso_release_gobject(spLogoutContext);
	lasso_release_gobject(idpLogoutContext);

	/* process the response */
	check_not_null(idpLogoutContext = lasso_logout_new(idpContext));
	check_good_rc(lasso_profile_set_session_from_dump(&idpLogoutContext->parent, idpSessionContextDump));
	check_good_rc(lasso_logout_process_response_msg(idpLogoutContext, logoutResponseSoapMessage));
	lasso_release_gobject(idpLogoutContext);
	lasso_release_string(logoutResponseSoapMessage);

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

START_TEST(test05_sso_idp_with_key_rollover)
{
	LassoServer *idpContext1 = NULL;
	LassoServer *idpContext2 = NULL;
	LassoServer *spContext = NULL;
	LassoLogin *idpLoginContext1 = NULL;
	LassoLogin *idpLoginContext2 = NULL;
	LassoLogin *spLoginContext = NULL;

	/* Create an IdP context for IdP initiated SSO with private key 1 */
	idpContext1 = lasso_server_new(
			TESTSDATADIR "idp11-multikey-saml2/metadata.xml",
			TESTSDATADIR "idp11-multikey-saml2/private-key-1.pem",
			NULL, /* Secret key to unlock private key */
			TESTSDATADIR "idp11-multikey-saml2/certificate-1.pem");
	check_not_null(idpContext1)
	check_good_rc(lasso_server_add_provider(
			idpContext1,
			LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp6-saml2/metadata.xml",
			NULL,
			NULL));
	/* Create an IdP context for IdP initiated SSO with private key 2 */
	idpContext2 = lasso_server_new(
			TESTSDATADIR "idp11-multikey-saml2/metadata.xml",
			TESTSDATADIR "idp11-multikey-saml2/private-key-2.pem",
			NULL, /* Secret key to unlock private key */
			TESTSDATADIR "idp11-multikey-saml2/certificate-2.pem");
	check_not_null(idpContext2)
	check_good_rc(lasso_server_add_provider(
			idpContext2,
			LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp6-saml2/metadata.xml",
			NULL,
			NULL));
	/* Create an SP context */
	spContext = lasso_server_new(
			TESTSDATADIR "/sp6-saml2/metadata.xml",
			TESTSDATADIR "/sp6-saml2/private-key.pem",
			NULL, /* Secret key to unlock private key */
			NULL);
	check_not_null(spContext)
	check_good_rc(lasso_server_add_provider(
			spContext,
			LASSO_PROVIDER_ROLE_IDP,
			TESTSDATADIR "/idp11-multikey-saml2/metadata.xml",
			NULL,
			NULL));

	/* Create login contexts */
	idpLoginContext1 = lasso_login_new(idpContext1);
	check_not_null(idpLoginContext1);
	idpLoginContext2 = lasso_login_new(idpContext2);
	check_not_null(idpLoginContext2);
	spLoginContext = lasso_login_new(spContext);
	check_not_null(spLoginContext);

	/* Create first response signed with key 1*/
	check_good_rc(lasso_login_init_idp_initiated_authn_request(idpLoginContext1, "http://sp6/metadata"));
	lasso_assign_string(LASSO_SAMLP2_AUTHN_REQUEST(idpLoginContext1->parent.request)->ProtocolBinding,
			LASSO_SAML2_METADATA_BINDING_POST);
	check_good_rc(lasso_login_process_authn_request_msg(idpLoginContext1, NULL));
	check_good_rc(lasso_login_validate_request_msg(idpLoginContext1,
			1, /* authentication_result */
		        0 /* is_consent_obtained */
			));

	check_good_rc(lasso_login_build_assertion(idpLoginContext1,
			LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD,
			"FIXME: authenticationInstant",
			"FIXME: reauthenticateOnOrAfter",
			"FIXME: notBefore",
			"FIXME: notOnOrAfter"));
	check_good_rc(lasso_login_build_authn_response_msg(idpLoginContext1));
	check_not_null(idpLoginContext1->parent.msg_body);
	check_not_null(idpLoginContext1->parent.msg_url);

	/* Create second response signed with key 2 */
	check_good_rc(lasso_login_init_idp_initiated_authn_request(idpLoginContext2, "http://sp6/metadata"));
	lasso_assign_string(LASSO_SAMLP2_AUTHN_REQUEST(idpLoginContext2->parent.request)->ProtocolBinding,
			LASSO_SAML2_METADATA_BINDING_POST);
	check_good_rc(lasso_login_process_authn_request_msg(idpLoginContext2, NULL));
	check_good_rc(lasso_login_validate_request_msg(idpLoginContext2,
			1, /* authentication_result */
		        0 /* is_consent_obtained */
			));

	check_good_rc(lasso_login_build_assertion(idpLoginContext2,
			LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD,
			"FIXME: authenticationInstant",
			"FIXME: reauthenticateOnOrAfter",
			"FIXME: notBefore",
			"FIXME: notOnOrAfter"));
	check_good_rc(lasso_login_build_authn_response_msg(idpLoginContext2));
	check_not_null(idpLoginContext2->parent.msg_body);
	check_not_null(idpLoginContext2->parent.msg_url);

	/* Process response 1 */
	check_good_rc(lasso_login_process_authn_response_msg(spLoginContext,
				idpLoginContext1->parent.msg_body));
	check_good_rc(lasso_login_accept_sso(spLoginContext));

	/* Process response 2 */
	block_lasso_logs;
	check_good_rc(lasso_login_process_authn_response_msg(spLoginContext,
				idpLoginContext2->parent.msg_body));
	unblock_lasso_logs;
	check_good_rc(lasso_login_accept_sso(spLoginContext));

	/* Cleanup */
	lasso_release_gobject(idpLoginContext1);
	lasso_release_gobject(idpLoginContext2);
	lasso_release_gobject(spLoginContext);
	lasso_release_gobject(idpContext1);
	lasso_release_gobject(idpContext2);
	lasso_release_gobject(spContext);
}
END_TEST

#define make_context(ctx, server_prefix, server_suffix, provider_role, \
		provider_prefix, provider_suffix) \
	ctx =  lasso_server_new( \
			TESTSDATADIR server_prefix "/metadata" server_suffix ".xml", \
			TESTSDATADIR server_prefix "/private-key" server_suffix ".pem", \
			NULL, /* Secret key to unlock private key */ \
			TESTSDATADIR server_prefix "/certificate" server_suffix ".pem"); \
	check_not_null(ctx); \
	check_good_rc(lasso_server_add_provider( \
			ctx, \
			provider_role, \
			TESTSDATADIR provider_prefix "/metadata" provider_suffix ".xml", \
			NULL, \
			NULL)); \
	providers = g_hash_table_get_values(ctx->providers); \
	check_not_null(providers); \
	lasso_provider_set_encryption_mode(LASSO_PROVIDER(providers->data), \
			LASSO_ENCRYPTION_MODE_ASSERTION | LASSO_ENCRYPTION_MODE_NAMEID); \
	g_list_free(providers);

void
sso_sp_with_key_rollover(LassoServer *idp_context, LassoServer *sp_context)
{
	LassoLogin *idp_login_context;
	LassoLogin *sp_login_context;

	check_not_null(idp_login_context = lasso_login_new(idp_context));
	check_not_null(sp_login_context = lasso_login_new(sp_context))

	/* Create response */
	check_good_rc(lasso_login_init_idp_initiated_authn_request(idp_login_context,
				"http://sp11/metadata"));

	lasso_assign_string(LASSO_SAMLP2_AUTHN_REQUEST(idp_login_context->parent.request)->ProtocolBinding,
			LASSO_SAML2_METADATA_BINDING_POST);
	lasso_assign_string(LASSO_SAMLP2_AUTHN_REQUEST(idp_login_context->parent.request)->NameIDPolicy->Format,
			LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT);
	LASSO_SAMLP2_AUTHN_REQUEST(idp_login_context->parent.request)->NameIDPolicy->AllowCreate = 1;

	block_lasso_logs;
	check_good_rc(lasso_login_process_authn_request_msg(idp_login_context, NULL));
	unblock_lasso_logs;
	check_good_rc(lasso_login_validate_request_msg(idp_login_context,
			1, /* authentication_result */
		        0 /* is_consent_obtained */
			));

	check_good_rc(lasso_login_build_assertion(idp_login_context,
			LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD,
			"FIXME: authenticationInstant",
			"FIXME: reauthenticateOnOrAfter",
			"FIXME: notBefore",
			"FIXME: notOnOrAfter"));
	check_good_rc(lasso_login_build_authn_response_msg(idp_login_context));
	check_not_null(idp_login_context->parent.msg_body);
	check_not_null(idp_login_context->parent.msg_url);

	/* Process response */
	block_lasso_logs;
	check_good_rc(lasso_login_process_authn_response_msg(sp_login_context,
				idp_login_context->parent.msg_body));
	unblock_lasso_logs;
	check_good_rc(lasso_login_accept_sso(sp_login_context));

	/* Cleanup */
	lasso_release_gobject(idp_login_context);
	lasso_release_gobject(sp_login_context);
}

START_TEST(test06_sso_sp_with_key_rollover)
{
	LassoServer *idp_context_before_rollover = NULL;
	LassoServer *idp_context_after_rollover = NULL;
	LassoServer *sp_context_before_rollover = NULL;
	LassoServer *sp_context_after_rollover = NULL;
	GList *providers;

	/* Create an IdP context for IdP initiated SSO with provider metadata 1 */
	make_context(idp_context_before_rollover, "idp6-saml2", "", LASSO_PROVIDER_ROLE_SP,
			"sp11-multikey-saml2", "-before-rollover")
	make_context(idp_context_after_rollover, "idp6-saml2", "", LASSO_PROVIDER_ROLE_SP,
			"sp11-multikey-saml2", "-after-rollover")
	make_context(sp_context_before_rollover, "sp11-multikey-saml2", "-before-rollover",
			LASSO_PROVIDER_ROLE_IDP, "idp6-saml2", "")
	lasso_server_set_encryption_private_key(sp_context_before_rollover,
			TESTSDATADIR "sp11-multikey-saml2/private-key-after-rollover.pem");
	make_context(sp_context_after_rollover, "sp11-multikey-saml2", "-after-rollover",
			LASSO_PROVIDER_ROLE_IDP, "idp6-saml2", "")
	lasso_server_set_encryption_private_key(sp_context_after_rollover,
			TESTSDATADIR "sp11-multikey-saml2/private-key-before-rollover.pem");

	/* Tests... */
	sso_sp_with_key_rollover(idp_context_before_rollover, sp_context_before_rollover);
	sso_sp_with_key_rollover(idp_context_after_rollover, sp_context_before_rollover);
	sso_sp_with_key_rollover(idp_context_before_rollover, sp_context_after_rollover);
	sso_sp_with_key_rollover(idp_context_after_rollover, sp_context_after_rollover);

	/* Cleanup */
	lasso_release_gobject(idp_context_before_rollover);
	lasso_release_gobject(idp_context_after_rollover);
	lasso_release_gobject(sp_context_before_rollover);
	lasso_release_gobject(sp_context_after_rollover);
}
END_TEST

#define test07_make_context(ctx, server_prefix, provider_role, provider_prefix, key) \
	ctx =  lasso_server_new( \
			TESTSDATADIR server_prefix "/metadata.xml", \
			NULL, \
			NULL, /* Secret key to unlock private key */ \
			NULL); \
	check_not_null(ctx); \
	check_good_rc(lasso_server_add_provider( \
			ctx, \
			provider_role, \
			TESTSDATADIR provider_prefix "/metadata.xml", \
			NULL, \
			NULL)); \
	providers = g_hash_table_get_values(ctx->providers); \
	check_not_null(providers); \
	lasso_provider_set_server_signing_key(LASSO_PROVIDER(providers->data), \
			key); \
	lasso_provider_add_key(LASSO_PROVIDER(providers->data), key, FALSE); \
	g_list_free(providers);

static void
sso_initiated_by_sp(LassoServer *idp_context, LassoServer *sp_context)
{
	LassoLogin *idp_login_context;
	LassoLogin *sp_login_context;
	char *authn_request_query;

	check_not_null(idp_login_context = lasso_login_new(idp_context));
	check_not_null(sp_login_context = lasso_login_new(sp_context))

	/* Create response */
	check_good_rc(lasso_login_init_authn_request(sp_login_context, NULL, LASSO_HTTP_METHOD_REDIRECT));

	lasso_assign_string(LASSO_SAMLP2_AUTHN_REQUEST(sp_login_context->parent.request)->ProtocolBinding,
			LASSO_SAML2_METADATA_BINDING_POST);
	lasso_assign_string(LASSO_SAMLP2_AUTHN_REQUEST(sp_login_context->parent.request)->NameIDPolicy->Format,
			LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT);
	LASSO_SAMLP2_AUTHN_REQUEST(sp_login_context->parent.request)->NameIDPolicy->AllowCreate = 1;
	check_good_rc(lasso_login_build_authn_request_msg(sp_login_context));
	check_not_null(sp_login_context->parent.msg_url);
	authn_request_query = strchr(sp_login_context->parent.msg_url, '?');
	check_not_null(authn_request_query);
	authn_request_query += 1;
	check_good_rc(lasso_login_process_authn_request_msg(idp_login_context, authn_request_query));

	check_good_rc(lasso_login_validate_request_msg(idp_login_context,
			1, /* authentication_result */
		        0 /* is_consent_obtained */
			));

	check_good_rc(lasso_login_build_assertion(idp_login_context,
			LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD,
			"FIXME: authenticationInstant",
			"FIXME: reauthenticateOnOrAfter",
			"FIXME: notBefore",
			"FIXME: notOnOrAfter"));
	check_good_rc(lasso_login_build_authn_response_msg(idp_login_context));
	check_not_null(idp_login_context->parent.msg_body);
	check_not_null(idp_login_context->parent.msg_url);

	/* Process response */
	check_good_rc(lasso_login_process_authn_response_msg(sp_login_context,
				idp_login_context->parent.msg_body));
	check_good_rc(lasso_login_accept_sso(sp_login_context));

	/* Cleanup */
	lasso_release_gobject(idp_login_context);
	lasso_release_gobject(sp_login_context);
}

START_TEST(test07_sso_sp_with_hmac_sha1_signatures)
{
	LassoServer *idp_context = NULL;
	LassoServer *sp_context = NULL;
	GList *providers;
	LassoKey *key = NULL;

	/* Create the shared key */
	key = lasso_key_new_for_signature_from_memory("xxxxxxxxxxxxxxxx", 16,
			NULL, LASSO_SIGNATURE_METHOD_HMAC_SHA1, NULL);
	check_true(LASSO_IS_KEY(key));

	/* Create an IdP context for IdP initiated SSO with provider metadata 1 */
	test07_make_context(idp_context, "idp6-saml2", LASSO_PROVIDER_ROLE_SP, "sp6-saml2", key)
	test07_make_context(sp_context, "sp6-saml2", LASSO_PROVIDER_ROLE_IDP, "idp6-saml2", key)

	block_lasso_logs;
	sso_initiated_by_sp(idp_context, sp_context);
	unblock_lasso_logs;

	/* Cleanup */
	lasso_release_gobject(idp_context);
	lasso_release_gobject(sp_context);
	lasso_release_gobject(key);
}
END_TEST

typedef struct {
	char *assertion_consumer_service_url;
	char *protocol_binding;
	gboolean use_assertion_consumer_service_idx;
	int assertion_consumer_service_idx;
	gboolean stop_after_build_assertion;
} SsoSettings;

static void
sso_initiated_by_sp2(LassoServer *idp_context, LassoServer *sp_context, SsoSettings sso_settings)
{
	LassoLogin *idp_login_context;
	LassoLogin *sp_login_context;
	LassoSamlp2AuthnRequest *request;
	char *authn_request_query;

	check_not_null(idp_login_context = lasso_login_new(idp_context));
	check_not_null(sp_login_context = lasso_login_new(sp_context))

	/* Create response */
	check_good_rc(lasso_login_init_authn_request(sp_login_context, NULL, LASSO_HTTP_METHOD_REDIRECT));
	request = (LassoSamlp2AuthnRequest*)sp_login_context->parent.request;
	if (sso_settings.assertion_consumer_service_url) {
		lasso_assign_string(request->AssertionConsumerServiceURL, sso_settings.assertion_consumer_service_url);
	}
	if (sso_settings.protocol_binding) {
		lasso_assign_string(request->ProtocolBinding, sso_settings.protocol_binding);
	}
	if (sso_settings.use_assertion_consumer_service_idx) {
		request->AssertionConsumerServiceIndex = sso_settings.assertion_consumer_service_idx;
	}
	lasso_assign_string(LASSO_SAMLP2_AUTHN_REQUEST(sp_login_context->parent.request)->NameIDPolicy->Format,
			LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT);
	LASSO_SAMLP2_AUTHN_REQUEST(sp_login_context->parent.request)->NameIDPolicy->AllowCreate = 1;
	check_good_rc(lasso_login_build_authn_request_msg(sp_login_context));
	check_not_null(sp_login_context->parent.msg_url);
	authn_request_query = strchr(sp_login_context->parent.msg_url, '?');
	check_not_null(authn_request_query);
	authn_request_query += 1;
	check_good_rc(lasso_login_process_authn_request_msg(idp_login_context, authn_request_query));

	check_good_rc(lasso_login_validate_request_msg(idp_login_context,
			1, /* authentication_result */
		        0 /* is_consent_obtained */
			));

	check_good_rc(lasso_login_build_assertion(idp_login_context,
			LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD,
			"FIXME: authenticationInstant",
			"FIXME: reauthenticateOnOrAfter",
			"FIXME: notBefore",
			"FIXME: notOnOrAfter"));
	if (sso_settings.stop_after_build_assertion) {
		goto cleanup;
	}
	check_good_rc(lasso_login_build_authn_response_msg(idp_login_context));
	check_not_null(idp_login_context->parent.msg_body);
	check_not_null(idp_login_context->parent.msg_url);

	/* Process response */
	check_good_rc(lasso_login_process_authn_response_msg(sp_login_context,
				idp_login_context->parent.msg_body));
	check_good_rc(lasso_login_accept_sso(sp_login_context));

	/* Cleanup */
cleanup:
	lasso_release_gobject(idp_login_context);
	lasso_release_gobject(sp_login_context);
}

START_TEST(test08_test_authnrequest_flags)
{
	LassoServer *idp_context = NULL;
	LassoServer *sp_context = NULL;
	GList *providers;

	/* Create an IdP context for IdP initiated SSO with provider metadata 1 */
	make_context(idp_context, "idp5-saml2", "", LASSO_PROVIDER_ROLE_SP, "sp5-saml2", "")
	make_context(sp_context, "sp5-saml2", "", LASSO_PROVIDER_ROLE_IDP, "idp5-saml2", "")

	block_lasso_logs;
	sso_initiated_by_sp2(idp_context, sp_context, 
			(SsoSettings) { 
				.use_assertion_consumer_service_idx = 1,
				.assertion_consumer_service_idx = 0,
				.stop_after_build_assertion = 1,
			});
	sso_initiated_by_sp2(idp_context, sp_context, 
			(SsoSettings) { 
				.assertion_consumer_service_url = "http://sp5/singleSignOnPost",
				.stop_after_build_assertion = 1,
			});
	sso_initiated_by_sp2(idp_context, sp_context, 
			(SsoSettings) { 
				.protocol_binding = LASSO_SAML2_METADATA_BINDING_ARTIFACT,
				.stop_after_build_assertion = 1,
			});
	sso_initiated_by_sp2(idp_context, sp_context, 
			(SsoSettings) { 
				.assertion_consumer_service_url = "http://sp5/singleSignOnPost",
				.protocol_binding = LASSO_SAML2_METADATA_BINDING_POST,
				.stop_after_build_assertion = 1,
			});
	sso_initiated_by_sp2(idp_context, sp_context, 
			(SsoSettings) { 
				.assertion_consumer_service_url = "http://sp5/singleSignOnArtifact",
				.protocol_binding = LASSO_SAML2_METADATA_BINDING_ARTIFACT,
				.stop_after_build_assertion = 1,
			});
	sso_initiated_by_sp2(idp_context, sp_context, 
			(SsoSettings) { 
				.assertion_consumer_service_url = "http://sp5/singleSignOnPostAndArtifact",
				.protocol_binding = LASSO_SAML2_METADATA_BINDING_ARTIFACT,
				.stop_after_build_assertion = 1,
			});
	sso_initiated_by_sp2(idp_context, sp_context, 
			(SsoSettings) { 
				.assertion_consumer_service_url = "http://sp5/singleSignOnPostAndArtifact",
				.protocol_binding = LASSO_SAML2_METADATA_BINDING_POST,
				.stop_after_build_assertion = 1,
			});
	unblock_lasso_logs;

	/* Cleanup */
	lasso_release_gobject(idp_context);
	lasso_release_gobject(sp_context);
}
END_TEST

typedef enum {
	ECP_IDP_LIST_NONE,
	ECP_IDP_LIST_ECP,
	ECP_IDP_LIST_BOGUS,
} EcpIdpListVariant;

/* Build an IDPList whose members have an endpoint supporing
 * the protocol_type and http_method.
 */
static LassoNode *
get_idp_list(const LassoServer *server, LassoMdProtocolType protocol_type, LassoHttpMethod http_method)
{
    GList *idp_entity_ids = NULL;
    GList *entity_id = NULL;
    GList *idp_entries = NULL;
    LassoSamlp2IDPList *idp_list;
    LassoSamlp2IDPEntry *idp_entry;

    idp_list = LASSO_SAMLP2_IDP_LIST(lasso_samlp2_idp_list_new());

    idp_entity_ids =
        lasso_server_get_filtered_provider_list(server,
                                                LASSO_PROVIDER_ROLE_IDP,
                                                protocol_type, http_method);

    for (entity_id = g_list_first(idp_entity_ids); entity_id != NULL;
         entity_id = g_list_next(entity_id)) {
        idp_entry = LASSO_SAMLP2_IDP_ENTRY(lasso_samlp2_idp_entry_new());
        idp_entry->ProviderID = g_strdup(entity_id->data);
        idp_entry->Name = g_strdup_printf("[NAME] %s", idp_entry->ProviderID);
        idp_entry->Loc = g_strdup_printf("[LOCATION] %s", idp_entry->ProviderID);

        idp_entries = g_list_append(idp_entries, idp_entry);
    }
    lasso_release_list_of_strings(idp_entity_ids);

    idp_list->IDPEntry = idp_entries;
    return LASSO_NODE(idp_list);
}

static LassoNode *
get_bogus_idp_list()
{
    char *idp_entity_ids[] = {"http://bogus_1/metadata", NULL};
	char **idp_entity_id_iter = NULL;
    char *entity_id = NULL;
    GList *idp_entries = NULL;
    LassoSamlp2IDPList *idp_list;
    LassoSamlp2IDPEntry *idp_entry;

    idp_list = LASSO_SAMLP2_IDP_LIST(lasso_samlp2_idp_list_new());

    for (idp_entity_id_iter = idp_entity_ids, entity_id = *idp_entity_id_iter;
		 *idp_entity_id_iter != NULL;
		 idp_entity_id_iter++) {
        idp_entry = LASSO_SAMLP2_IDP_ENTRY(lasso_samlp2_idp_entry_new());
        idp_entry->ProviderID = g_strdup(entity_id);
        idp_entry->Name = g_strdup_printf("[NAME] %s", idp_entry->ProviderID);
        idp_entry->Loc = g_strdup_printf("[LOCATION] %s", idp_entry->ProviderID);

        idp_entries = g_list_append(idp_entries, idp_entry);
    }

    idp_list->IDPEntry = idp_entries;
    return LASSO_NODE(idp_list);
}

static void validate_idp_list(LassoEcp *ecp, EcpIdpListVariant ecpIDPListVariant, LassoSamlp2IDPList *idp_list)
{
	if (ecpIDPListVariant == ECP_IDP_LIST_NONE) {
		check_null(ecp->sp_idp_list);
		check_null(ecp->known_sp_provided_idp_entries_supporting_ecp);
	} else if (ecpIDPListVariant == ECP_IDP_LIST_ECP || ecpIDPListVariant == ECP_IDP_LIST_BOGUS) {
		GList *ecp_iter, *src_iter;

		check_not_null(ecp->sp_idp_list);
		check_not_null(idp_list);

		check_null(ecp->sp_idp_list->GetComplete);
		check_null(idp_list->GetComplete);

		check_equals(g_list_length(ecp->sp_idp_list->IDPEntry),
					 g_list_length(idp_list->IDPEntry));

		for (ecp_iter = g_list_first(ecp->sp_idp_list->IDPEntry), src_iter = g_list_first(idp_list->IDPEntry);
			 ecp_iter && src_iter;
			 ecp_iter = g_list_next(ecp_iter), src_iter = g_list_next(src_iter)) {
			LassoSamlp2IDPEntry *ecp_item, *src_item;

			ecp_item = LASSO_SAMLP2_IDP_ENTRY(ecp_iter->data);
			src_item = LASSO_SAMLP2_IDP_ENTRY(src_iter->data);

			check_not_null(ecp_item->ProviderID);
			check_not_null(src_item->ProviderID);
			check_str_equals(ecp_item->ProviderID, src_item->ProviderID);

			check_not_null(ecp_item->Name);
			check_not_null(src_item->Name);
			check_str_equals(ecp_item->Name, src_item->Name);

			check_not_null(ecp_item->Loc);
			check_not_null(src_item->Loc);
			check_str_equals(ecp_item->Loc, src_item->Loc);
		}

		if (ecpIDPListVariant == ECP_IDP_LIST_ECP) {
			check_not_null(ecp->known_sp_provided_idp_entries_supporting_ecp);
			for (ecp_iter = g_list_first(ecp->known_sp_provided_idp_entries_supporting_ecp),
				 src_iter = g_list_first(idp_list->IDPEntry);
				 ecp_iter && src_iter;
				 ecp_iter = g_list_next(ecp_iter), src_iter = g_list_next(src_iter)) {
				gchar *ecp_item, *src_item;

				ecp_item = ecp_iter->data;
				src_item = src_iter->data;

				check_not_null(ecp_item);
				check_not_null(src_item);
				check_str_equals(ecp_item, src_item);
			}
		} else {
			check_null(ecp->known_sp_provided_idp_entries_supporting_ecp);
		}

	}
	check_equals(g_list_length(ecp->known_idp_entity_ids_supporting_ecp), 1);
	check_str_equals((char*)g_list_nth(ecp->known_idp_entity_ids_supporting_ecp, 0)->data, "http://idp5/metadata");
}

void test_ecp(EcpIdpListVariant ecpIDPListVariant)
{
	char *serviceProviderContextDump = NULL, *identityProviderContextDump = NULL;
	LassoServer *spContext = NULL, *ecpContext=NULL, *idpContext = NULL;
	LassoLogin *spLoginContext = NULL, *idpLoginContext = NULL;
	LassoEcp *ecp = NULL;
	LassoSamlp2AuthnRequest *request = NULL;
	gboolean is_passive = FALSE;
    char *provider_name = NULL;
	char *relayState = NULL;
	char *messageID = NULL;
	char *spPaosRequestMsg = NULL;
	char *ecpSoapRequestMsg = NULL;
	char *idpSoapResponseMsg = NULL;
	char *ecpPaosResponseMsg = NULL;
	char *spLoginDump = NULL;
	LassoSaml2Assertion *assertion;
    LassoSamlp2IDPList *idp_list = NULL;

	/*
	 * SAML2 Profile for ECP (Section 4.2) defines these steps for an ECP
	 * transaction
	 *
	 * 1. ECP issues HTTP Request to SP
	 * 2. SP issues <AuthnRequest> to ECP using PAOS
	 * 3. ECP determines IdP
	 * 4. ECP conveys <AuthnRequest> to IdP using SOAP
	 * 5. IdP identifies principal
	 * 6. IdP issues <Response> to ECP, targeted at SP using SOAP
	 * 7. ECP conveys <Response> to SP using PAOS
	 * 8. SP grants or denies access to principal
	 */


	/*
	 * Act as the SP who generates an AuthnRequest & conveys it in PAOS
	 */

	/* Create new SP Login Context */
	serviceProviderContextDump = generateServiceProviderContextDump();
	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new(spContext);
	check_not_null(spLoginContext);

	check_good_rc(lasso_login_init_authn_request(spLoginContext, "http://idp5/metadata",
												 LASSO_HTTP_METHOD_PAOS));

	/* Set PAOS authn request parameters */
	request = LASSO_SAMLP2_AUTHN_REQUEST(LASSO_PROFILE(spLoginContext)->request);
	fail_unless(LASSO_IS_SAMLP2_AUTHN_REQUEST(request), "request should be authn_request");
	request->IsPassive = is_passive;

	lasso_assign_string(request->NameIDPolicy->Format, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT);
	request->NameIDPolicy->AllowCreate = 1;

	provider_name = "test_sp_001";
	lasso_assign_string(request->ProviderName, provider_name);

	relayState = "fake[]";
	lasso_assign_string(LASSO_PROFILE(spLoginContext)->msg_relayState, relayState);

	messageID = "id-1234";
	lasso_profile_set_message_id(LASSO_PROFILE(spLoginContext), messageID);

	if (ecpIDPListVariant == ECP_IDP_LIST_ECP) {
		idp_list = LASSO_SAMLP2_IDP_LIST(get_idp_list(spContext,
													  LASSO_MD_PROTOCOL_TYPE_SINGLE_SIGN_ON,
													  LASSO_HTTP_METHOD_SOAP));
		lasso_profile_set_idp_list(LASSO_PROFILE(spLoginContext), LASSO_NODE(idp_list));
	} else if (ecpIDPListVariant == ECP_IDP_LIST_BOGUS) {
		idp_list = LASSO_SAMLP2_IDP_LIST(get_bogus_idp_list());
		lasso_profile_set_idp_list(LASSO_PROFILE(spLoginContext), LASSO_NODE(idp_list));
	}

	/* Build PAOS authn request message */
	check_good_rc(lasso_login_build_authn_request_msg(spLoginContext));

	/*
	 * spPaosRequestMsg is what will be sent back to the ECP client.
     * No reason to validate the contents of spPaosRequestMsg here
     * because in the next step the spPaosRequestMsg will be parsed
     * and we'll validate the parsed values.
	 */
	lasso_assign_string(spPaosRequestMsg, LASSO_PROFILE(spLoginContext)->msg_body);
	check_not_null(spPaosRequestMsg);
	check_null(LASSO_PROFILE(spLoginContext)->msg_url);
	check_not_null(strstr(spPaosRequestMsg, "RelayState"));


	/* Finished with SP Login Context, will create new one later */
	lasso_server_destroy(spContext);
	spContext = NULL;
	spLoginDump = lasso_node_dump(LASSO_NODE(spLoginContext));
	lasso_login_destroy(spLoginContext);
	spLoginContext = NULL;

	/*
	 * Act as the ECP client who just received a PAOS request (spPaosRequestMsg).
	 */

	/* Create an ECP client & load an IdP */
	ecpContext = lasso_server_new(NULL, NULL, NULL, NULL);
	lasso_provider_set_protocol_conformance(LASSO_PROVIDER(ecpContext), LASSO_PROTOCOL_SAML_2_0);

	lasso_server_add_provider(ecpContext, LASSO_PROVIDER_ROLE_IDP,
							  TESTSDATADIR "/idp5-saml2/metadata.xml", NULL, NULL);

	ecp = lasso_ecp_new(ecpContext);
	check_not_null(ecp);

	/* parse the spPaosRequestMsg */
	check_good_rc(lasso_ecp_process_authn_request_msg(ecp, spPaosRequestMsg));

	/* Validate ECP properties received in the spPaosRequestMsg */
	check_null(ecp->assertion_consumer_url);
	check_str_equals(ecp->response_consumer_url, "http://sp5/singleSignOnSOAP");
	check_str_equals(ecp->message_id, messageID);
	check_str_equals(ecp->relaystate, relayState);
	check_str_equals(ecp->issuer->content, "http://sp5/metadata");
	check_str_equals(ecp->provider_name, provider_name);
    check_equals(ecp->is_passive, is_passive);

	/* Validate ECP IdP list info & default IdP URL */
	validate_idp_list(ecp, ecpIDPListVariant, idp_list);
	check_str_equals(LASSO_PROFILE(ecp)->msg_url, "http://idp5/singleSignOnSOAP");

	/*
	 * ecpSoapRequestMsg is what we'll post to the IdP at the msg_url.
     */
	lasso_assign_string(ecpSoapRequestMsg, LASSO_PROFILE(ecp)->msg_body);
	check_not_null(ecpSoapRequestMsg);

	/*
	 * Act as the IdP which just received the SOAP request (ecpSoapRequestMsg)
	 */

	/* Create an IdP */
	identityProviderContextDump = generateIdentityProviderContextDump();
	idpContext = lasso_server_new_from_dump(identityProviderContextDump);
	idpLoginContext = lasso_login_new(idpContext);
	check_not_null(idpLoginContext);

	/* Parse the ecpSoapRequestMsg */
	check_good_rc(lasso_login_process_authn_request_msg(idpLoginContext, ecpSoapRequestMsg));

	check_true(lasso_login_must_authenticate(idpLoginContext));
	check_equals(idpLoginContext->protocolProfile, LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_LECP);
	check_false(lasso_login_must_ask_for_consent(idpLoginContext));
	check_good_rc(lasso_login_validate_request_msg(idpLoginContext,
			1, /* authentication_result */
			0  /* is_consent_obtained */ ));

	/* Build IdP response */

	check_good_rc(lasso_login_build_assertion(idpLoginContext,
			LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD,
			"FIXME: authenticationInstant",
			"FIXME: reauthenticateOnOrAfter",
			"FIXME: notBefore",
			"FIXME: notOnOrAfter"));
	assertion = (LassoSaml2Assertion*)lasso_login_get_assertion(idpLoginContext);
	check_true(LASSO_IS_SAML2_ASSERTION(assertion));
	lasso_saml2_assertion_set_basic_conditions(LASSO_SAML2_ASSERTION(assertion), 60, 120, FALSE);
	lasso_release_gobject(assertion);

	/* Build IdP SOAP response message */
	check_good_rc(lasso_login_build_response_msg(idpLoginContext, NULL));

	/* idpSoapResponseMsg is what we'll send back to the ECP client */
	lasso_assign_string(idpSoapResponseMsg, LASSO_PROFILE(idpLoginContext)->msg_body);
	check_not_null(idpSoapResponseMsg);

	/*
	 * Resume acting as the ECP client, process IdP response
	 */

	check_good_rc(lasso_ecp_process_response_msg(ecp, idpSoapResponseMsg));

	/* Validate ECP properties, only the assertion_consumer_url should have changed */
	check_str_equals(ecp->assertion_consumer_url, "http://sp5/singleSignOnSOAP");
	check_str_equals(ecp->response_consumer_url, "http://sp5/singleSignOnSOAP");
	check_str_equals(ecp->response_consumer_url, ecp->assertion_consumer_url); /* MUST match! */

	check_str_equals(ecp->message_id, messageID);
	check_str_equals(ecp->relaystate, relayState);
	check_str_equals(ecp->issuer->content, "http://sp5/metadata");
	check_str_equals(ecp->provider_name, provider_name);
    check_equals(ecp->is_passive, is_passive);

	/* Validate ECP IdP list info */
	validate_idp_list(ecp, ecpIDPListVariant, idp_list);

	lasso_assign_string(ecpPaosResponseMsg, LASSO_PROFILE(ecp)->msg_body);
	check_not_null(ecpPaosResponseMsg);
	check_str_equals(LASSO_PROFILE(ecp)->msg_url, ecp->assertion_consumer_url);

	/* Act as the SP again which has just been posted the ecpPaosResponseMsg */

	/* Create new SP Login Context */
	spContext = lasso_server_new_from_dump(serviceProviderContextDump);
	spLoginContext = lasso_login_new(spContext);
	check_not_null(spLoginContext);

	/* Parse the ecpPaosResponseMsg */
	check_good_rc(lasso_login_process_paos_response_msg(spLoginContext, ecpPaosResponseMsg));

	/* Verify we got back the same relayState and messageID */
	check_str_equals(LASSO_PROFILE(spLoginContext)->msg_relayState, relayState);
	check_str_equals(lasso_profile_get_message_id(LASSO_PROFILE(spLoginContext)), messageID);


	g_free(serviceProviderContextDump);
	g_free(identityProviderContextDump);

	lasso_release_gobject(spContext);
	lasso_release_gobject(ecpContext);
	lasso_release_gobject(idpContext);

	lasso_release_gobject(spLoginContext);
	lasso_release_gobject(idpLoginContext);

	lasso_release_gobject(ecp);

	lasso_release_string(spLoginDump);
	lasso_release_string(spPaosRequestMsg);
	lasso_release_string(ecpSoapRequestMsg);
	lasso_release_string(idpSoapResponseMsg);
	lasso_release_string(ecpPaosResponseMsg);

	lasso_release_gobject(idp_list);

}

START_TEST(test09_ecp)
{
	test_ecp(ECP_IDP_LIST_NONE);
}
END_TEST

START_TEST(test10_ecp)
{
	test_ecp(ECP_IDP_LIST_ECP);
}
END_TEST

START_TEST(test11_ecp)
{
	test_ecp(ECP_IDP_LIST_BOGUS);
}
END_TEST

Suite*
login_saml2_suite()
{
	Suite *s = suite_create("Login using SAML 2.0");
	TCase *tc_generate = tcase_create("Generate Server Contexts");
	TCase *tc_spLogin = tcase_create("Login initiated by service provider");
	TCase *tc_spLoginMemory = tcase_create("Login initiated by service provider without key loading");
	TCase *tc_spSloSoap = tcase_create("Login initiated by service provider without key loading and with SLO SOAP");
	TCase *tc_idpKeyRollover = tcase_create("Login initiated by idp, idp use two differents signing keys (simulate key roll-over)");
	TCase *tc_spKeyRollover = tcase_create("Login initiated by idp, sp use two differents encrypting keys (simulate key roll-over)");
	TCase *tc_hmacSignature = tcase_create("Login initiated by sp, using shared-key signature");
	TCase *tc_ecp = tcase_create("ECP Login");
	suite_add_tcase(s, tc_generate);
	suite_add_tcase(s, tc_spLogin);
	suite_add_tcase(s, tc_spLoginMemory);
	suite_add_tcase(s, tc_spSloSoap);
	suite_add_tcase(s, tc_idpKeyRollover);
	suite_add_tcase(s, tc_spKeyRollover);
	suite_add_tcase(s, tc_hmacSignature);
	suite_add_tcase(s, tc_ecp);
	tcase_add_test(tc_generate, test01_saml2_generateServersContextDumps);
	tcase_add_test(tc_spLogin, test02_saml2_serviceProviderLogin);
	tcase_add_test(tc_spLoginMemory, test03_saml2_serviceProviderLogin);
	tcase_add_test(tc_spSloSoap, test04_sso_then_slo_soap);
	tcase_add_test(tc_idpKeyRollover, test05_sso_idp_with_key_rollover);
	tcase_add_test(tc_spKeyRollover, test06_sso_sp_with_key_rollover);
	tcase_add_test(tc_hmacSignature, test07_sso_sp_with_hmac_sha1_signatures);
	tcase_add_test(tc_spLogin, test08_test_authnrequest_flags);
	tcase_add_test(tc_ecp, test09_ecp);
	tcase_add_test(tc_ecp, test10_ecp);
	tcase_add_test(tc_ecp, test11_ecp);
	return s;
}

