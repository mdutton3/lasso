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

#include "../lasso/lasso.h"
#include <glib.h>
#include "../lasso/utils.h"

#include "../lasso/id-ff/login.h"
#include "../lasso/id-ff/server.h"
#include "../lasso/id-ff/identity.h"
#include "../lasso/id-ff/session.h"
#include "../lasso/id-wsf-2.0/discovery.h"
#include "../lasso/id-wsf-2.0/data_service.h"
#include "../lasso/id-wsf-2.0/saml2_login.h"

#include "../lasso/xml/saml-2.0/samlp2_authn_request.h"
#include "../lasso/xml/idwsf_strings.h"

#include "tests.h"

static const char
wsp_metadata[] = TESTSDATADIR "sp5-saml2/metadata.xml";
static const char
wsp_private_key[] = TESTSDATADIR "sp5-saml2/private-key.pem";
static const char
wsc_metadata[] = TESTSDATADIR "sp6-saml2/metadata.xml";
static const char
wsc_private_key[] = TESTSDATADIR "sp6-saml2/private-key.pem";
static const char
idp_metadata[] = TESTSDATADIR "idp5-saml2/metadata.xml";
static const char
idp_private_key[] = TESTSDATADIR "idp5-saml2/private-key.pem";
static const char
service_type[] = "urn:test-service";


struct
IdPState {
	LassoLogin *login;
	LassoIdWsf2Discovery *discovery;
	LassoServer *server;
	LassoIdentity *identity;
	LassoSession *session;
};

struct
SPState {
	LassoLogin *login;
	LassoIdWsf2Discovery *discovery;
	LassoIdWsf2DataService *dataservice;
	LassoServer *server;
	LassoIdentity *identity;
	LassoSession *session;
};

static LassoServer*
get_wsc_server() {
	LassoServer *server;
	server = lasso_server_new(wsc_metadata, wsc_private_key, NULL, NULL);
	lasso_server_add_provider(server, LASSO_PROVIDER_ROLE_IDP, idp_metadata, NULL, NULL);
	return server;
}

static
LassoServer*
get_wsp_server() {
	LassoServer *server = lasso_server_new(wsp_metadata, wsp_private_key, NULL, NULL);
	lasso_server_add_provider(server, LASSO_PROVIDER_ROLE_IDP, idp_metadata, NULL, NULL);
	return server;
}

static
LassoServer*
get_idp_server() {
	LassoServer *server = lasso_server_new(idp_metadata, idp_private_key, NULL, NULL);
	check_good_rc(lasso_server_add_provider(server, LASSO_PROVIDER_ROLE_SP, wsp_metadata, NULL, NULL));
	check_good_rc(lasso_server_add_provider(server, LASSO_PROVIDER_ROLE_SP, wsc_metadata, NULL, NULL));
	return server;
}

static void
prepare_idp(struct IdPState *idpstate) {
	check_not_null(idpstate->server = get_idp_server());
	check_not_null(idpstate->identity = lasso_identity_new());
	check_not_null(idpstate->session = lasso_session_new());
	check_not_null(idpstate->login = lasso_login_new(idpstate->server));
	lasso_assign_gobject(idpstate->login->parent.identity, idpstate->identity);
	lasso_assign_gobject(idpstate->login->parent.session, idpstate->session);
	idpstate->discovery = lasso_idwsf2_discovery_new(idpstate->server);
	lasso_assign_gobject(idpstate->discovery->parent.parent.identity, idpstate->identity);
	lasso_assign_gobject(idpstate->discovery->parent.parent.session, idpstate->session);
}

static void
prepare_wsp(struct SPState *spstate) {
	spstate->server = get_wsp_server();
	spstate->identity = lasso_identity_new();
	spstate->session = lasso_session_new();
	spstate->login = lasso_login_new(spstate->server);
	lasso_assign_gobject(spstate->login->parent.identity, spstate->identity);
	lasso_assign_gobject(spstate->login->parent.session, spstate->session);
	spstate->discovery = lasso_idwsf2_discovery_new(spstate->server);
	lasso_assign_gobject(spstate->discovery->parent.parent.identity, spstate->identity);
	lasso_assign_gobject(spstate->discovery->parent.parent.session, spstate->session);
	spstate->dataservice = lasso_idwsf2_data_service_new(spstate->server);
	lasso_assign_gobject(spstate->dataservice->parent.parent.identity, spstate->identity);
	lasso_assign_gobject(spstate->dataservice->parent.parent.session, spstate->session);

}

static void
prepare_wsc(struct SPState *spstate) {
	spstate->server = get_wsc_server();
	spstate->identity = lasso_identity_new();
	spstate->session = lasso_session_new();
	spstate->login = lasso_login_new(spstate->server);
	lasso_assign_gobject(spstate->login->parent.identity, spstate->identity);
	lasso_assign_gobject(spstate->login->parent.session, spstate->session);
	spstate->discovery = lasso_idwsf2_discovery_new(spstate->server);
	lasso_assign_gobject(spstate->discovery->parent.parent.identity, spstate->identity);
	lasso_assign_gobject(spstate->discovery->parent.parent.session, spstate->session);
	spstate->dataservice = lasso_idwsf2_data_service_new(spstate->server);
	lasso_assign_gobject(spstate->dataservice->parent.parent.identity, spstate->identity);
	lasso_assign_gobject(spstate->dataservice->parent.parent.session, spstate->session);

}

static void
prepare_saml2_authn_request(LassoLogin *splogin, LassoLogin *idplogin)
{
	LassoSamlp2AuthnRequest *request;

	check_good_rc(lasso_login_init_authn_request(splogin, idplogin->parent.server->parent.ProviderID, LASSO_HTTP_METHOD_REDIRECT));
	check_not_null(request = LASSO_SAMLP2_AUTHN_REQUEST(splogin->parent.request));
	request->IsPassive = 0;
	request->NameIDPolicy->AllowCreate = 1;
	check_good_rc(lasso_login_build_authn_request_msg(splogin));

}

static void
process_authn_request(LassoLogin *splogin, LassoLogin *idplogin)
{
	GList node = { .data = LASSO_SECURITY_MECH_BEARER, .next = NULL };

	check_good_rc(lasso_login_process_authn_request_msg(idplogin, strchr(splogin->parent.msg_url,'?')+1));
	lasso_login_must_authenticate(idplogin);
	check_false(lasso_login_must_ask_for_consent(idplogin));
	check_good_rc(lasso_login_validate_request_msg(idplogin, 1, 0));
	check_good_rc(lasso_login_build_assertion(idplogin,
			LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD,
			"FIXME: authenticationInstant",
			"FIXME: reauthenticateOnOrAfter",
			"FIXME: notBefore",
			"FIXME: notOnOrAfter"));
	check_good_rc(lasso_login_idwsf2_add_discovery_bootstrap_epr(idplogin,
				"http://example.com/disco", "Discovery Service Description",
				&node, -1, 0));
	check_good_rc(lasso_login_build_artifact_msg(idplogin, LASSO_HTTP_METHOD_ARTIFACT_GET));
}

static void
login_to_idp(struct IdPState *idpstate, struct SPState *spstate)
{
	// generate request
	prepare_saml2_authn_request(spstate->login, idpstate->login);
	// send request to idp
	// build assertion
	// add disco token
	// generate response artifact
	process_authn_request(spstate->login, idpstate->login);
	// process artifact
	// get response
	// process response
}

static void
register_metadata(G_GNUC_UNUSED struct IdPState *idpstate, G_GNUC_UNUSED struct SPState *wspstate)
{
}

static void
register_data_service(G_GNUC_UNUSED struct IdPState *idpstate, G_GNUC_UNUSED struct SPState *wspstate, G_GNUC_UNUSED const char *service_type)
{
}

static void
query_disco(G_GNUC_UNUSED struct IdPState *idpstate, G_GNUC_UNUSED struct SPState *wscstate, G_GNUC_UNUSED const char *service_type)
{
}

static void
query_data_service(G_GNUC_UNUSED struct SPState *wspstate, G_GNUC_UNUSED struct SPState *wscstate, G_GNUC_UNUSED int index, G_GNUC_UNUSED char *query, G_GNUC_UNUSED char *data)
{
}

void
free_idpstate(struct IdPState *idpstate)
{
	lasso_release_gobject(idpstate->login);
	lasso_release_gobject(idpstate->discovery);
	lasso_release_gobject(idpstate->server);
	lasso_release_gobject(idpstate->identity);
	lasso_release_gobject(idpstate->session);
}

void
free_spstate(struct SPState *spstate)
{
	lasso_release_gobject(spstate->login);
	lasso_release_gobject(spstate->discovery);
	lasso_release_gobject(spstate->dataservice);
	lasso_release_gobject(spstate->identity);
	lasso_release_gobject(spstate->session);
	lasso_release_gobject(spstate->server);
}


START_TEST(test01_simple_data_query)
{
	struct IdPState idpstate;
	struct SPState wspstate, wscstate;

	prepare_idp(&idpstate);
	// check somes values
	prepare_wsp(&wspstate);
	// check somes values
	prepare_wsc(&wscstate);
	login_to_idp(&idpstate, &wspstate);
	register_metadata(&idpstate, &wspstate);
	register_data_service(&idpstate, &wspstate, service_type);
	login_to_idp(&idpstate, &wscstate);
	query_disco(&idpstate, &wspstate, service_type);
	query_data_service(&wspstate, &wscstate, 0, "/test", "<test/>");
	free_spstate(&wscstate);
	free_spstate(&wspstate);
	free_idpstate(&idpstate);
}
END_TEST


Suite*
idwsf2_suite()
{
	Suite *s = suite_create("IdWsf2");
	TCase *tc_idwsf2_base = tcase_create("Login, Disco, DST queries");

	suite_add_tcase(s, tc_idwsf2_base);
	tcase_add_test(tc_idwsf2_base, test01_simple_data_query);

	return s;
}
