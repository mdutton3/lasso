/*
 * Lasso library performance tests
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

#include <sys/time.h>
#include <time.h>
#include <getopt.h>

#include "../lasso/lasso.h"
#include "../lasso/xml/saml-2.0/samlp2_response.h"
#include "../lasso/xml/saml-2.0/samlp2_authn_request.h"

#define IDP_METADATA TESTSDATADIR "/idp%s/metadata.xml"
#define IDP_PKEY TESTSDATADIR "/idp%s/private-key.pem"
#define SP_METADATA TESTSDATADIR "/sp%s/metadata.xml"
#define SP_PKEY TESTSDATADIR "/sp%s/private-key.pem"

char* create_authn_response_msg(char *query);

#define check_good_rc(what) \
	{ \
		int _rc = (what); \
		if (_rc != 0) { \
			printf("Error: %s: %s", #what, lasso_strerror(_rc)); \
			exit(-1); \
		} \
	}

void create_authn_request(LassoLogin *sp_login, G_GNUC_UNUSED LassoLogin *idp_login)
{

	check_good_rc(lasso_login_init_authn_request(sp_login, NULL, LASSO_HTTP_METHOD_REDIRECT));
	LASSO_SAMLP2_AUTHN_REQUEST(sp_login->parent.request)->ProtocolBinding = g_strdup(LASSO_SAML2_METADATA_BINDING_POST);
	check_good_rc(lasso_login_build_authn_request_msg(sp_login));
}

void
process_authn_request(LassoLogin *sp_login, LassoLogin *idp_login)
{
	check_good_rc(lasso_login_process_authn_request_msg(idp_login, strchr(sp_login->parent.msg_url, '?')+1));

}

void
create_authn_response(G_GNUC_UNUSED LassoLogin *sp_login, LassoLogin *idp_login)
{
	if (LASSO_SAMLP2_RESPONSE(idp_login->parent.response)->Assertion) {
		g_object_unref(LASSO_SAMLP2_RESPONSE(idp_login->parent.response)->Assertion->data);
		g_list_free(LASSO_SAMLP2_RESPONSE(idp_login->parent.response)->Assertion);
		LASSO_SAMLP2_RESPONSE(idp_login->parent.response)->Assertion = NULL;
	}
	check_good_rc(lasso_login_validate_request_msg(idp_login, 1, 0));
	lasso_login_build_assertion(idp_login,
			LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD,
			"FIXME: authenticationInstant",
			"FIXME: reauthenticateOnOrAfter",
			"FIXME: notBefore",
			"FIXME: notOnOrAfter");
#if 0 /* activate for simulating simple signature at the assertion level, request/response
	 production should be at the same speed */
	lasso_profile_set_signature_hint(&idp_login->parent, LASSO_PROFILE_SIGNATURE_HINT_FORBID);
#endif
	check_good_rc(lasso_login_build_authn_response_msg(idp_login));
}

void
process_authn_response(LassoLogin *sp_login, LassoLogin *idp_login)
{
#if 0
		lasso_profile_set_signature_verify_hint(&sp_login->parent, LASSO_PROFILE_SIGNATURE_VERIFY_HINT_FORCE);
#endif
		check_good_rc(lasso_login_process_authn_response_msg(sp_login, idp_login->parent.msg_body));
		if (sp_login->parent.session) {
			g_object_unref(sp_login->parent.session);
			sp_login->parent.session = NULL;
		}
		check_good_rc(lasso_login_accept_sso(sp_login));
}

void timing(int n, char *text, void (*f)(LassoLogin *sp_login, LassoLogin *idp_login), LassoLogin
		*sp_login, LassoLogin *idp_login)
{
	int i;
	struct timeval start, end;
	int usec;
	fprintf(stdout, text, n);
	gettimeofday(&start, NULL);

	for (i = 0; i < n; i++) {
		f(sp_login, idp_login);
	}
	gettimeofday(&end, NULL);
	usec = (end.tv_sec*1000000+end.tv_usec)-(start.tv_sec*1000000+start.tv_usec);
	fprintf(stdout, " total: %.4f seconds (%f request/second) (%.2f ms/request)\n",
			(double)usec/1000000,
			(double)n/usec*1000000,
			(double)usec/1000/n);
}

int
main(int argc, char *argv[])
{
	LassoServer *sp_server, *idp_server;
	LassoLogin *sp_login, *idp_login;
	int n = 100;
	char sp_metadata[100], sp_pkey[100],
	     idp_metadata[100], idp_pkey[100];
	char *index = "5-saml2";
	GList *providers;
	LassoKey *key;
	LassoProvider *provider;
	gboolean use_shared_secret = FALSE;
	int opt = 0;

	while ((opt = getopt(argc, argv, "hn:s:")) != -1) {
		switch (opt) {
			case 'h':
				use_shared_secret = TRUE;
				break;
			case 'n':
				n = atoi(optarg);
				break;
			case 's':
				index = optarg;
				break;
		}
	}

	printf("Looping %d times, %susing metadata %s\n", n,
			use_shared_secret ? "with shared secret key, " : "", index);

	sprintf(sp_metadata, SP_METADATA, index);
	sprintf(sp_pkey, SP_PKEY, index);
	sprintf(idp_metadata, IDP_METADATA, index);
	sprintf(idp_pkey, IDP_PKEY, index);

	lasso_init();

	sp_server = lasso_server_new(
			sp_metadata,
			sp_pkey,
			NULL, /* Secret key to unlock private key */
			NULL);
	lasso_server_add_provider(
			sp_server,
			LASSO_PROVIDER_ROLE_IDP,
			idp_metadata,
			idp_pkey,
			NULL);
	if (use_shared_secret) {
		key = lasso_key_new_for_signature_from_memory("xxxxxxxxxxxxxxxx", 16,
				NULL, LASSO_SIGNATURE_METHOD_HMAC_SHA1, NULL);
		providers = g_hash_table_get_values(sp_server->providers);
		provider = LASSO_PROVIDER(providers->data);
		lasso_provider_set_server_signing_key(provider, key);
		lasso_provider_add_key(provider, key, FALSE);
		g_list_free(providers);
	}

	idp_server = lasso_server_new(
			idp_metadata,
			idp_pkey,
			NULL, /* Secret key to unlock private key */
			NULL);
	lasso_server_add_provider(
			idp_server,
			LASSO_PROVIDER_ROLE_SP,
			sp_metadata,
			sp_pkey,
			NULL);
	if (use_shared_secret) {
		providers = g_hash_table_get_values(idp_server->providers);
		provider = LASSO_PROVIDER(providers->data);
		lasso_provider_set_server_signing_key(provider, key);
		lasso_provider_add_key(provider, key, FALSE);
		g_list_free(providers);
	}

	sp_login = lasso_login_new(sp_server);
	idp_login = lasso_login_new(idp_server);

	timing(n, "Generating %d AuthnRequest...\n", create_authn_request, sp_login, idp_login);
#if 0
	printf("%s\n", lasso_node_export_to_xml(sp_login->parent.request));
#endif
	timing(n, "Processing %d AuthnRequest...\n", process_authn_request, sp_login, idp_login);
	timing(n, "Generating %d AuthnResponse...\n", create_authn_response, sp_login, idp_login);
#if 0
	printf("%s\n", lasso_node_export_to_xml(idp_login->parent.response));
#endif
	timing(n, "Processing %d AuthnResponse...\n", process_authn_response, sp_login, idp_login);

	return 0;
}

