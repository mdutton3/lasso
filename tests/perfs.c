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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/time.h>
#include <time.h>

#include <../lasso/lasso.h>
#include <../lasso/xml/saml-2.0/samlp2_response.h>
#include <../lasso/xml/saml-2.0/samlp2_authn_request.h>

#define INDEX "5"
#define PROTO "saml2"
#define IDP_METADATA TESTSDATADIR "/idp" INDEX "-" PROTO "/metadata.xml"
#define IDP_PKEY TESTSDATADIR "/idp" INDEX "-" PROTO "/private-key.pem"
#define SP_METADATA TESTSDATADIR "/sp" INDEX "-" PROTO "/metadata.xml"
#define SP_PKEY TESTSDATADIR "/sp" INDEX "-" PROTO "/private-key.pem"

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
	int n;

	lasso_init();

	sp_server = lasso_server_new(
			SP_METADATA,
			SP_PKEY,
			NULL, /* Secret key to unlock private key */
			NULL);
	lasso_server_add_provider(
			sp_server,
			LASSO_PROVIDER_ROLE_IDP,
			IDP_METADATA,
			IDP_PKEY,
			NULL);
	idp_server = lasso_server_new(
			IDP_METADATA,
			IDP_PKEY,
			NULL, /* Secret key to unlock private key */
			NULL);
	lasso_server_add_provider(
			idp_server,
			LASSO_PROVIDER_ROLE_SP,
			SP_METADATA,
			SP_PKEY,
			NULL);

	n = 100;
	if (argc == 2) {
		n = atoi(argv[1]);
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

