/*
 * Lasso library performance tests
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

#include <lasso.h>

char* create_authn_response_msg(char *query);

char*
create_authn_response_msg(char *query)
{
	LassoServer *server;
	LassoLogin *login;
	char *t;
	int rc;

	server = lasso_server_new(
			TESTSDATADIR "/idp1-la/metadata.xml",
			TESTSDATADIR "/idp1-la/private-key-raw.pem",
			NULL, /* Secret key to unlock private key */
			TESTSDATADIR "/idp1-la/certificate.pem");
	lasso_server_add_provider(
			server,
			LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp1-la/metadata.xml",
			TESTSDATADIR "/sp1-la/public-key.pem",
			TESTSDATADIR "/ca1-la/certificate.pem");

	login = lasso_login_new(server);
	rc = lasso_login_process_authn_request_msg(login, strchr(query, '?')+1);

	rc = lasso_login_validate_request_msg(login, 1, 0);
	rc = lasso_login_build_assertion(login,
			LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD,
			"FIXME: authenticationInstant",
			"FIXME: reauthenticateOnOrAfter",
			"FIXME: notBefore",
			"FIXME: notOnOrAfter");
	rc = lasso_login_build_authn_response_msg(login);

	t = g_strdup(LASSO_PROFILE(login)->msg_body);
	lasso_login_destroy(login);
	lasso_server_destroy(server);

	return t;
}

int
main(int argc, char *argv[])
{
	LassoServer *server;
	LassoLogin *login;
	LassoLibAuthnRequest *request;
	int i, n;
	struct timeval start, end;
	int usec;
	char *authn_response_msg;

	lasso_init();
	
	server = lasso_server_new(
			TESTSDATADIR "/sp1-la/metadata.xml",
			TESTSDATADIR "/sp1-la/private-key-raw.pem",
			NULL, /* Secret key to unlock private key */
			TESTSDATADIR "/sp1-la/certificate.pem");
	lasso_server_add_provider(
			server,
			LASSO_PROVIDER_ROLE_IDP,
			TESTSDATADIR "/idp1-la/metadata.xml",
			TESTSDATADIR "/idp1-la/public-key.pem",
			TESTSDATADIR "/ca1-la/certificate.pem");

	n = 100;
	if (argc == 2) {
		n = atoi(argv[1]);
	}

	login = lasso_login_new(server);

	fprintf(stdout, "Generating %d AuthnRequest...\n", n);
	gettimeofday(&start, NULL);
	for (i=0; i < n; i++) {
		fprintf(stderr, ".");
		lasso_login_init_authn_request(login, "https://idp1/metadata",
				LASSO_HTTP_METHOD_REDIRECT);
		request = LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request);
		request->IsPassive = 0;
		request->NameIDPolicy = g_strdup(LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED);
		request->consent = g_strdup(LASSO_LIB_CONSENT_OBTAINED);
		request->ProtocolProfile = g_strdup(LASSO_LIB_PROTOCOL_PROFILE_BRWS_POST);
		lasso_login_build_authn_request_msg(login);
		if ((i+1)%70 == 0) {
			fprintf(stderr, " %d \n", i+1);
		}
	}
	if ((i)%70 != 0) {
		fprintf(stderr, " %d \n", i);
	}
	gettimeofday(&end, NULL);
	usec = (end.tv_sec*1000000+end.tv_usec)-(start.tv_sec*1000000+start.tv_usec);
	fprintf(stdout, " total: %.4f seconds (%f request/second) (%.2f ms/request)\n",
			(double)usec/1000000,
			(double)n/usec*1000000,
			(double)usec/1000/n);

	authn_response_msg = create_authn_response_msg(LASSO_PROFILE(login)->msg_url);

	fprintf(stdout, "Processing %d AuthnResponse...\n", n);
	gettimeofday(&start, NULL);
	for (i=0; i < n; i++) {
		fprintf(stderr, ".");
		lasso_login_process_authn_response_msg(login, authn_response_msg);
		lasso_login_accept_sso(login);
		if ((i+1)%70 == 0) {
			fprintf(stderr, " %d \n", i+1);
		}
	}
	if ((i)%70 != 0) {
		fprintf(stderr, " %d \n", i);
	}
	gettimeofday(&end, NULL);
	usec = (end.tv_sec*1000000+end.tv_usec)-(start.tv_sec*1000000+start.tv_usec);
	fprintf(stdout, " total: %.4f seconds (%f request/second) (%.2f ms/request)\n",
			(double)usec/1000000,
			(double)n/usec*1000000,
			(double)usec/1000/n);



	return 0;
}

