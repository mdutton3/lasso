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
#include <check.h>
#include <lasso/lasso.h>


char *generateIdentityProviderContextDump() {
	LassoServer *serverContext = lasso_server_new(
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
	char *serverContextDump = lasso_server_dump(serverContext);
	return serverContextDump;
}

START_TEST(test01_generateServersContextDumps)
{
	char *identityProviderContextDump = generateIdentityProviderContextDump();
	fail_unless(identityProviderContextDump != NULL,
		"generateIdentityProviderContextDump should not return NULL");
}
END_TEST

Suite* login_suite()
{
	Suite *s = suite_create("Login");
	TCase *tc_generate = tcase_create("Generate Server Contexts");
	suite_add_tcase(s, tc_generate);
	tcase_add_test(tc_generate, test01_generateServersContextDumps);
	return s;
}

int main(int argc, char *argv[])
{
	int rc;
	Suite *s;
	SRunner *sr;

	lasso_init();
	
	s = login_suite();
	sr = srunner_create(s);
	srunner_run_all (sr, CK_VERBOSE);
	rc = srunner_ntests_failed(sr);
	
	srunner_free(sr);
	suite_free(s);

	/*lasso_destroy();*/

	return (rc == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

