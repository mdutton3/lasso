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

Suite* random_suite();

START_TEST(test01_provider_new)
{
	LassoProvider *provider;
	char *dump;

	provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp1-la/metadata.xml",
			TESTSDATADIR "/sp1-la/public-key.pem",
			TESTSDATADIR "/ca1-la/certificate.pem");

	dump = lasso_node_dump(LASSO_NODE(provider));
	printf("dump:\n%s\n", dump);
}
END_TEST

START_TEST(test02_provider_new_from_dump)
{
	LassoProvider *provider1, *provider2;
	char *dump;

	provider1 = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp1-la/metadata.xml",
			TESTSDATADIR "/sp1-la/public-key.pem",
			TESTSDATADIR "/ca1-la/certificate.pem");

	dump = lasso_node_dump(LASSO_NODE(provider1));

	provider2 = lasso_provider_new_from_dump(dump);
	dump = lasso_node_dump(LASSO_NODE(provider2));
	printf("dump:\n%s\n", dump);
}
END_TEST

START_TEST(test01_server_new)
{
	LassoServer *server;
	char *dump;

	server = lasso_server_new(
			TESTSDATADIR "/idp1-la/metadata.xml",
			TESTSDATADIR "/idp1-la/private-key-raw.pem",
			NULL, /* Secret key to unlock private key */
			TESTSDATADIR "/idp1-la/certificate.pem");

	dump = lasso_node_dump(LASSO_NODE(server));
	printf("dump:\n%s\n", dump);
}
END_TEST

START_TEST(test02_server_add_provider)
{
	LassoServer *server;
	char *dump;

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

	dump = lasso_node_dump(LASSO_NODE(server));
	printf("dump:\n%s\n", dump);
}
END_TEST

START_TEST(test03_server_new_from_dump)
{
	LassoServer *server1, *server2;
	char *dump;

	server1 = lasso_server_new(
			TESTSDATADIR "/idp1-la/metadata.xml",
			TESTSDATADIR "/idp1-la/private-key-raw.pem",
			NULL, /* Secret key to unlock private key */
			TESTSDATADIR "/idp1-la/certificate.pem");
	lasso_server_add_provider(
			server1,
			LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp1-la/metadata.xml",
			TESTSDATADIR "/sp1-la/public-key.pem",
			TESTSDATADIR "/ca1-la/certificate.pem");

	dump = lasso_node_dump(LASSO_NODE(server1));

	server2 = lasso_server_new_from_dump(dump);
	dump = lasso_node_dump(LASSO_NODE(server2));
	printf("dump:\n%s\n", dump);
}
END_TEST

START_TEST(test04_node_new_from_dump)
{
	LassoNode *node;

	char *msg = \
	  "<lib:LogoutRequest xmlns:lib=\"urn:liberty:iff:2003-08\" "\
	  "xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" "\
	  "RequestID=\"_52EDD5A8A0BF74977C0A16B827CA4229\" MajorVersion=\"1\" "\
	  "MinorVersion=\"2\" IssueInstant=\"2004-12-04T11:05:26Z\">" \
	  "<lib:ProviderID>https://idp1/metadata</lib:ProviderID>" \
	  "<saml:NameIdentifier xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" "\
	  "NameQualifier=\"https://idp1/metadata\" "\
	  "Format=\"urn:liberty:iff:nameid:federated\">_AF452F97C9E1590DDEB91D5BA6AA48ED"\
	  "</saml:NameIdentifier>"\
	  "</lib:LogoutRequest>";

	node = lasso_node_new_from_dump(msg);
	fail_unless(node != NULL, "new_from_dump failed");
}
END_TEST

Suite*
random_suite()
{
	Suite *s = suite_create("Random tests");
	TCase *tc_providers = tcase_create("Provider stuffs");
	TCase *tc_servers = tcase_create("Server stuffs");
	TCase *tc_node = tcase_create("Node stuff");

	suite_add_tcase(s, tc_providers);
	tcase_add_test(tc_providers, test01_provider_new);
	tcase_add_test(tc_providers, test02_provider_new_from_dump);

	suite_add_tcase(s, tc_servers);
	tcase_add_test(tc_servers, test01_server_new);
	tcase_add_test(tc_servers, test02_server_add_provider);
	tcase_add_test(tc_servers, test03_server_new_from_dump);

	suite_add_tcase(s, tc_node);
	tcase_add_test(tc_node, test04_node_new_from_dump);

	return s;
}

