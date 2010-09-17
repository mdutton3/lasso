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

#include <../lasso/xml/lib_assertion.h>
#include <../lasso/xml/lib_authentication_statement.h>
#include <../lasso/xml/saml_name_identifier.h>
#include <../lasso/xml/samlp_response.h>
#include "../lasso/utils.h"


Suite* random_suite();

START_TEST(test01_provider_new)
{
	LassoProvider *provider;
	char *dump;

	provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp1-la/metadata.xml",
			TESTSDATADIR "/sp1-la/public-key.pem",
			TESTSDATADIR "/ca1-la/certificate.pem");
	fail_unless(LASSO_IS_PROVIDER(provider));

	dump = lasso_node_dump(LASSO_NODE(provider));
	fail_unless(dump != NULL);
	g_object_unref(provider);
	lasso_release_string(dump);
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
	fail_unless(LASSO_IS_PROVIDER(provider1));

	dump = lasso_node_dump(LASSO_NODE(provider1));
	fail_unless(dump != NULL);
	provider2 = lasso_provider_new_from_dump(dump);
	fail_unless(LASSO_IS_PROVIDER(provider2));
	lasso_release_string(dump);
	dump = lasso_node_dump(LASSO_NODE(provider2));
	fail_unless(dump != NULL);
	g_object_unref(provider1);
	g_object_unref(provider2);
	lasso_release_string(dump);
}
END_TEST

START_TEST(test01_server_new)
{
	LassoServer *server;
	LassoProvider *provider;
	char *dump;
	char *content = NULL;
	size_t len;

	server = lasso_server_new(
			TESTSDATADIR "/idp1-la/metadata.xml",
			TESTSDATADIR "/idp1-la/private-key-raw.pem",
			NULL, /* Secret key to unlock private key */
			TESTSDATADIR "/idp1-la/certificate.pem");
	fail_unless(LASSO_IS_SERVER(server));
	provider = LASSO_PROVIDER(server);
	fail_unless(server->private_key != NULL);
	fail_unless(server->private_key_password == NULL);
	fail_unless(server->certificate != NULL);
	fail_unless(server->signature_method == LASSO_SIGNATURE_METHOD_RSA_SHA1);
	fail_unless(provider->ProviderID != NULL);
	fail_unless(provider->role == 0);
	fail_unless(g_file_get_contents(TESTSDATADIR "/idp1-la/metadata.xml", &content, &len, NULL));
	fail_unless(strcmp(provider->metadata_filename, content) == 0);
	g_free(content);
	fail_unless(provider->public_key == NULL);
	fail_unless(provider->ca_cert_chain == NULL);

	dump = lasso_node_dump(LASSO_NODE(server));
	fail_unless(dump != NULL);
	g_object_unref(server);
	server = lasso_server_new_from_dump(dump);
	fail_unless(LASSO_IS_SERVER(server));
	provider = LASSO_PROVIDER(server);
	fail_unless(server->private_key != NULL);
	fail_unless(server->private_key_password == NULL);
	fail_unless(server->certificate != NULL);
	fail_unless(server->signature_method == LASSO_SIGNATURE_METHOD_RSA_SHA1);
	fail_unless(server->providers != NULL);
	fail_unless(provider->ProviderID != NULL);
	fail_unless(provider->role == 0, "provider->role != 0 => provider :=  %d", provider->role);
	fail_unless(g_file_get_contents(TESTSDATADIR "/idp1-la/metadata.xml", &content, &len, NULL));
	fail_unless(strcmp(provider->metadata_filename, content) == 0);
	fail_unless(provider->public_key == NULL);
	fail_unless(provider->ca_cert_chain == NULL);
	g_object_unref(server);
	lasso_release_string(dump);
	lasso_release_string(content);
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
	fail_unless(LASSO_IS_SERVER(server));
	fail_unless(server->private_key != NULL);
	fail_unless(! server->private_key_password);
	fail_unless(server->certificate != NULL);
	fail_unless(server->signature_method == LASSO_SIGNATURE_METHOD_RSA_SHA1);
	fail_unless(server->providers != NULL);
	lasso_server_add_provider(
			server,
			LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp1-la/metadata.xml",
			TESTSDATADIR "/sp1-la/public-key.pem",
			TESTSDATADIR "/ca1-la/certificate.pem");
	fail_unless(g_hash_table_size(server->providers) == 1);


	dump = lasso_node_dump(LASSO_NODE(server));
	g_object_unref(server);
	lasso_release_string(dump);
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
	g_free(dump);
	dump = lasso_node_dump(LASSO_NODE(server2));
	g_object_unref(server1);
	g_object_unref(server2);
	g_free(dump);
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
	char *dump;

	node = lasso_node_new_from_dump(msg);
	fail_unless(node != NULL, "new_from_dump failed");
	dump = lasso_node_dump(node);
	fail_unless(dump != NULL, "node_dump failed");
	g_object_unref(node);
	g_free(dump);
}
END_TEST

START_TEST(test05_xsi_type)
{
	/* check lib:AuthnContext element is not converted to
	 * saml:AuthnContext xsi:type="lib:AuthnContextType" and
	 * lib:AuthenticationStatement is converted to
	 * saml:AuthenticationStatement * xsi:type="lib:AuthenticationStatementType"
	 */

	LassoSamlAssertion *assertion;
	LassoLibAuthenticationStatement *stmt;
	LassoSamlNameIdentifier *name_identifier;
	char *dump;

	name_identifier = lasso_saml_name_identifier_new();
	assertion = LASSO_SAML_ASSERTION(lasso_lib_assertion_new_full("", "", "", "", ""));

	assertion->AuthenticationStatement = LASSO_SAML_AUTHENTICATION_STATEMENT(
			lasso_lib_authentication_statement_new_full(
			"toto", "toto", "toto",
			NULL,
			name_identifier));
	g_object_unref(name_identifier);
	stmt = LASSO_LIB_AUTHENTICATION_STATEMENT(assertion->AuthenticationStatement);
	stmt->AuthnContext = LASSO_LIB_AUTHN_CONTEXT(lasso_lib_authn_context_new());
	stmt->AuthnContext->AuthnContextClassRef = g_strdup("urn:toto");

	dump = lasso_node_dump(LASSO_NODE(assertion));
	fail_unless(strstr(dump, "xsi:type=\"lib:AuthnContextType\"") == NULL,
			"AuthnContext got a xsi:type");
	g_free(dump);
	dump = lasso_node_dump(LASSO_NODE(assertion));
	fail_unless(strstr(dump, "xsi:type=\"lib:AuthenticationStatementType\"") != NULL,
			"AuthenticationStatement didn't get a xsi:type");
	g_free(dump);
	g_object_unref(assertion);
}
END_TEST

START_TEST(test06_lib_statuscode)
{
	/* check status code value in samlp:Response; it is a QName, if it
	 * starts with lib:, that namespace must be defined.  (was bug#416)
	 */
	LassoSamlpResponse *response = LASSO_SAMLP_RESPONSE(lasso_samlp_response_new());
	char *dump = NULL;

	lasso_assign_string(response->Status->StatusCode->Value, LASSO_SAML_STATUS_CODE_SUCCESS);
	dump = lasso_node_dump(LASSO_NODE(response));
	fail_unless(strstr(dump, "xmlns:lib=") == NULL,
			"liberty namespace should not be defined");
	lasso_release_string(dump);

	lasso_assign_string(response->Status->StatusCode->Value, LASSO_SAML_STATUS_CODE_RESPONDER);
	response->Status->StatusCode->StatusCode = lasso_samlp_status_code_new();
	response->Status->StatusCode->StatusCode->Value = g_strdup(
			LASSO_LIB_STATUS_CODE_UNKNOWN_PRINCIPAL);
	dump = lasso_node_dump(LASSO_NODE(response));
	fail_unless(strstr(dump, "xmlns:lib=") != NULL,
			"liberty namespace should be defined");
	lasso_release_string(dump);
	g_object_unref(response);
}
END_TEST

extern xmlSecKey* lasso_xmlsec_load_private_key_from_buffer(const char *buffer, size_t length, const char *password);

extern int lasso_saml2_query_verify_signature(const char *query, const xmlSecKey *sender_public_key);


START_TEST(test07_saml2_query_verify_signature)
{
	/* normal query as produces by Lasso */
	const char query1[] = "SAMLRequest=fZHNasMwEIRfxeieWrYTtQjb4DgJBNqSNqWHXopw1kQgS6523Z%2B3r%2BxQSKDkOppvd2aVo%2BpML6uBjvYZPgZAir47Y1FODwUbvJVOoUZpVQcoqZH76uFepjdc9t6Ra5xhZ8h1QiGCJ%2B0si7argr0vxTLJ1guRilpU8%2FWtyKpNnaXrukoF32SCRa%2FgMfgLFvAAIQ6wtUjKUpB4wmc8nSX8hXOZ3Ml0%2FsaijfMNTIUK1iqDMGK7sFl%2Fwp9S5mNWOY3z5ZGol3GM%2FSLugNRBkcrjc0N%2ButJj6LNd7ZzRzc%2B4plN0ve6o6MOsnayyH6sggSUW7XfjsKdBGd1q8AX7JwOLKmPcV%2B1BUUhOfgAWl6dkl19W%2FgI%3D&RelayState=fake%5B%5D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=wDxMSEPKhK%2FuU06cmL50oVx%2B7eP5%2FQirShQE%2BLv9pT3CrVwb6WBV1Tp9XS2VVJ2odLHogdA%2FE1XDW7BIRKYgkN8bXVlC2GybSYBhyn8bwAuyHs%2BnMW48LF%2FE5vFiZxbw8tMWUAktdvDuaXoZLhubX7UgV%2B%2BdRyjhckolpXTC9xuJdoHJUDF0vzzNm8xZs6LR7tjWUoz5CcjMJA3LVfWmpE5UjCyRmGbi9knGWHdY75CFtArD%2BNSkGeNx9xySrUlik6e57Zlodv4V9WBdeopAWskO58BA27GqTmnSLooeo%2FrtLxc1NZeuau11YxNzwl%2FvN8%2FQ5IsR3Xic8X1TaCCtwg%3D%3D";
	/* SAMLRequest field was moved in the middle, Signature to the beginning and all & were
	 * changed to ; */
	const char query2[] = "Signature=wDxMSEPKhK%2FuU06cmL50oVx%2B7eP5%2FQirShQE%2BLv9pT3CrVwb6WBV1Tp9XS2VVJ2odLHogdA%2FE1XDW7BIRKYgkN8bXVlC2GybSYBhyn8bwAuyHs%2BnMW48LF%2FE5vFiZxbw8tMWUAktdvDuaXoZLhubX7UgV%2B%2BdRyjhckolpXTC9xuJdoHJUDF0vzzNm8xZs6LR7tjWUoz5CcjMJA3LVfWmpE5UjCyRmGbi9knGWHdY75CFtArD%2BNSkGeNx9xySrUlik6e57Zlodv4V9WBdeopAWskO58BA27GqTmnSLooeo%2FrtLxc1NZeuau11YxNzwl%2FvN8%2FQ5IsR3Xic8X1TaCCtwg%3D%3D;RelayState=fake%5B%5D;SAMLRequest=fZHNasMwEIRfxeieWrYTtQjb4DgJBNqSNqWHXopw1kQgS6523Z%2B3r%2BxQSKDkOppvd2aVo%2BpML6uBjvYZPgZAir47Y1FODwUbvJVOoUZpVQcoqZH76uFepjdc9t6Ra5xhZ8h1QiGCJ%2B0si7argr0vxTLJ1guRilpU8%2FWtyKpNnaXrukoF32SCRa%2FgMfgLFvAAIQ6wtUjKUpB4wmc8nSX8hXOZ3Ml0%2FsaijfMNTIUK1iqDMGK7sFl%2Fwp9S5mNWOY3z5ZGol3GM%2FSLugNRBkcrjc0N%2ButJj6LNd7ZzRzc%2B4plN0ve6o6MOsnayyH6sggSUW7XfjsKdBGd1q8AX7JwOLKmPcV%2B1BUUhOfgAWl6dkl19W%2FgI%3D;SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1";
	const char query3[] = "RelayState=fake%5B%5D&SAMLRequest=fZHNasMwEIRfxeieWrYTtQjb4DgJBNqSNqWHXopw1kQgS6523Z%2B3r%2BxQSKDkOppvd2aVo%2BpML6uBjvYZPgZAir47Y1FODwUbvJVOoUZpVQcoqZH76uFepjdc9t6Ra5xhZ8h1QiGCJ%2B0si7argr0vxTLJ1guRilpU8%2FWtyKpNnaXrukoF32SCRa%2FgMfgLFvAAIQ6wtUjKUpB4wmc8nSX8hXOZ3Ml0%2FsaijfMNTIUK1iqDMGK7sFl%2Fwp9S5mNWOY3z5ZGol3GM%2FSLugNRBkcrjc0N%2ButJj6LNd7ZzRzc%2B4plN0ve6o6MOsnayyH6sggSUW7XfjsKdBGd1q8AX7JwOLKmPcV%2B1BUUhOfgAWl6dkl19W%2FgI%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=wDxMSEPKhK%2FuU06cmL50oVx%2B7eP5%2FQirShQE%2BLv9pT3CrVwb6WBV1Tp9XS2VVJ2odLHogdA%2FE1XDW7BIRKYgkN8bXVlC2GybSYBhyn8bwAuyHs%2BnMW48LF%2FE5vFiZxbw8tMWUAktdvDuaXoZLhubX7UgV%2B%2BdRyjhckolpXTC9xuJdoHJUDF0vzzNm8xZs6LR7tjWUoz5CcjMJA3LVfWmpE5UjCyRmGbi9knGWHdY75CFtArD%2BNSkGeNx9xySrUlik6e57Zlodv4V9WBdeopAWskO58BA27GqTmnSLooeo%2FrtLxc1NZeuau11YxNzwl%2FvN8%2FQ5IsR3Xic8X1TacCtwg%3D%3D";
	/* sp5-saml2 key */
	const char pkey[] = "-----BEGIN CERTIFICATE-----\n\
MIIDnjCCAoagAwIBAgIBATANBgkqhkiG9w0BAQUFADBUMQswCQYDVQQGEwJGUjEP\n\
MA0GA1UECBMGRnJhbmNlMQ4wDAYDVQQHEwVQYXJpczETMBEGA1UEChMKRW50cm91\n\
dmVydDEPMA0GA1UEAxMGRGFtaWVuMB4XDTA2MTAyNzA5MDc1NFoXDTExMTAyNjA5\n\
MDc1NFowVDELMAkGA1UEBhMCRlIxDzANBgNVBAgTBkZyYW5jZTEOMAwGA1UEBxMF\n\
UGFyaXMxEzARBgNVBAoTCkVudHJvdXZlcnQxDzANBgNVBAMTBkRhbWllbjCCASIw\n\
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM06Hx6VgHYR9wUf/tZVVTRkVWNq\n\
h9x+PvHA2qH4OYMuqGs4Af6lU2YsZvnrmRdcFWv0+UkdAgXhReCWAZgtB1pd/W9m\n\
6qDRldCCyysow6xPPKRz/pOTwRXm/fM0QGPeXzwzj34BXOIOuFu+n764vKn18d+u\n\
uVAEzk1576pxTp4pQPzJfdNLrLeQ8vyCshoFU+MYJtp1UA+h2JoO0Y8oGvywbUxH\n\
ioHN5PvnzObfAM4XaDQohmfxM9Uc7Wp4xKAc1nUq5hwBrHpjFMRSz6UCfMoJSGIi\n\
+3xJMkNCjL0XEw5NKVc5jRKkzSkN5j8KTM/k1jPPsDHPRYzbWWhnNtd6JlkCAwEA\n\
AaN7MHkwCQYDVR0TBAIwADAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0\n\
ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFP2WWMDShux3iF74+SoO1xf6qhqaMB8G\n\
A1UdIwQYMBaAFGjl6TRXbQDHzSlZu+e8VeBaZMB5MA0GCSqGSIb3DQEBBQUAA4IB\n\
AQAZ/imK7UMognXbs5RfSB8cMW6iNAI+JZqe9XWjvtmLfIIPbHM96o953SiFvrvQ\n\
BZjGmmPMK3UH29cjzDx1R/RQaYTyMrHyTePLh3BMd5mpJ/9eeJCSxPzE2ECqWRUa\n\
pkjukecFXqmRItwgTxSIUE9QkpzvuQRb268PwmgroE0mwtiREADnvTFkLkdiEMew\n\
fiYxZfJJLPBqwlkw/7f1SyzXoPXnz5QbNwDmrHelga6rKSprYKb3pueqaIe8j/AP\n\
NC1/bzp8cGOcJ88BD5+Ny6qgPVCrMLE5twQumJ12V3SvjGNtzFBvg2c/9S5OmVqR\n\
LlTxKnCrWAXftSm1rNtewTsF\n\
-----END CERTIFICATE-----";

	xmlSecKeyPtr key = lasso_xmlsec_load_private_key_from_buffer(pkey, sizeof(pkey)-1, NULL);

	fail_unless(key != NULL, "Cannot load public key");
	fail_unless(lasso_saml2_query_verify_signature(query1, key) == 0, "Signature was not validated");
	/* test reordering and semi-colon separator support */
	fail_unless(lasso_saml2_query_verify_signature(query2, key) == 0, "Disordered signature was not validated");
	fail_unless(lasso_saml2_query_verify_signature(query3, key) != 0, "Altered signature was validated");
	xmlSecKeyDestroy(key);
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
	tcase_add_test(tc_node, test05_xsi_type);
	tcase_add_test(tc_node, test06_lib_statuscode);
	tcase_add_test(tc_node, test07_saml2_query_verify_signature);

	return s;
}

