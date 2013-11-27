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
#include "tests.h"
#include "../lasso/xml/lib_assertion.h"
#include "../lasso/xml/lib_authentication_statement.h"
#include "../lasso/xml/saml_name_identifier.h"
#include "../lasso/xml/samlp_response.h"
#include "../lasso/xml/saml-2.0/saml2_attribute.h"
#include "../lasso/xml/saml-2.0/samlp2_authn_request.h"
#include "../lasso/id-ff/provider.h"
#include "../lasso/utils.h"
#include <libxml/tree.h>
#include <libxml/parser.h>


Suite* non_regression_suite();

START_TEST(test01_googleapps_27092010)
{

/*
 * Here the decoded request:
 *
 * char *gapp_request = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n\
ID=\"lfnoehcfgagfbefiaijaefdpndeppgmfllenelik\" Version=\"2.0\"\n\
IssueInstant=\"2010-09-27T12:55:29Z\"\n\
ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n\
ProviderName=\"google.com\" IsPassive=\"false\"\n\
AssertionConsumerServiceURL=\"https://www.google.com/a/linid.org/acs\"><saml:Issuer\n\
xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">google.com</saml:Issuer><samlp:NameIDPolicy\n\
AllowCreate=\"true\"\n\
Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\"\n\
/></samlp:AuthnRequest>"; */
	char *b64_encoded_request = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIgpJRD0ibGZub2VoY2ZnYWdmYmVmaWFpamFlZmRwbmRlcHBnbWZsbGVuZWxpayIgVmVyc2lvbj0iMi4wIgpJc3N1ZUluc3RhbnQ9IjIwMTAtMDktMjdUMTI6NTU6MjlaIgpQcm90b2NvbEJpbmRpbmc9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpiaW5kaW5nczpIVFRQLVBPU1QiClByb3ZpZGVyTmFtZT0iZ29vZ2xlLmNvbSIgSXNQYXNzaXZlPSJmYWxzZSIKQXNzZXJ0aW9uQ29uc3VtZXJTZXJ2aWNlVVJMPSJodHRwczovL3d3dy5nb29nbGUuY29tL2EvbGluaWQub3JnL2FjcyI+PHNhbWw6SXNzdWVyCnhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmdvb2dsZS5jb208L3NhbWw6SXNzdWVyPjxzYW1scDpOYW1lSURQb2xpY3kKQWxsb3dDcmVhdGU9InRydWUiCkZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6dW5zcGVjaWZpZWQiCi8+PC9zYW1scDpBdXRoblJlcXVlc3Q+Cg==";
	char *metadata = "<md:EntityDescriptor entityID=\"google.com\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">\n\
<SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n\
<AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://www.google.com/a/linid.org/acs\" index=\"0\" />\n\
<NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>\n\
</SPSSODescriptor>\n\
</md:EntityDescriptor>\n";
	LassoServer *server = NULL;
	LassoLogin *login = NULL;
	check_not_null(server = lasso_server_new(TESTSDATADIR "/idp5-saml2/metadata.xml",
				TESTSDATADIR "/idp5-saml2/private-key.pem", NULL, NULL));
	check_good_rc(lasso_server_add_provider_from_buffer(server, LASSO_PROVIDER_ROLE_SP,
				metadata, NULL, NULL));
	check_not_null(login = lasso_login_new(server));
	lasso_profile_set_signature_verify_hint(&login->parent,
				LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE);
	check_good_rc(lasso_login_process_authn_request_msg(login, b64_encoded_request));
	check_good_rc(lasso_login_validate_request_msg(login, TRUE, TRUE));
	check_good_rc(lasso_login_build_authn_response_msg(login));
	check_not_null(LASSO_PROFILE(login)->msg_url);
	check_not_null(LASSO_PROFILE(login)->msg_body);
	lasso_release_gobject(login);
	lasso_release_gobject(server);

}
END_TEST

START_TEST(indexed_endpoints_20101008)
{
	LassoProvider *provider = NULL;
	char *str;
	char *meta01 = "<md:EntityDescriptor entityID=\"google.com\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">\n\
<SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n\
<AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"wrong\" index=\"1\" />\n\
<AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"ok\" index=\"0\" />\n\
</SPSSODescriptor>\n\
</md:EntityDescriptor>\n";
	char *meta02 = "<md:EntityDescriptor entityID=\"google.com\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">\n\
<SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n\
<AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"wrong\" index=\"0\" isDefault=\"false\" />\n\
<AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"ok\" index=\"1\" />\n\
</SPSSODescriptor>\n\
</md:EntityDescriptor>\n";
	char *meta03 = "<md:EntityDescriptor entityID=\"google.com\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">\n\
<SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n\
<AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"wrong\" index=\"0\" isDefault=\"false\" />\n\
<AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"ok\" index=\"1\" />\n\
</SPSSODescriptor>\n\
</md:EntityDescriptor>\n";
	char *meta04 = "<md:EntityDescriptor entityID=\"google.com\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">\n\
<SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n\
<AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"wrong\" index=\"0\" />\n\
<AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"ok\" index=\"1\" isDefault=\"true\" />\n\
</SPSSODescriptor>\n\
</md:EntityDescriptor>\n";

	provider = lasso_provider_new_from_buffer(LASSO_PROVIDER_ROLE_SP, meta01, NULL, NULL);
	check_not_null(provider);
	str = lasso_provider_get_assertion_consumer_service_url(provider, NULL);
	check_str_equals(str, "ok");
	g_free(str);
	str = lasso_provider_get_assertion_consumer_service_url(provider, "0");
	check_str_equals(str, "ok");
	g_free(str);
	str = lasso_provider_get_assertion_consumer_service_url(provider, "1");
	check_str_equals(str, "wrong");
	g_free(str);
	lasso_release_gobject(provider);
	provider = lasso_provider_new_from_buffer(LASSO_PROVIDER_ROLE_SP, meta02, NULL, NULL);
	check_not_null(provider);
	str = lasso_provider_get_assertion_consumer_service_url(provider, NULL);
	check_str_equals(str, "ok");
	g_free(str);
	str = lasso_provider_get_assertion_consumer_service_url(provider, "0");
	check_str_equals(str, "wrong");
	g_free(str);
	str = lasso_provider_get_assertion_consumer_service_url(provider, "1");
	check_str_equals(str, "ok");
	g_free(str);
	lasso_release_gobject(provider);
	provider = lasso_provider_new_from_buffer(LASSO_PROVIDER_ROLE_SP, meta03, NULL, NULL);
	check_not_null(provider);
	str = lasso_provider_get_assertion_consumer_service_url(provider, NULL);
	check_str_equals(str, "ok");
	g_free(str);
	str = lasso_provider_get_assertion_consumer_service_url(provider, "0");
	check_str_equals(str, "wrong");
	g_free(str);
	str = lasso_provider_get_assertion_consumer_service_url(provider, "1");
	check_str_equals(str, "ok");
	g_free(str);
	lasso_release_gobject(provider);
	provider = lasso_provider_new_from_buffer(LASSO_PROVIDER_ROLE_SP, meta04, NULL, NULL);
	check_not_null(provider);
	str = lasso_provider_get_assertion_consumer_service_url(provider, NULL);
	check_str_equals(str, "ok");
	g_free(str);
	str = lasso_provider_get_assertion_consumer_service_url(provider, "0");
	check_str_equals(str, "wrong");
	g_free(str);
	str = lasso_provider_get_assertion_consumer_service_url(provider, "1");
	check_str_equals(str, "ok");
	g_free(str);
	lasso_release_gobject(provider);
}
END_TEST

START_TEST(remove_warning_when_parssing_unknown_SNIPPET_LIST_NODES_20111007)
{
	LassoNode *node;
	xmlDoc *xmldoc;
	const char content[] = "<saml:Attribute Name=\"urn:oid:1.3.6.1.4.1.5923.1.1.1.10\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\" FriendlyName=\"eduPersonTargetedID\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:AttributeValue><NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\" NameQualifier=\"https://services-federation.renater.fr/test/idp\" SPNameQualifier=\"https://univnautes.entrouvert.lan/authsaml2/metadata\">C8NQsm1Y3Gas9m0AMDhxU7UxCSI=</NameID></saml:AttributeValue></saml:Attribute>";

	xmldoc = xmlReadMemory(content, sizeof(content)-1, NULL, NULL, 0);
	check_not_null(xmldoc);
	node = lasso_node_new_from_xmlNode(xmlDocGetRootElement(xmldoc));
	check_not_null(node);
	check_true(LASSO_IS_SAML2_ATTRIBUTE(node));
	check_true(LASSO_IS_NODE(node));
	xmlFreeDoc(xmldoc);
	lasso_release_gobject(node);
}
END_TEST

START_TEST(wrong_endpoint_index_in_artifacts)
{
	LassoServer *server = NULL;
	LassoLogin *login = NULL;
	guchar *decoded = NULL;
	size_t out_len;

	check_not_null(server = lasso_server_new(TESTSDATADIR "/idp13-artifact-resolution-service-indexed/metadata.xml",
				TESTSDATADIR "/idp13-artifact-resolution-service-indexed/private-key.pem", NULL, NULL));
	check_good_rc(lasso_server_add_provider(server, LASSO_PROVIDER_ROLE_SP,
				TESTSDATADIR "/sp7-saml2/metadata.xml", NULL, NULL));
	check_not_null(login = lasso_login_new(server));
	check_good_rc(lasso_login_init_idp_initiated_authn_request(login,
				"http://sp7/metadata"));
	lasso_assign_string(LASSO_SAMLP2_AUTHN_REQUEST(login->parent.request)->ProtocolBinding,
			LASSO_SAML2_METADATA_BINDING_ARTIFACT);
	check_good_rc(lasso_login_process_authn_request_msg(login, NULL));
	check_good_rc(lasso_login_validate_request_msg(login, TRUE, TRUE));
	check_good_rc(lasso_login_build_artifact_msg(login, LASSO_HTTP_METHOD_ARTIFACT_GET));
	check_not_null(LASSO_PROFILE(login)->msg_url);
	check_null(LASSO_PROFILE(login)->msg_body);
	printf("%s\n", LASSO_PROFILE(login)->msg_url);
	decoded = g_base64_decode(strstr(LASSO_PROFILE(login)->msg_url, "SAMLart=")+8, &out_len);
	check_equals(decoded[2],0);
	check_equals(decoded[3],7);
	lasso_release_gobject(login);
	lasso_release_gobject(server);
	lasso_release(decoded);
}
END_TEST

struct {
	char *name;
	void *function;
} tests[] = {
	{ "Googleapps error from coudot@ on 27-09-2010", test01_googleapps_27092010},
	{ "Wrong assertionConsumer ordering on 08-10-2010", indexed_endpoints_20101008},
	{ "Warning when parsing AttributeValue node containing unknown namespace nodes", remove_warning_when_parssing_unknown_SNIPPET_LIST_NODES_20111007 },
	{ "Wrong endpoint index in artifacts", wrong_endpoint_index_in_artifacts },
};

Suite*
non_regression_suite()
{
	Suite *s = suite_create("Non regression tests");
	unsigned int i = 0;

	for (i = 0 ; i < G_N_ELEMENTS(tests); i++) {
		TCase *c = tcase_create(tests[i].name);
		void *f = tests[i].function;
		tcase_add_test(c, f);
		suite_add_tcase(s, c);
	}

	return s;
}
