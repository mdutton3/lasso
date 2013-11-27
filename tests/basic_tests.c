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
#include "../lasso/xml/strings.h"
#include "../lasso/xml/xml_idff.h"
#include "../lasso/xml/saml-2.0/xml_saml2.h"
#include "../lasso/xml/xml_idwsf.h"
#include "../lasso/xml/id-wsf-2.0/xml_idwsf2.h"
#include "../lasso/xml/ws/xml_ws.h"
#include "../lasso/xml/soap-1.1/xml_soap11.h"
#include "../lasso/utils.h"
#include "../lasso/xml/private.h"
#include <libxml/tree.h>
#include "tests.h"

START_TEST(test01_server_load_dump_empty_string)
{
	LassoServer *serverContext;
	serverContext = lasso_server_new_from_dump("");
	fail_unless(serverContext == NULL,
			"serverContext was created from an empty string dump");
}
END_TEST

START_TEST(test02_server_load_dump_random_string)
{
	LassoServer *serverContext;
	begin_check_do_log(G_LOG_LEVEL_CRITICAL, "libxml2: Start tag expected, '<' not found\\n", FALSE);
	serverContext = lasso_server_new_from_dump("foo");
	end_check_do_log();
	fail_unless(serverContext == NULL,
			"serverContext was created from a fake dump");
}
END_TEST

START_TEST(test03_server_load_dump_random_xml)
{
	LassoServer *serverContext;
	begin_check_do_log(G_LOG_LEVEL_CRITICAL, " Unable to build a LassoNode from a xmlNode", TRUE);
	serverContext = lasso_server_new_from_dump("<?xml version=\"1.0\"?><foo/>");
	end_check_do_log();
	fail_unless(serverContext == NULL,
			"serverContext was created from fake (but valid XML) dump");
}
END_TEST


START_TEST(test04_identity_load_dump_null)
{
	LassoIdentity *identity;

	identity = lasso_identity_new_from_dump(NULL);
	fail_unless(identity == NULL, "identity was created from NULL dump");
}
END_TEST

START_TEST(test05_identity_load_dump_empty)
{
	LassoIdentity *identity;

	identity = lasso_identity_new_from_dump("");
	fail_unless(identity == NULL, "identity was created from empty dump");
}
END_TEST

#include "../lasso/registry.h"

START_TEST(test06_registry_direct_mapping)
{
	const char *name;
	gint r;

	r = lasso_registry_default_add_direct_mapping(LASSO_LIB_HREF, "test", LASSO_LASSO_HREF,
			"LassoTestClass");
	fail_unless(r == 0, "lasso_registry_default_add_direct_mapping should return 0 for new mappings");
	name = lasso_registry_default_get_mapping(LASSO_LIB_HREF, "test", LASSO_LASSO_HREF);
	fail_unless(name != NULL, "lasso_registry_default_get_mapping should return the recent mapping");
	fail_unless(strcmp(name, "LassoTestClass") == 0, "lasso_registry_default_get_mapping should return LassoTestClass");
	r = lasso_registry_default_add_direct_mapping(LASSO_LIB_HREF, "test", LASSO_LASSO_HREF,
			"LassoTestClass");
	fail_unless(r == LASSO_REGISTRY_ERROR_KEY_EXISTS, "lasso_registry_default_add_direct_mapping should return LASSO_REGISTRY_KEY_EXISTS when done two times");
}
END_TEST

const char *trad(const char *from_namespace, const char *from_name, const char* to_namespace)
{
	if (strcmp(from_namespace, "coin") == 0 &&
			strcmp(to_namespace, LASSO_LASSO_HREF) == 0)
	{
		char *temp = g_strconcat("Lasso", from_name, NULL);
		const char *ret = g_intern_string(temp);
		g_free(temp);
		return ret;
	}
	return NULL;
}


START_TEST(test07_registry_functional_mapping)
{
	const char *name;
	gint r;

	r = lasso_registry_default_add_functional_mapping("coin", LASSO_LASSO_HREF, trad);
	fail_unless(r == 0, "lasso_registry_default_add_functional mapping should return 0 for new mapping");
	name = lasso_registry_default_get_mapping("coin", "Assertion", LASSO_LASSO_HREF);
	fail_unless(name != NULL, "lasso_registry_default_get_mapping should return the recent mapping");
	fail_unless(strcmp(name, "LassoAssertion") == 0, "lasso_registry_default_get_mapping should return LassoAssertion");
	r = lasso_registry_default_add_functional_mapping("coin", LASSO_LASSO_HREF, trad);
	fail_unless(r == LASSO_REGISTRY_ERROR_KEY_EXISTS, "lasso_registry_default_add_functional_mapping should return LASSO_REGISTRY_KEY_EXISTS when done two times");
}
END_TEST

static struct XmlSnippet schema_snippets[] = {
	{NULL, 0, 0, NULL, NULL, NULL}
};

static void
class_init(LassoNodeClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Assertion");
	lasso_node_class_set_ns(nclass,LASSO_SAML2_ASSERTION_HREF, LASSO_SAML2_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);

}

START_TEST(test08_test_new_from_xmlNode)
{
	gint r;
	LassoNode *node = NULL;

	static const GTypeInfo this_info = {
		sizeof (LassoNodeClass),
		NULL,
		NULL,
		(GClassInitFunc) class_init,
		NULL,
		NULL,
		sizeof(LassoNode),
		0,
		NULL,
		NULL
	};

	g_type_register_static(LASSO_TYPE_NODE,
			"LassoTest", &this_info, 0);
	r = lasso_registry_default_add_direct_mapping("http://example.com", "Test1", LASSO_LASSO_HREF, "LassoTest");
	fail_unless(r == 0, "no mapping for http://example.com:Test1 should exist");
	begin_check_do_log(G_LOG_LEVEL_WARNING, "	Class LassoTest has no node_data so no initialization is possible", TRUE);
	node = lasso_node_new_from_dump("<Test1 xmlns=\"http://example.com\"></Test1>");
	end_check_do_log();
	fail_unless(node != NULL, "parsing <Test1/> should return an object");
	fail_unless(strcmp(G_OBJECT_TYPE_NAME(node), "LassoTest") == 0, "node classname should be LassoTest");
	g_object_unref(node);
}
END_TEST

START_TEST(test09_test_deserialization)
{
	char *content = NULL;
	size_t len = 0;
	LassoNode *node;

	g_file_get_contents(TESTSDATADIR "/response-1", &content, &len, NULL);

	fail_unless(content != NULL, "content should be read");
	node = lasso_node_new_from_dump(content);
	fail_unless(node != NULL, "node should be parsed");
	g_object_unref(node);
	g_free(content);
}
END_TEST

/* try to test all new functions and their associated deserialization codes */
START_TEST(test10_test_alldumps)
{
	LassoNode *node, *node2;
	char *node_dump;

	node = LASSO_NODE(lasso_identity_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_identity_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_session_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_session_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
#ifdef LASSO_WSF_ENABLED
	node = LASSO_NODE(lasso_disco_authenticate_requester_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_disco_authenticate_requester_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_disco_authenticate_session_context_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_disco_authenticate_session_context_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_disco_authorize_requester_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_disco_authorize_requester_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_disco_credentials_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_disco_credentials_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_disco_description_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_disco_description_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_disco_encrypt_resource_id_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_disco_encrypt_resource_id_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_disco_encrypted_resource_id_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_disco_encrypted_resource_id_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_disco_generate_bearer_token_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_disco_generate_bearer_token_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_disco_modify_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_disco_modify_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_disco_options_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_disco_options_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_disco_query_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_disco_query_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_disco_send_single_logout_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_disco_send_single_logout_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_ds_key_info_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_ds_key_info_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_ds_key_value_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_ds_key_value_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_ds_rsa_key_value_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_ds_rsa_key_value_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_dst_data_new());
	node_dump = lasso_node_dump(node);
	fail_unless(node_dump && strcmp(node_dump, "<Data/>") == 0, "LassoDstData dump failed");
	lasso_release_string(node_dump);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_dst_new_data_new());
	node_dump = lasso_node_dump(node);
	fail_unless(node_dump && strcmp(node_dump, "<NewData/>") == 0, "LassoDstNewData dump failed");
	lasso_release_string(node_dump);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_abstract_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_abstract_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_endpoint_context_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_endpoint_context_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_keys_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_keys_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_options_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_options_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_provider_id_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_provider_id_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_query_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_query_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_query_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_query_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_requested_service_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_requested_service_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_security_context_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_security_context_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_service_context_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_service_context_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_service_type_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_service_type_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_svc_md_association_add_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_svc_md_association_add_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_svc_md_association_add_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_svc_md_association_add_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_svc_md_association_delete_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_svc_md_association_delete_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_svc_md_association_delete_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_svc_md_association_delete_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_svc_md_association_query_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_svc_md_association_query_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_svc_md_association_query_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_svc_md_association_query_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_svc_md_delete_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_svc_md_delete_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_svc_md_delete_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_svc_md_delete_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_svc_md_query_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_svc_md_query_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_svc_md_query_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_svc_md_query_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_svc_md_register_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_svc_md_register_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_svc_md_register_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_svc_md_register_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_svc_md_replace_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_svc_md_replace_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_svc_md_replace_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_svc_md_replace_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_disco_svc_metadata_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_disco_svc_metadata_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
#if 0
	node = LASSO_NODE(lasso_idwsf2_dst_data_response_base_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dst_data_response_base_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dst_delete_item_base_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dst_delete_item_base_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dst_delete_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dst_delete_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dst_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dst_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dst_result_query_base_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dst_result_query_base_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dst_test_item_base_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dst_test_item_base_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_app_data_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_app_data_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_create_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_create_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_create_item_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_create_item_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_create_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_create_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_data_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_data_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_data_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_data_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_delete_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_delete_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_delete_item_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_delete_item_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_delete_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_delete_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_item_data_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_item_data_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_modify_new());
	LASSO_IDWSF2_DSTREF_MODIFY(node)->prefixServiceType = LASSO_PP10_PREFIX;
	LASSO_IDWSF2_DSTREF_MODIFY(node)->hrefServiceType = LASSO_PP10_HREF;
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_modify_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_modify_item_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_modify_item_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_modify_response_new());
	LASSO_IDWSF2_DSTREF_MODIFY_RESPONSE(node)->prefixServiceType = LASSO_PP10_PREFIX;
	LASSO_IDWSF2_DSTREF_MODIFY_RESPONSE(node)->hrefServiceType = LASSO_PP10_HREF;
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_modify_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_query_new());
	LASSO_IDWSF2_DSTREF_QUERY(node)->prefixServiceType = LASSO_PP10_PREFIX;
	LASSO_IDWSF2_DSTREF_QUERY(node)->hrefServiceType = LASSO_PP10_HREF;
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_query_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_query_item_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_query_item_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_query_response_new());
	LASSO_IDWSF2_DSTREF_QUERY_RESPONSE(node)->prefixServiceType = LASSO_PP10_PREFIX;
	LASSO_IDWSF2_DSTREF_QUERY_RESPONSE(node)->hrefServiceType = LASSO_PP10_HREF;
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_query_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_result_query_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_result_query_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_dstref_test_item_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_dstref_test_item_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
#endif
	node = LASSO_NODE(lasso_idwsf2_ims_identity_mapping_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ims_identity_mapping_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ims_identity_mapping_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ims_identity_mapping_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ims_mapping_input_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ims_mapping_input_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ims_mapping_output_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ims_mapping_output_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_is_help_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_is_help_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_is_inquiry_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_is_inquiry_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
#if 0
	node = LASSO_NODE(lasso_idwsf2_is_inquiry_element_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_is_inquiry_element_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
#endif
	node = LASSO_NODE(lasso_idwsf2_is_interaction_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_is_interaction_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_is_interaction_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_is_interaction_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_is_interaction_statement_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_is_interaction_statement_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_is_item_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_is_item_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_is_parameter_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_is_parameter_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_is_select_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_is_select_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_is_text_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_is_text_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_add_collection_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_add_collection_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_add_collection_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_add_collection_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_add_entity_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_add_entity_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_add_entity_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_add_entity_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_add_known_entity_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_add_known_entity_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_add_known_entity_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_add_known_entity_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_add_to_collection_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_add_to_collection_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_get_object_info_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_get_object_info_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_get_object_info_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_get_object_info_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_item_data_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_item_data_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_list_members_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_list_members_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_list_members_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_list_members_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_notification_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_notification_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_notify_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_notify_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_object_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_object_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_query_objects_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_query_objects_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_query_objects_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_query_objects_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_remove_collection_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_remove_collection_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_remove_entity_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_remove_entity_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_remove_from_collection_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_remove_from_collection_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_request_abstract_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_request_abstract_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_resolve_identifier_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_resolve_identifier_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_resolve_identifier_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_resolve_identifier_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_resolve_input_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_resolve_input_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_response_abstract_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_response_abstract_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_set_object_info_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_set_object_info_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_test_membership_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_test_membership_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_ps_test_membership_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_ps_test_membership_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	/* ID-WSF 2.0 Soap Binding */
	node = LASSO_NODE(lasso_idwsf2_sb2_consent_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_sb2_consent_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_sb2_credentials_context_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_sb2_credentials_context_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_sb2_endpoint_update_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_sb2_endpoint_update_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_sb2_redirect_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_sb2_redirect_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_sb2_sender_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_sb2_sender_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_sb2_target_identity_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_sb2_target_identity_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_sb2_timeout_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_sb2_timeout_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_sb2_usage_directive_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_sb2_usage_directive_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_sb2_user_interaction_header_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_sb2_user_interaction_header_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	/* ID-WSF 2.0 Soap Binding Framework */
	node = LASSO_NODE(lasso_idwsf2_sbf_framework_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_sbf_framework_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	/* ID-WSF 2.0 Security */
	node = LASSO_NODE(lasso_idwsf2_sec_token_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_sec_token_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_sec_token_policy_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_sec_token_policy_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_sec_transited_provider_path_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_sec_transited_provider_path_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	/* ID-WSF 2.0 Subs */
	node = LASSO_NODE(lasso_idwsf2_subs_notification_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subs_notification_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subs_notify_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subs_notify_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subs_ref_item_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subs_ref_item_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subs_subscription_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subs_subscription_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_app_data_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_app_data_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_create_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_create_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_create_item_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_create_item_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_create_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_create_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_data_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_data_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_data_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_data_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_delete_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_delete_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_delete_item_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_delete_item_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_delete_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_delete_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_item_data_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_item_data_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_modify_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_modify_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_modify_item_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_modify_item_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_modify_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_modify_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_notification_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_notification_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_notify_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_notify_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_notify_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_notify_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_query_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_query_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_query_item_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_query_item_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_query_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_query_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_result_query_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_result_query_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_subscription_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_subscription_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_subsref_test_item_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_subsref_test_item_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	/* ID-WSF 2.0 Utils */
	node = LASSO_NODE(lasso_idwsf2_util_empty_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_util_empty_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_util_extension_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_util_extension_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_util_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_util_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_idwsf2_util_status_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_idwsf2_util_status_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	/* Interaction Service */
	node = LASSO_NODE(lasso_is_help_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_is_help_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_is_inquiry_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_is_inquiry_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_is_interaction_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_is_interaction_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_is_select_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_is_select_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_is_text_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_is_text_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_is_user_interaction_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_is_user_interaction_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
#endif
	/* ID-FF 1.2 */
	node = LASSO_NODE(lasso_lib_assertion_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_assertion_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_authn_context_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_authn_context_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_authn_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_authn_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_authn_request_envelope_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_authn_request_envelope_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_federation_termination_notification_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_federation_termination_notification_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_idp_entries_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_idp_entries_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_idp_entry_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_idp_entry_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_idp_list_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_idp_list_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_logout_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_logout_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_logout_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_logout_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_name_identifier_mapping_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_name_identifier_mapping_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_name_identifier_mapping_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_name_identifier_mapping_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_register_name_identifier_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_register_name_identifier_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_register_name_identifier_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_register_name_identifier_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_request_authn_context_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_request_authn_context_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_scoping_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_scoping_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_lib_subject_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_lib_subject_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_misc_text_node_new());
	node_dump = lasso_node_dump(node);
	fail_unless(node_dump && strcmp(node_dump, "<XXX/>") == 0, "LassoMiscTextNode dump failed");
	lasso_release_string(node_dump);
	lasso_release_gobject(node);
#ifdef LASSO_WSF_ENABLED
	node = LASSO_NODE(lasso_sa_credentials_new());
	node_dump = lasso_node_dump(node);
	fail_unless(node_dump && strcmp(node_dump, "<Credentials/>") == 0, "SACredentials dump failed");
	lasso_release_string(node_dump);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_sa_password_transforms_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_sa_password_transforms_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
#endif
	/* SAML 2.0 */
	node = LASSO_NODE(lasso_saml2_action_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_action_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_advice_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_advice_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_assertion_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_assertion_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_attribute_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_attribute_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_attribute_statement_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_attribute_statement_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_attribute_value_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_attribute_value_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_audience_restriction_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_audience_restriction_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_authn_context_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_authn_context_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_authn_statement_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_authn_statement_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_authz_decision_statement_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_authz_decision_statement_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_base_idabstract_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_base_idabstract_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_condition_abstract_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_condition_abstract_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_conditions_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_conditions_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_encrypted_element_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_encrypted_element_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_evidence_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_evidence_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_key_info_confirmation_data_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_key_info_confirmation_data_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_name_id_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_name_id_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_one_time_use_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_one_time_use_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_proxy_restriction_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_proxy_restriction_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_statement_abstract_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_statement_abstract_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_subject_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_subject_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_subject_confirmation_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_subject_confirmation_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_subject_confirmation_data_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_subject_confirmation_data_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml2_subject_locality_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_subject_locality_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_artifact_resolve_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_artifact_resolve_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_artifact_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_artifact_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_assertion_id_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_assertion_id_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_attribute_query_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_attribute_query_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_authn_query_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_authn_query_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_authn_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_authn_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_authz_decision_query_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_authz_decision_query_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_extensions_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_extensions_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_idp_entry_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_idp_entry_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_idp_list_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_idp_list_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
/*	node = LASSO_NODE(lasso_samlp2_logout_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_logout_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node); */
	node = LASSO_NODE(lasso_samlp2_logout_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_logout_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
/*	node = LASSO_NODE(lasso_samlp2_manage_name_id_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_manage_name_id_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node); */
	node = LASSO_NODE(lasso_samlp2_manage_name_id_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_manage_name_id_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_name_id_mapping_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_name_id_mapping_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_name_id_mapping_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_name_id_mapping_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_name_id_policy_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_name_id_policy_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_request_abstract_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_request_abstract_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_requested_authn_context_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_requested_authn_context_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_scoping_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_scoping_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_status_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_status_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_status_code_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_status_code_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_status_detail_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_status_detail_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_status_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_status_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_subject_query_abstract_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_subject_query_abstract_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp2_terminate_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp2_terminate_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	/* SAML 1.0 */
	node = LASSO_NODE(lasso_saml_advice_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_advice_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_assertion_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_assertion_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_attribute_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_attribute_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_attribute_designator_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_attribute_designator_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_attribute_statement_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_attribute_statement_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_attribute_value_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_attribute_value_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_audience_restriction_condition_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_audience_restriction_condition_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_authentication_statement_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_authentication_statement_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_authority_binding_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_authority_binding_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_conditions_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_conditions_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_name_identifier_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_name_identifier_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_subject_confirmation_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_subject_confirmation_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_saml_subject_statement_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml_subject_statement_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp_request_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp_request_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp_response_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp_response_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp_status_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp_status_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_samlp_status_code_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_samlp_status_code_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
#ifdef LASSO_WSF_ENABLED
	/* SOAP Binding - ID-WSF 1.0 */
	node = LASSO_NODE(lasso_soap_binding_ext_credentials_context_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_soap_binding_ext_credentials_context_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_soap_binding_ext_service_instance_update_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_soap_binding_ext_service_instance_update_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_soap_binding_processing_context_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_soap_binding_processing_context_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
#endif
	/* SOAP */
	node = LASSO_NODE(lasso_soap_body_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_soap_body_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_soap_detail_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_soap_detail_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_soap_fault_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_soap_fault_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_soap_header_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_soap_header_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	/* WSA */
#ifdef LASSO_WSF_ENABLED
	node = LASSO_NODE(lasso_wsa_attributed_any_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsa_attributed_any_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_wsa_attributed_qname_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsa_attributed_qname_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_wsa_attributed_unsigned_long_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsa_attributed_unsigned_long_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_wsa_attributed_uri_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsa_attributed_uri_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_wsa_endpoint_reference_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsa_endpoint_reference_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_wsa_metadata_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsa_metadata_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_wsa_problem_action_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsa_problem_action_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_wsa_reference_parameters_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsa_reference_parameters_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_wsa_relates_to_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsa_relates_to_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	/* WSSE */
	node = LASSO_NODE(lasso_wsse_embedded_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsse_embedded_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_wsse_reference_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsse_reference_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_wsse_security_header_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsse_security_header_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_wsse_security_token_reference_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsse_security_token_reference_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_wsse_transformation_parameters_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsse_transformation_parameters_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	node = LASSO_NODE(lasso_wsse_username_token_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsse_username_token_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	/* WSU */
	node = LASSO_NODE(lasso_wsu_timestamp_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_wsu_timestamp_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
	/* test serialization / deserialization of KeyInfoConfirmationDataType */
	node = LASSO_NODE(lasso_saml2_key_info_confirmation_data_type_new());
	node_dump = lasso_node_dump(node);
	fail_unless((node2 = lasso_node_new_from_dump(node_dump)) != NULL, "restoring dump failed after lasso_saml2_key_info_confirmation_data_type_new");
	lasso_release_string(node_dump);
	lasso_release_gobject(node2);
	lasso_release_gobject(node);
#endif
	/* test deserialization of saml2:EncryptedAssertion" */
	const char *encrypted_element_xml[] = {
	"<EncryptedAssertion xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:xmlenc=\"http://www.w3.org/2001/04/xmlenc#\">\n\
		<xmlenc:EncryptedData/>\
		<xmlenc:EncryptedKey/>\
	</EncryptedAssertion>",
	"<EncryptedID xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:xmlenc=\"http://www.w3.org/2001/04/xmlenc#\">\n\
		<xmlenc:EncryptedData/>\
		<xmlenc:EncryptedKey/>\
	</EncryptedID>",
	"<EncryptedAttribute xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:xmlenc=\"http://www.w3.org/2001/04/xmlenc#\">\n\
		<xmlenc:EncryptedData/>\
		<xmlenc:EncryptedKey/>\
	</EncryptedAttribute>",
	"<NewEncryptedID xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:xmlenc=\"http://www.w3.org/2001/04/xmlenc#\">\n\
		<xmlenc:EncryptedData/>\
		<xmlenc:EncryptedKey/>\
	</NewEncryptedID>", NULL };
	const char **iter = encrypted_element_xml;
	while (*iter) {
		xmlDoc *xmldoc;
		LassoNode *node;

		xmldoc = xmlParseDoc (BAD_CAST (*iter));
		fail_unless(xmldoc != NULL, "Failed to parse %s: no xmldoc", *iter);
		fail_unless(xmlDocGetRootElement (xmldoc) != NULL, "Failed to parse %s: no root node element", *iter);
		node = lasso_node_new_from_xmlNode(xmlDocGetRootElement(xmldoc));
		fail_unless (LASSO_IS_SAML2_ENCRYPTED_ELEMENT (node), "Parsing of %s did not return a saml2:EncryptedElement, %s", *iter);
		g_object_unref(node);
		lasso_release_doc(xmldoc);
		++iter;
	}
}
END_TEST

/* test NameIDFormat extraction */
START_TEST(test11_get_default_name_id_format)
{
	LassoProvider *provider;
	char *name_id_format;
	const GList *name_id_formats;

	provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP, TESTSDATADIR "/sp5-saml2/metadata.xml", NULL, NULL);
	fail_unless(provider != NULL, "lasso_provider_new failed on metadata file: %s", TESTSDATADIR "/sp5-saml2/metadata.xml");
	name_id_format = lasso_provider_get_default_name_id_format(provider);
	fail_unless(name_id_format != NULL, "no default name id format found!");
	fail_unless(strcmp(name_id_format, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_EMAIL) == 0, "default name id format is not email, it is: %s", name_id_format);
	lasso_release_string(name_id_format);
	name_id_formats = lasso_provider_get_metadata_list(provider, "NameIDFormat");
	fail_unless(g_list_length((GList*)name_id_formats) == 1, "lasso_provider_get_metadata_list returned more or less than 1 NameIDFormat: %u", g_list_length((GList*)name_id_formats));
	fail_unless(name_id_formats->data != NULL, "first name id format is NULL");
	fail_unless(strcmp((char*)name_id_formats->data, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_EMAIL) == 0, "first name id format is not email, it is %s", (char*)name_id_formats->data);
	/* cleanup */
	lasso_release_gobject(provider);
}
END_TEST
#define SHOW_NAMESPACES 0

#if SHOW_NAMESPACES
static void
print_namespace(const char *prefix, const char *href, G_GNUC_UNUSED gpointer data)
{
	printf("Prefix: %s Href: %s\n", prefix, href);
}
#endif

/* test custom namespace handling */
START_TEST(test12_custom_namespace)
{
#ifdef LASSO_WSF_ENABLED
	LassoNode *node;
	LassoIdWsf2DstRefResultQuery *result_query;
	char *dump;
	node = (LassoNode*)lasso_idwsf2_dstref_result_query_new();
	check_not_null(node);
	lasso_node_add_custom_namespace(node, "example", "http://example.com");
	lasso_node_set_custom_namespace(node, "example2", "http://example.com");
	lasso_register_idwsf2_dst_service("example2", "http://example.com");

	dump = lasso_node_dump(node);
	check_not_null(dump);
#if SHOW_NAMESPACES
	printf("%s\n", dump);
#endif
	result_query = LASSO_IDWSF2_DSTREF_RESULT_QUERY(lasso_node_new_from_dump(dump));
	check_not_null(result_query);
	check_not_null(result_query->namespaces);
	check_str_equals(g_hash_table_lookup(result_query->namespaces, "example"), "http://example.com");
	check_str_equals(g_hash_table_lookup(result_query->namespaces, "example2"), "http://example.com");
	check_str_equals(g_hash_table_lookup(result_query->namespaces, "dst"), LASSO_IDWSF2_DST_HREF);
#if SHOW_NAMESPACES
	g_hash_table_foreach(result_query->namespaces, (GHFunc)print_namespace, NULL);
#endif
	lasso_release_string(dump);
#endif
}
END_TEST

#include <stdio.h>

/* test load federation */
START_TEST(test13_test_lasso_server_load_metadata)
{
	LassoServer *server = NULL;
	GList *loaded_entity_ids = NULL;
	GList blacklisted_1 = { .data = "https://identities.univ-jfc.fr/idp/prod", .next = NULL };

	check_not_null(server = lasso_server_new(
			TESTSDATADIR "/idp5-saml2/metadata.xml",
			TESTSDATADIR "/idp5-saml2/private-key.pem",
			NULL, /* Secret key to unlock private key */
			NULL));
	block_lasso_logs;
	check_good_rc(lasso_server_load_metadata(server, LASSO_PROVIDER_ROLE_IDP,
				TESTSDATADIR "/metadata/renater-metadata.xml",
				TESTSDATADIR "/metadata/metadata-federation-renater.crt",
				&blacklisted_1, &loaded_entity_ids,
				LASSO_SERVER_LOAD_METADATA_FLAG_DEFAULT));
	unblock_lasso_logs;
	check_equals(g_hash_table_size(server->providers), 110);
	check_equals(g_list_length(loaded_entity_ids), 110);

#if 0
	/* UK federation file are too big to distribute (and I don't even known if it's right to do
	 * it, disable this test for now ) */
	check_good_rc(lasso_server_load_metadata(server, LASSO_PROVIDER_ROLE_IDP,
				TESTSDATADIR "/ukfederation-metadata.xml",
				TESTSDATADIR "/ukfederation.pem",
				&blacklisted_1, &loaded_entity_ids,
				LASSO_SERVER_LOAD_METADATA_FLAG_DEFAULT));
	check_equals(g_list_length(loaded_entity_ids), 283);
	check_equals(g_hash_table_size(server->providers), 393);
#endif
	lasso_release_list_of_strings(loaded_entity_ids);

	lasso_release_gobject(server);
}
END_TEST

#include "../lasso/key.h"

/* test load federation */
START_TEST(test14_lasso_key)
{
	LassoKey *key;
	char *buffer;
	gsize length;
	char *base64_encoded;

	check_true(g_file_get_contents(TESTSDATADIR "sp1-la/private-key-raw.pem", &buffer, &length, NULL));
	check_not_null(key = lasso_key_new_for_signature_from_memory(buffer,
				length, NULL, LASSO_SIGNATURE_METHOD_RSA_SHA1,
				NULL));
	lasso_release_gobject(key);
	check_not_null(key = lasso_key_new_for_signature_from_file(TESTSDATADIR
				"sp1-la/private-key-raw.pem", NULL, LASSO_SIGNATURE_METHOD_RSA_SHA1,
				NULL));
	lasso_release_gobject(key);
	base64_encoded = g_base64_encode(BAD_CAST buffer, length);
	check_not_null(key = lasso_key_new_for_signature_from_base64_string(base64_encoded, NULL,
				LASSO_SIGNATURE_METHOD_RSA_SHA1, NULL));
	lasso_release_string(base64_encoded);
	lasso_release_string(buffer);
}
END_TEST

/* test load federation */
START_TEST(test15_ds_key_info)
{
	LassoDsKeyInfo *ds_key_info = lasso_ds_key_info_new();
	LassoDsKeyValue *ds_key_value = lasso_ds_key_value_new();
	LassoDsX509Data *x509_data = lasso_ds_x509_data_new();
	char *dump;
	GList list;
	LassoNode *node;

	lasso_ds_x509_data_set_certificate(x509_data, "coucou");
	lasso_ds_key_value_set_x509_data(ds_key_value, x509_data);
	ds_key_info->KeyValue = g_object_ref(ds_key_value);
	dump = lasso_node_debug((LassoNode*)ds_key_info, 10);
	lasso_release_gobject(ds_key_info);
	lasso_release_gobject(ds_key_value);
	lasso_release_gobject(x509_data);
	ds_key_info = (LassoDsKeyInfo*)lasso_node_new_from_dump(dump);
	lasso_release_string(dump);
	check_not_null(ds_key_info);
	check_true(LASSO_IS_DS_KEY_INFO(ds_key_info));
	check_not_null(ds_key_info->KeyValue);
	check_true(LASSO_IS_DS_KEY_VALUE(ds_key_info->KeyValue));
	x509_data = lasso_ds_key_value_get_x509_data(ds_key_info->KeyValue);
	check_not_null(x509_data);
	check_true(LASSO_IS_DS_X509_DATA(x509_data));
	check_str_equals(lasso_ds_x509_data_get_certificate(x509_data), "coucou");
	/* LassoSaml2SubjectConfirmation */
	LassoSaml2SubjectConfirmation *sc = (LassoSaml2SubjectConfirmation*) \
			lasso_saml2_subject_confirmation_new();
	LassoSaml2KeyInfoConfirmationDataType *kicdt = (LassoSaml2KeyInfoConfirmationDataType*) \
			lasso_saml2_key_info_confirmation_data_type_new();
	lasso_assign_string(sc->Method, LASSO_SAML2_CONFIRMATION_METHOD_HOLDER_OF_KEY);
	lasso_assign_new_gobject(sc->SubjectConfirmationData, &kicdt->parent);
	list = (GList){ .data = ds_key_info, .next = NULL, .prev = NULL };
	lasso_saml2_key_info_confirmation_data_type_set_key_info(kicdt, &list);
	dump = lasso_node_debug((LassoNode*)sc, 10);
	lasso_release_gobject(sc);
	lasso_release_gobject(ds_key_info);
	node = lasso_node_new_from_dump(dump);
	lasso_release_string(dump);
	dump = lasso_node_debug(node, 10);
	lasso_release_string(dump);
}
END_TEST

Suite*
basic_suite()
{
	Suite *s = suite_create("Basic");
	TCase *tc_server_load_dump_empty_string = tcase_create("Create server from empty string");
	TCase *tc_server_load_dump_random_string = tcase_create("Create server from random string");
	TCase *tc_server_load_dump_random_xml = tcase_create("Create server from random XML");
	TCase *tc_identity_load_dump_null = tcase_create("Create identity from NULL");
	TCase *tc_identity_load_dump_empty = tcase_create("Create identity from empty string");
	TCase *tc_registry_direct_mapping = tcase_create("Test QName registry with direct mapping");
	TCase *tc_registry_functional_mapping = tcase_create("Test QName registry with functional mapping");
	TCase *tc_registry_new_from_xmlNode = tcase_create("Test parsing a node that has a mapping to Lasso Object in the registry");
	TCase *tc_response_new_from_xmlNode = tcase_create("Test parsing a message from Ping Federate");
	TCase *tc_custom_namespace = tcase_create("Test custom namespace handling");
	TCase *tc_load_metadata = tcase_create("Test loading a federation metadata file");
	TCase *tc_key = tcase_create("Test loading and manipulating LassoKey objects");
	TCase *tc_key_info = tcase_create("Test creating and dumping ds:KeyInfo nodes");

	suite_add_tcase(s, tc_server_load_dump_empty_string);
	suite_add_tcase(s, tc_server_load_dump_random_string);
	suite_add_tcase(s, tc_server_load_dump_random_xml);
	suite_add_tcase(s, tc_identity_load_dump_null);
	suite_add_tcase(s, tc_identity_load_dump_empty);
	suite_add_tcase(s, tc_registry_direct_mapping);
	suite_add_tcase(s, tc_registry_functional_mapping);
	suite_add_tcase(s, tc_registry_new_from_xmlNode);
	suite_add_tcase(s, tc_response_new_from_xmlNode);
	suite_add_tcase(s, tc_custom_namespace);
	suite_add_tcase(s, tc_load_metadata);
	suite_add_tcase(s, tc_key);
	suite_add_tcase(s, tc_key_info);

	tcase_add_test(tc_server_load_dump_empty_string, test01_server_load_dump_empty_string);
	tcase_add_test(tc_server_load_dump_random_string, test02_server_load_dump_random_string);
	tcase_add_test(tc_server_load_dump_random_xml, test03_server_load_dump_random_xml);
	tcase_add_test(tc_identity_load_dump_null, test04_identity_load_dump_null);
	tcase_add_test(tc_identity_load_dump_empty, test05_identity_load_dump_empty);
	tcase_add_test(tc_registry_direct_mapping, test06_registry_direct_mapping);
	tcase_add_test(tc_registry_functional_mapping, test07_registry_functional_mapping);
	tcase_add_test(tc_registry_new_from_xmlNode, test08_test_new_from_xmlNode);
	tcase_add_test(tc_response_new_from_xmlNode, test09_test_deserialization);
	tcase_add_test(tc_response_new_from_xmlNode, test10_test_alldumps);
	tcase_add_test(tc_response_new_from_xmlNode, test11_get_default_name_id_format);
	tcase_add_test(tc_custom_namespace, test12_custom_namespace);
	tcase_add_test(tc_load_metadata, test13_test_lasso_server_load_metadata);
	tcase_add_test(tc_key, test14_lasso_key);
	tcase_add_test(tc_key_info, test15_ds_key_info);
	tcase_set_timeout(tc_load_metadata, 10);
	return s;
}

