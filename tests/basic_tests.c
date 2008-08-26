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

#include <lasso/lasso.h>
#include <lasso/xml/strings.h>


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
	serverContext = lasso_server_new_from_dump("foo");
	fail_unless(serverContext == NULL,
			"serverContext was created from a fake dump");
}
END_TEST

START_TEST(test03_server_load_dump_random_xml)
{
	LassoServer *serverContext;
	serverContext = lasso_server_new_from_dump("<?xml version=\"1.0\"?><foo/>");
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

#include <lasso/registry.h>

START_TEST(test06_registry_direct_mapping)
{
	const char *name;
	gint r;

	r = lasso_registry_default_add_direct_mapping(LASSO_LIB_HREF,
				"test", LASSO_LASSO_HREF,
				"LassoTestClass");
	fail_unless(r == 0, "lasso_registry_default_add_direct_mapping should return 0 for new mappings");
	name = lasso_registry_default_get_mapping(LASSO_LIB_HREF, "test", LASSO_LASSO_HREF);
	fail_unless(name != NULL, "lasso_registry_default_get_mapping should return the recent mapping");
	fail_unless(strcmp(name, "LassoTestClass") == 0, "lasso_registry_default_get_mapping should return LassoTestClass");
}
END_TEST

const char *trad(const char *from_namespace, const char *from_name, const char* to_namespace)
{
	if (strcmp(from_namespace, LASSO_LIB_HREF) == 0 &&
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

	r = lasso_registry_default_add_functional_mapping(LASSO_LIB_HREF, LASSO_LASSO_HREF, trad);
	fail_unless(r == 0, "lasso_registry_default_add_functional mapping should return 0 for new mapping");
	name = lasso_registry_default_get_mapping(LASSO_LIB_HREF, "Assertion", LASSO_LASSO_HREF);
	fail_unless(name != NULL, "lasso_registry_default_get_mapping should return the recent mapping");
	fail_unless(strcmp(name, "LassoAssertion") == 0, "lasso_registry_default_get_mapping should return LassoAssertion");
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
	suite_add_tcase(s, tc_server_load_dump_empty_string);
	suite_add_tcase(s, tc_server_load_dump_random_string);
	suite_add_tcase(s, tc_server_load_dump_random_xml);
	suite_add_tcase(s, tc_identity_load_dump_null);
	suite_add_tcase(s, tc_identity_load_dump_empty);
	suite_add_tcase(s, tc_registry_direct_mapping);
	suite_add_tcase(s, tc_registry_functional_mapping);
	tcase_add_test(tc_server_load_dump_empty_string, test01_server_load_dump_empty_string);
	tcase_add_test(tc_server_load_dump_random_string, test02_server_load_dump_random_string);
	tcase_add_test(tc_server_load_dump_random_xml, test03_server_load_dump_random_xml);
	tcase_add_test(tc_identity_load_dump_null, test04_identity_load_dump_null);
	tcase_add_test(tc_identity_load_dump_empty, test05_identity_load_dump_empty);
	tcase_add_test(tc_registry_direct_mapping, test06_registry_direct_mapping);
	tcase_add_test(tc_registry_functional_mapping, test07_registry_functional_mapping);
	return s;
}

